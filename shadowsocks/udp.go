// Copyright 2018 Jigsaw Operations LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package shadowsocks

import (
	"errors"
	"fmt"
	"io"
	"net"
	"runtime/debug"
	"time"

	"github.com/Jigsaw-Code/outline-ss-server/metrics"
	logging "github.com/op/go-logging"

	onet "github.com/Jigsaw-Code/outline-ss-server/net"

	"sync"

	"github.com/shadowsocks/go-shadowsocks2/shadowaead"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

const udpBufSize = 64 * 1024

// Wrapper for logger.Debugf during UDP proxying.
func debugUDP(tag string, template string, val interface{}) {
	// This is an optimization to reduce unnecessary allocations due to an interaction
	// between Go's inlining/escape analysis and varargs functions like logger.Debugf.
	if logger.IsEnabledFor(logging.DEBUG) {
		logger.Debugf("UDP(%s): "+template, tag, val)
	}
}

func debugUDPAddr(addr net.Addr, template string, val interface{}) {
	if logger.IsEnabledFor(logging.DEBUG) {
		// Avoid calling addr.String() unless debugging is enabled.
		debugUDP(addr.String(), template, val)
	}
}

// upack decrypts src into dst. It tries each cipher until it finds one that authenticates
// correctly. dst and src must not overlap.
func unpack(clientIP net.IP, dst, src []byte, cipherList CipherList) ([]byte, string, shadowaead.Cipher, error) {
	// Try each cipher until we find one that authenticates successfully. This assumes that all ciphers are AEAD.
	// We snapshot the list because it may be modified while we use it.
	_, snapshot := cipherList.SnapshotForClientIP(clientIP)
	for ci, entry := range snapshot {
		id, cipher := entry.Value.(*CipherEntry).ID, entry.Value.(*CipherEntry).Cipher
		buf, err := shadowaead.Unpack(dst, src, cipher)
		if err != nil {
			debugUDP(id, "Failed to unpack: %v", err)
			continue
		}
		debugUDP(id, "Found cipher at index %d", ci)
		// Move the active cipher to the front, so that the search is quicker next time.
		cipherList.MarkUsedByClientIP(entry, clientIP)
		return buf, id, cipher, nil
	}
	return nil, "", nil, errors.New("could not find valid cipher")
}

type udpService struct {
	clientConn net.PacketConn
	running    sync.WaitGroup
}

// NewUDPService creates a UDPService
func NewUDPService(clientConn net.PacketConn, natTimeout time.Duration, cipherList CipherList, m metrics.ShadowsocksMetrics, ipPolicy onet.IPPolicy) UDPService {
	if ipPolicy == nil {
		ipPolicy = onet.RequirePublicIP
	}
	s := &udpService{
		clientConn: clientConn,
	}
	nm := newNATmap(natTimeout, m, &s.running)
	s.running.Add(1)
	go s.start(cipherList, m, nm, ipPolicy)
	return s
}

// UDPService is a running UDP shadowsocks proxy that can be stopped.
type UDPService interface {
	io.Closer
	// Wait blocks until Close has been called and all resources have been cleaned up.
	Wait()
}

// Listen on addr for encrypted packets and basically do UDP NAT.
// We take the ciphers as a pointer because it gets replaced on config updates.
func (s *udpService) start(ciphers CipherList, m metrics.ShadowsocksMetrics, nm *natmap, checkAllowedIP onet.IPPolicy) {
	defer s.running.Done()
	defer s.clientConn.Close()
	defer nm.Close()

	cipherBuf := make([]byte, udpBufSize)
	textBuf := make([]byte, udpBufSize)

	closeRequested := false
	for !closeRequested {
		func() (connError *onet.ConnectionError) {
			defer func() {
				if r := recover(); r != nil {
					logger.Errorf("Panic in UDP loop: %v", r)
					debug.PrintStack()
				}
			}()

			// Attempt to read an upstream packet.
			clientProxyBytes, clientAddr, err := s.clientConn.ReadFrom(cipherBuf)
			neterr, ok := err.(net.Error)
			if ok && neterr.Timeout() {
				closeRequested = true
				return nil // Clean shutdown, ignore the packet or error.
			}

			// An upstream packet should have been read.  Set up the metrics reporting
			// for this forwarding event.
			clientLocation := ""
			keyID := ""
			var proxyTargetBytes int
			var timeToCipher time.Duration
			defer func() {
				status := "OK"
				if connError != nil {
					logger.Debugf("UDP Error: %v: %v", connError.Message, connError.Cause)
					status = connError.Status
				}
				m.AddUDPPacketFromClient(clientLocation, keyID, status, clientProxyBytes, proxyTargetBytes, timeToCipher)
			}()

			if err != nil {
				return onet.NewConnectionError("ERR_READ", "Failed to read from client", err)
			}
			if logger.IsEnabledFor(logging.DEBUG) {
				defer logger.Debugf("UDP(%v): done", clientAddr)
				logger.Debugf("UDP(%v): Outbound packet has %d bytes", clientAddr, clientProxyBytes)
			}
			unpackStart := time.Now()
			ip := clientAddr.(*net.UDPAddr).IP
			buf, keyID, cipher, err := unpack(ip, textBuf, cipherBuf[:clientProxyBytes], ciphers)
			timeToCipher = time.Now().Sub(unpackStart)

			if err != nil {
				return onet.NewConnectionError("ERR_CIPHER", "Failed to upack data from client", err)
			}

			tgtAddr := socks.SplitAddr(buf)
			if tgtAddr == nil {
				return onet.NewConnectionError("ERR_READ_ADDRESS", "Failed to get target address", nil)
			}

			tgtUDPAddr, err := net.ResolveUDPAddr("udp", tgtAddr.String())
			if err != nil {
				return onet.NewConnectionError("ERR_RESOLVE_ADDRESS", fmt.Sprintf("Failed to resolve target address %v", tgtAddr), err)
			}
			if err := checkAllowedIP(tgtUDPAddr.IP); err != nil {
				return err
			}

			payload := buf[len(tgtAddr):]

			targetConn := nm.Get(clientAddr.String())
			if targetConn == nil {
				clientLocation, locErr := m.GetLocation(clientAddr)
				if locErr != nil {
					logger.Warningf("Failed location lookup: %v", locErr)
				}
				debugUDPAddr(clientAddr, "Got location \"%s\"", clientLocation)

				udpConn, err := net.ListenPacket("udp", "")
				if err != nil {
					return onet.NewConnectionError("ERR_CREATE_SOCKET", "Failed to create UDP socket", err)
				}
				targetConn = nm.Add(clientAddr, s.clientConn, cipher, udpConn, clientLocation, keyID)
			}
			clientLocation = targetConn.clientLocation

			debugUDPAddr(clientAddr, "Proxy exit %v", targetConn.LocalAddr())
			proxyTargetBytes, err = targetConn.WriteTo(payload, tgtUDPAddr) // accept only UDPAddr despite the signature
			if err != nil {
				return onet.NewConnectionError("ERR_WRITE", "Failed to write to target", err)
			}
			return nil
		}()
	}
}

func (s *udpService) Close() error {
	return s.clientConn.SetReadDeadline(time.Now())
}

func (s *udpService) Wait() {
	s.running.Wait()
}

func isDNS(addr net.Addr) bool {
	_, port, _ := net.SplitHostPort(addr.String())
	return port == "53"
}

type natconn struct {
	net.PacketConn
	// We store the client location in the NAT map to avoid recomputing it
	// for every downstream packet in a UDP-based connection.
	clientLocation string
	// NAT timeout to apply for non-DNS packets.
	defaultTimeout time.Duration
	// Current read deadline of PacketConn.  Used to avoid decreasing the
	// deadline.  Initially zero.
	readDeadline time.Time
	// If the connection has only sent one DNS query, it will close
	// if it receives a DNS response.
	fastClose sync.Once
}

func (c *natconn) onWrite(addr net.Addr) {
	// Fast close is only allowed if there has been exactly one write,
	// and it was a DNS query.
	isDNS := isDNS(addr)
	isFirstWrite := c.readDeadline.IsZero()
	if !isDNS || !isFirstWrite {
		// Disable fast close.  (Idempotent.)
		c.fastClose.Do(func() {})
	}

	timeout := c.defaultTimeout
	if isDNS {
		// Shorten timeout as required by RFC 5452 Section 10.
		timeout = 17 * time.Second
	}

	newDeadline := time.Now().Add(timeout)
	if newDeadline.After(c.readDeadline) {
		c.readDeadline = newDeadline
		c.SetReadDeadline(newDeadline)
	}
}

func (c *natconn) onRead(addr net.Addr) {
	c.fastClose.Do(func() {
		if isDNS(addr) {
			// The next ReadFrom() should time out immediately.
			c.SetReadDeadline(time.Now())
		}
	})
}

func (c *natconn) WriteTo(buf []byte, dst net.Addr) (int, error) {
	c.onWrite(dst)
	return c.PacketConn.WriteTo(buf, dst)
}

func (c *natconn) ReadFrom(buf []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(buf)
	if err == nil {
		c.onRead(addr)
	}
	return n, addr, err
}

// Packet NAT table
type natmap struct {
	sync.RWMutex
	keyConn map[string]*natconn
	timeout time.Duration
	metrics metrics.ShadowsocksMetrics
	running *sync.WaitGroup
}

func newNATmap(timeout time.Duration, sm metrics.ShadowsocksMetrics, running *sync.WaitGroup) *natmap {
	m := &natmap{metrics: sm, running: running}
	m.keyConn = make(map[string]*natconn)
	m.timeout = timeout
	return m
}

func (m *natmap) Get(key string) *natconn {
	m.RLock()
	defer m.RUnlock()
	return m.keyConn[key]
}

func (m *natmap) set(key string, pc net.PacketConn, clientLocation string) *natconn {
	entry := &natconn{
		PacketConn:     pc,
		clientLocation: clientLocation,
		defaultTimeout: m.timeout,
	}

	m.Lock()
	defer m.Unlock()

	m.keyConn[key] = entry
	return entry
}

func (m *natmap) del(key string) net.PacketConn {
	m.Lock()
	defer m.Unlock()

	entry, ok := m.keyConn[key]
	if ok {
		delete(m.keyConn, key)
		return entry
	}
	return nil
}

func (m *natmap) Add(clientAddr net.Addr, clientConn net.PacketConn, cipher shadowaead.Cipher, targetConn net.PacketConn, clientLocation, keyID string) *natconn {
	entry := m.set(clientAddr.String(), targetConn, clientLocation)

	m.metrics.AddUDPNatEntry()
	m.running.Add(1)
	go func() {
		timedCopy(clientAddr, clientConn, cipher, entry, keyID, m.metrics)
		m.metrics.RemoveUDPNatEntry()
		if pc := m.del(clientAddr.String()); pc != nil {
			pc.Close()
		}
		m.running.Done()
	}()
	return entry
}

func (m *natmap) Close() error {
	m.Lock()
	defer m.Unlock()

	var err error
	now := time.Now()
	for _, pc := range m.keyConn {
		if e := pc.SetReadDeadline(now); e != nil {
			err = e
		}
	}
	return err
}

// Get the maximum length of the shadowsocks address header by parsing
// and serializing an IPv6 address from the example range.
var maxAddrLen int = len(socks.ParseAddr("[2001:db8::1]:12345"))

// copy from target to client until read timeout
func timedCopy(clientAddr net.Addr, clientConn net.PacketConn, cipher shadowaead.Cipher, targetConn *natconn,
	keyID string, sm metrics.ShadowsocksMetrics) {
	// pkt is used for in-place encryption of downstream UDP packets, with the layout
	// [padding?][salt][address][body][tag][extra]
	// Padding is only used if the address is IPv4.
	pkt := make([]byte, udpBufSize)

	saltSize := cipher.SaltSize()
	// Leave enough room at the beginning of the packet for a max-length header (i.e. IPv6).
	bodyStart := saltSize + maxAddrLen

	expired := false
	for {
		var bodyLen, proxyClientBytes int
		connError := func() (connError *onet.ConnectionError) {
			var (
				raddr net.Addr
				err   error
			)
			// `readBuf` receives the plaintext body in `pkt`:
			// [padding?][salt][address][body][tag][unused]
			// |--     bodyStart     --|[      readBuf    ]
			readBuf := pkt[bodyStart:]
			bodyLen, raddr, err = targetConn.ReadFrom(readBuf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok {
					if netErr.Timeout() {
						expired = true
						return nil
					}
				}
				return onet.NewConnectionError("ERR_READ", "Failed to read from target", err)
			}

			debugUDPAddr(clientAddr, "Got response from %v", raddr)
			srcAddr := socks.ParseAddr(raddr.String())
			addrStart := bodyStart - len(srcAddr)
			// `plainTextBuf` concatenates the SOCKS address and body:
			// [padding?][salt][address][body][tag][unused]
			// |-- addrStart -|[plaintextBuf ]
			plaintextBuf := pkt[addrStart : bodyStart+bodyLen]
			copy(plaintextBuf, srcAddr)

			// saltStart is 0 if raddr is IPv6.
			saltStart := addrStart - saltSize
			// `packBuf` adds space for the salt and tag.
			// `buf` shows the space that was used.
			// [padding?][salt][address][body][tag][unused]
			//           [            packBuf             ]
			//           [          buf           ]
			packBuf := pkt[saltStart:]
			buf, err := shadowaead.Pack(packBuf, plaintextBuf, cipher) // Encrypt in-place
			if err != nil {
				return onet.NewConnectionError("ERR_PACK", "Failed to pack data to client", err)
			}
			proxyClientBytes, err = clientConn.WriteTo(buf, clientAddr)
			if err != nil {
				return onet.NewConnectionError("ERR_WRITE", "Failed to write to client", err)
			}
			return nil
		}()
		status := "OK"
		if connError != nil {
			logger.Debugf("UDP Error: %v: %v", connError.Message, connError.Cause)
			status = connError.Status
		}
		if expired {
			break
		}
		sm.AddUDPPacketFromTarget(targetConn.clientLocation, keyID, status, bodyLen, proxyClientBytes)
	}
}
