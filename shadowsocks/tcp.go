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
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"time"

	"github.com/Jigsaw-Code/outline-ss-server/metrics"
	onet "github.com/Jigsaw-Code/outline-ss-server/net"

	"github.com/shadowsocks/go-shadowsocks2/socks"
)

func remoteIP(conn net.Conn) net.IP {
	addr := conn.RemoteAddr()
	if addr == nil {
		return nil
	}
	if tcpaddr, ok := addr.(*net.TCPAddr); ok {
		return tcpaddr.IP
	}
	ipstr, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err == nil {
		return net.ParseIP(ipstr)
	}
	return nil
}

func (s *tcpService) findAccessKey(clientConn onet.DuplexConn) (string, onet.DuplexConn, error) {
	// All supported ciphers must use a 32-byte salt.
	salt := [32]byte{}
	// The ciphertext consists of a 2-byte chunk length and a 16-byte AEAD tag.
	cipherText := [2 + 16]byte{}
	// Constant of zeroes to use as the start chunk count. This must be as big as the max NonceSize() across all ciphers.
	zeroCountBuf := [12]byte{} // MaxCountSize
	// To hold the decrypted chunk length.
	chunkLenBuf := [2]byte{}

	clientIP := remoteIP(clientConn)
	if _, err := io.ReadFull(clientConn, salt[:]); err != nil {
		logger.Debugf("TCP: Failed to read salt: %v", err)
		return "", clientConn, err
	}
	if _, err := io.ReadFull(clientConn, cipherText[:]); err != nil {
		logger.Debugf("TCP: Failed to read ciphertext: %v", err)
		return "", clientConn, err
	}

	// Try each cipher until we find one that authenticates successfully. This assumes that all ciphers are AEAD.
	// We snapshot the list because it may be modified while we use it.
	// TODO: Ban and log client IPs with too many failures too quick to protect against DoS.
	for ci, entry := range (*s.ciphers).SafeSnapshotForClientIP(clientIP) {
		id, cipher := entry.Value.(*CipherEntry).ID, entry.Value.(*CipherEntry).Cipher
		if cipher.SaltSize() != 32 {
			logger.Errorf("TCP %v: Salt size must be 32, not %d", id, cipher.SaltSize())
			continue
		}
		aead, err := cipher.Decrypter(salt[:])
		if err != nil {
			logger.Errorf("TCP %v: Decrypter initialization failed: %v", id, err)
			continue
		}
		_, err = aead.Open(chunkLenBuf[:0], zeroCountBuf[:aead.NonceSize()], cipherText[:], nil)
		if err != nil {
			logger.Debugf("TCP %v: Failed to decrypt length: %v", id, err)
			continue
		}
		logger.Debugf("TCP %v: Found cipher at index %d", id, ci)

		if !s.ivCache.Add(salt[:]) {
			logger.Warningf("TCP %v: Replay detected", id)
			return "", clientConn, errors.New("TCP: Replay detected")
		}

		// Move the active cipher to the front, so that the search is quicker next time.
		(*s.ciphers).SafeMarkUsedByClientIP(entry, clientIP)
		src := io.MultiReader(bytes.NewReader(salt[:]), bytes.NewReader(cipherText[:]), clientConn)
		ssr := NewShadowsocksReader(src, cipher)
		ssw := NewShadowsocksWriter(clientConn, cipher)
		return id, onet.WrapConn(clientConn, ssr, ssw).(onet.DuplexConn), nil
	}
	return "", clientConn, fmt.Errorf("Could not find valid TCP cipher")
}

type tcpService struct {
	listener    *net.TCPListener
	ciphers     *CipherList
	m           metrics.ShadowsocksMetrics
	isRunning   bool
	readTimeout time.Duration
	ivCache     IVCache
}

// Prevent replays of this many of the most recent handshakes.
const replayHistory = 10_000

// NewTCPService creates a TCPService
func NewTCPService(listener *net.TCPListener, ciphers *CipherList, m metrics.ShadowsocksMetrics, timeout time.Duration) TCPService {
	return &tcpService{
		listener:    listener,
		ciphers:     ciphers,
		m:           m,
		readTimeout: timeout,
		ivCache:     NewIVCache(replayHistory),
	}
}

// TCPService is a Shadowsocks TCP service that can be started and stopped.
type TCPService interface {
	Start()
	Stop() error
}

// proxyConnection will route the clientConn according to the address read from the connection.
func proxyConnection(clientConn onet.DuplexConn, proxyMetrics *metrics.ProxyMetrics) *onet.ConnectionError {
	tgtAddr, err := socks.ReadAddr(clientConn)
	if err != nil {
		return onet.NewConnectionError("ERR_READ_ADDRESS", "Failed to get target address", err)
	}
	tgtTCPAddr, err := net.ResolveTCPAddr("tcp", tgtAddr.String())
	if err != nil {
		return onet.NewConnectionError("ERR_RESOLVE_ADDRESS", fmt.Sprintf("Failed to resolve target address %v", tgtAddr.String()), err)
	}
	if !tgtTCPAddr.IP.IsGlobalUnicast() {
		return onet.NewConnectionError("ERR_ADDRESS_INVALID", fmt.Sprintf("Target address is not global unicast: %v", tgtAddr.String()), err)
	}
	if onet.IsPrivateAddress(tgtTCPAddr.IP) {
		return onet.NewConnectionError("ERR_ADDRESS_PRIVATE", fmt.Sprintf("Target address is a private address: %v", tgtAddr.String()), nil)
	}

	tgtTCPConn, err := net.DialTCP("tcp", nil, tgtTCPAddr)
	if err != nil {
		return onet.NewConnectionError("ERR_CONNECT", "Failed to connect to target", err)
	}
	defer tgtTCPConn.Close()
	tgtTCPConn.SetKeepAlive(true)
	tgtConn := metrics.MeasureConn(tgtTCPConn, &proxyMetrics.ProxyTarget, &proxyMetrics.TargetProxy)

	logger.Debugf("proxy %s <-> %s", clientConn.RemoteAddr().String(), tgtConn.RemoteAddr().String())
	_, _, err = onet.Relay(clientConn, tgtConn)
	if err != nil {
		return onet.NewConnectionError("ERR_RELAY", "Failed to relay traffic", err)
	}
	return nil
}

func (s *tcpService) Start() {
	s.isRunning = true
	for s.isRunning {
		var clientConn onet.DuplexConn
		clientConn, err := s.listener.AcceptTCP()
		if err != nil {
			if !s.isRunning {
				return
			}
			logger.Errorf("Failed to accept: %v", err)
		}

		go func() (connError *onet.ConnectionError) {
			clientLocation, err := s.m.GetLocation(clientConn.RemoteAddr())
			if err != nil {
				logger.Warningf("Failed location lookup: %v", err)
			}
			logger.Debugf("Got location \"%v\" for IP %v", clientLocation, clientConn.RemoteAddr().String())
			s.m.AddOpenTCPConnection(clientLocation)
			defer func() {
				if r := recover(); r != nil {
					logger.Errorf("Panic in TCP handler: %v", r)
				}
			}()
			connStart := time.Now()
			clientConn.(*net.TCPConn).SetKeepAlive(true)
			// Set a deadline for connection authentication
			clientConn.SetReadDeadline(connStart.Add(s.readTimeout))
			keyID := ""
			var proxyMetrics metrics.ProxyMetrics
			var timeToCipher time.Duration
			clientConn = metrics.MeasureConn(clientConn, &proxyMetrics.ProxyClient, &proxyMetrics.ClientProxy)
			defer func() {
				connDuration := time.Now().Sub(connStart)
				clientConn.Close()
				status := "OK"
				if connError != nil {
					logger.Debugf("TCP Error: %v: %v", connError.Message, connError.Cause)
					status = connError.Status
				}
				logger.Debugf("Done with status %v, duration %v", status, connDuration)
				s.m.AddClosedTCPConnection(clientLocation, keyID, status, proxyMetrics, timeToCipher, connDuration)
			}()

			findStartTime := time.Now()
			keyID, clientConn, err := s.findAccessKey(clientConn)
			timeToCipher = time.Now().Sub(findStartTime)

			if err != nil {
				// Keep the connection open until we hit the authentication deadline to protect against probing attacks
				logger.Debugf("Failed to find a valid cipher after reading %v bytes: %v", proxyMetrics.ClientProxy, err)
				_, drainErr := io.Copy(ioutil.Discard, clientConn) // drain socket
				drainResult := drainErrToString(drainErr)
				port := s.listener.Addr().(*net.TCPAddr).Port
				logger.Debugf("Drain error: %v, drain result: %v", drainErr, drainResult)
				s.m.AddTCPProbe(clientLocation, drainResult, port, proxyMetrics)
				return onet.NewConnectionError("ERR_CIPHER", "Failed to find a valid cipher", err)
			}

			// Clear the authentication deadline
			clientConn.SetReadDeadline(time.Time{})
			return proxyConnection(clientConn, &proxyMetrics)
		}()
	}
}

func drainErrToString(drainErr error) string {
	netErr, ok := drainErr.(net.Error)
	switch {
	case drainErr == nil:
		return "eof"
	case ok && netErr.Timeout():
		return "timeout"
	default:
		return "other"
	}
}

func (s *tcpService) Stop() error {
	s.isRunning = false
	return s.listener.Close()
}
