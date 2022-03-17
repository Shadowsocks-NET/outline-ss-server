package client

import (
	"errors"
	"log"
	"net"
	"os"
	"sync"
	"time"

	onet "github.com/Shadowsocks-NET/outline-ss-server/net"
	"github.com/Shadowsocks-NET/outline-ss-server/service"
)

type natconn struct {
	// Stores reference to proxy conn.
	proxyConn ShadowsocksPacketConn

	// NAT timeout to apply for non-DNS packets.
	defaultTimeout time.Duration

	// Current read deadline of PacketConn.  Used to avoid decreasing the
	// deadline.  Initially zero.
	readDeadline time.Time

	// If the connection has only sent one DNS query, it will close
	// if it receives a DNS response.
	fastClose sync.Once

	// oobCache stores the interface index and IP where the requests are received from the client.
	// This is used to send UDP packets from the correct interface and IP.
	oobCache []byte

	// The fixed client address where the first packet of the session was received from.
	clientAddr *net.UDPAddr

	// The UDPConn where the last client packet was received from.
	clientConn onet.UDPPacketConn
}

func isDNS(addr *net.UDPAddr) bool {
	return addr != nil && addr.Port == 53
}

func (c *natconn) onWrite(addr *net.UDPAddr) {
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

func (c *natconn) onRead(addr *net.UDPAddr) {
	c.fastClose.Do(func() {
		if isDNS(addr) {
			// The next ReadFrom() should time out immediately.
			c.SetReadDeadline(time.Now())
		}
	})
}

func (c *natconn) WriteToZeroCopy(b []byte, start, length int, socksAddr []byte) (n int, err error) {
	c.onWrite(nil)
	return c.proxyConn.WriteToZeroCopy(b, start, length, socksAddr)
}

func (c *natconn) ReadFromZeroCopy(b []byte) (payload []byte, address string, err error) {
	payload, address, err = c.proxyConn.ReadFromZeroCopy(b)
	if err == nil {
		c.onRead(nil)
	}
	return
}

func (c *natconn) SetReadDeadline(t time.Time) error {
	return c.proxyConn.SetReadDeadline(t)
}

func (c *natconn) LocalAddr() net.Addr {
	return c.proxyConn.LocalAddr()
}

func (c *natconn) Close() error {
	return c.proxyConn.Close()
}

// timedCopy copies from proxy to client until read timeout.
func (c *natconn) timedCopy() {
	packetBuf := make([]byte, service.UDPPacketBufferSize)

	for {
		payload, _, err := c.ReadFromZeroCopy(packetBuf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return
			}
			log.Print(err)
			continue
		}

		_, _, err = c.clientConn.WriteMsgUDP(payload, c.oobCache, c.clientAddr)
		if err != nil {
			log.Print(err)
		}
	}
}

// Packet NAT table
type natmap struct {
	sync.RWMutex
	keyConn map[string]*natconn
	timeout time.Duration
}

func newNATmap(timeout time.Duration) *natmap {
	return &natmap{
		keyConn: make(map[string]*natconn),
		timeout: timeout,
	}
}

func (m *natmap) GetByClientAddress(key string) *natconn {
	m.RLock()
	defer m.RUnlock()
	return m.keyConn[key]
}

func (m *natmap) set(clientAddr *net.UDPAddr, clientConn onet.UDPPacketConn, proxyConn ShadowsocksPacketConn, oobCache []byte) *natconn {
	entry := &natconn{
		proxyConn:      proxyConn,
		defaultTimeout: m.timeout,
		oobCache:       oobCache,
		clientAddr:     clientAddr,
		clientConn:     clientConn,
	}

	m.Lock()
	defer m.Unlock()

	m.keyConn[clientAddr.String()] = entry
	return entry
}

func (m *natmap) del(key string) *natconn {
	m.Lock()
	defer m.Unlock()

	entry, ok := m.keyConn[key]
	if ok {
		delete(m.keyConn, key)
		return entry
	}
	return nil
}

func (m *natmap) Add(clientAddr *net.UDPAddr, clientConn onet.UDPPacketConn, oobCache []byte, proxyConn ShadowsocksPacketConn) *natconn {
	entry := m.set(clientAddr, clientConn, proxyConn, oobCache)
	go func() {
		entry.timedCopy()
		if pc := m.del(clientAddr.String()); pc != nil {
			pc.Close()
		}
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
