package service

import (
	"crypto/cipher"
	"net"
	"sync"
	"time"

	onet "github.com/Shadowsocks-NET/outline-ss-server/net"
	"github.com/Shadowsocks-NET/outline-ss-server/service/metrics"
	ss "github.com/Shadowsocks-NET/outline-ss-server/shadowsocks"
	wgreplay "golang.zx2c4.com/wireguard/replay"
)

type natconn struct {
	// For legacy Shadowsocks servers, this stores reference to target conn.
	// For Shadowsocks 2022 servers, use the targetConn in session instead.
	targetConn onet.UDPPacketConn

	// Reference to access key's cipher.
	cipher *ss.Cipher

	keyID string

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

	// oobCache stores the interface index and IP where the requests are received from the client.
	// This is used to send UDP packets from the correct interface and IP.
	oobCache []byte

	// The fixed client address where the first packet of the session was received from.
	// Only meaningful for legacy Shadowsocks.
	// For Shadowsocks 2022, use lastSeenAddr in session.
	lastSeenAddr *net.UDPAddr

	// The UDPConn where the last client packet was received from.
	lastSeenConn onet.UDPPacketConn
}

func isDNS(addr *net.UDPAddr) bool {
	return addr.Port == 53
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

func (c *natconn) WriteToUDP(buf []byte, dst *net.UDPAddr) (int, error) {
	c.onWrite(dst)
	return c.targetConn.WriteToUDP(buf, dst)
}

func (c *natconn) ReadFromUDP(buf []byte) (int, *net.UDPAddr, error) {
	n, addr, err := c.targetConn.ReadFromUDP(buf)
	if err == nil {
		c.onRead(addr)
	}
	return n, addr, err
}

func (c *natconn) SetReadDeadline(t time.Time) error {
	return c.targetConn.SetReadDeadline(t)
}

func (c *natconn) LocalAddr() net.Addr {
	return c.targetConn.LocalAddr()
}

func (c *natconn) Close() error {
	return c.targetConn.Close()
}

// copy from target to client until read timeout
func (c *natconn) timedCopy(ses *session, sm metrics.ShadowsocksMetrics) {
	// pkt is used for in-place encryption of downstream UDP packets, with the layout
	// [padding?][salt][address][body][tag][extra]
	// Padding is only used if the address is IPv4.
	pkt := make([]byte, UDPPacketBufferSize)
	saltSize := c.cipher.SaltSize()
	cipherConfig := c.cipher.Config()
	lastSeenAddr := c.lastSeenAddr

	// Leave enough room at the beginning of the packet for a max-length header (i.e. IPv6).
	var bodyStart int

	switch {
	case cipherConfig.UDPHasSeparateHeader:
		bodyStart = 16 + 1 + 8 + ss.SocksAddressIPv6Length + 2 + ss.MaxPaddingLength
	case cipherConfig.IsSpec2022:
		bodyStart = 24 + 8 + 8 + 1 + 8 + ss.SocksAddressIPv6Length + 2 + ss.MaxPaddingLength
	default:
		bodyStart = saltSize + ss.SocksAddressIPv6Length
	}

	expired := false

	for {
		var bodyLen, proxyClientBytes int
		connError := func() (connError *onet.ConnectionError) {
			var (
				raddr       *net.UDPAddr
				err         error
				headerStart int
				pktStart    int
				buf         []byte
			)

			// `readBuf` receives the plaintext body in `pkt`:
			// [padding?][salt][address][body][tag][unused]
			// |--     bodyStart     --|[      readBuf    ]
			readBuf := pkt[bodyStart:]
			switch {
			case cipherConfig.IsSpec2022:
				bodyLen, raddr, err = ses.targetConn.ReadFromUDP(readBuf)
				if err == nil {
					c.onRead(raddr)
				}
			default:
				bodyLen, raddr, err = c.ReadFromUDP(readBuf)
			}
			if err != nil {
				if netErr, ok := err.(net.Error); ok {
					if netErr.Timeout() {
						expired = true
						return nil
					}
				}
				return onet.NewConnectionError("ERR_READ", "Failed to read from target", err)
			}

			// Refresh lastSeenAddr from session.
			if cipherConfig.IsSpec2022 {
				lastSeenAddr = ses.lastSeenAddr
			}

			debugUDPAddr(lastSeenAddr, "Got response from %v", raddr)

			socksAddrLen := ss.SocksAddressIPv6Length
			if raddr.IP.To4() != nil {
				socksAddrLen = ss.SocksAddressIPv4Length
			}

			// For now, let's not think about padding.
			switch {
			case cipherConfig.UDPHasSeparateHeader:
				headerStart = bodyStart - 8 - 8 - 1 - 8 - socksAddrLen - 2
				pktStart = headerStart
				ss.WriteUDPHeaderSeparated(pkt[pktStart:], ss.HeaderTypeServerPacket, ses.sid, ses.pid, raddr, 0)
				ses.pid++
			case cipherConfig.IsSpec2022:
				headerStart = bodyStart - 8 - 8 - 1 - 8 - socksAddrLen - 2
				pktStart = headerStart - 24
				ss.WriteUDPHeader(pkt[pktStart:], ss.HeaderTypeServerPacket, ses.sid, ses.pid, raddr, 0)
				ses.pid++
			default:
				headerStart = bodyStart - socksAddrLen
				pktStart = headerStart - saltSize
				ss.WriteUDPAddrToSocksAddr(pkt[headerStart:], raddr)
			}

			// `plainTextBuf` concatenates the SOCKS address and body:
			// [padding?][salt][address][body][tag][unused]
			// |-- addrStart -|[plaintextBuf ]
			plaintextBuf := pkt[headerStart : bodyStart+bodyLen]
			// pktStart is 0 if raddr is IPv6.

			// `packBuf` adds space for the salt and tag.
			// `buf` shows the space that was used.
			// [padding?][salt][address][body][tag][unused]
			//           [            packBuf             ]
			//           [          buf           ]
			packBuf := pkt[pktStart:]

			switch {
			case cipherConfig.UDPHasSeparateHeader:
				buf, err = ss.PackAesWithSeparateHeader(packBuf, plaintextBuf, c.cipher, ses.aead)
			default:
				buf, err = ss.Pack(packBuf, plaintextBuf, c.cipher)
			}

			if err != nil {
				return onet.NewConnectionError("ERR_PACK", "Failed to pack data to client", err)
			}

			proxyClientBytes, _, err = c.lastSeenConn.WriteMsgUDP(buf, c.oobCache, lastSeenAddr)
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
		sm.AddUDPPacketFromTarget(c.clientLocation, c.keyID, status, bodyLen, proxyClientBytes)
	}
}

// Packet NAT table
type natmap struct {
	sync.RWMutex
	keyConn map[string]*natconn
	sidConn map[uint64]*session
	timeout time.Duration
	metrics metrics.ShadowsocksMetrics
	running *sync.WaitGroup
}

func newNATmap(timeout time.Duration, sm metrics.ShadowsocksMetrics, running *sync.WaitGroup) *natmap {
	return &natmap{
		keyConn: make(map[string]*natconn),
		sidConn: make(map[uint64]*session),
		timeout: timeout,
		metrics: sm,
		running: running,
	}
}

func (m *natmap) GetByClientAddress(key string) *natconn {
	m.RLock()
	defer m.RUnlock()
	return m.keyConn[key]
}

func (m *natmap) GetBySessionID(sid uint64) *session {
	m.RLock()
	defer m.RUnlock()
	return m.sidConn[sid]
}

func (m *natmap) set(clientAddr *net.UDPAddr, clientConn onet.UDPPacketConn, targetConn onet.UDPPacketConn, cipher *ss.Cipher, keyID, clientLocation string, oobCache []byte) *natconn {
	entry := &natconn{
		targetConn:     targetConn,
		cipher:         cipher,
		keyID:          keyID,
		clientLocation: clientLocation,
		defaultTimeout: m.timeout,
		oobCache:       oobCache,
		lastSeenAddr:   clientAddr,
		lastSeenConn:   clientConn,
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

func (m *natmap) Add(clientAddr *net.UDPAddr, clientConn onet.UDPPacketConn, oobCache []byte, cipher *ss.Cipher, targetConn onet.UDPPacketConn, clientLocation, keyID string, ses *session) *natconn {
	entry := m.set(clientAddr, clientConn, targetConn, cipher, keyID, clientLocation, oobCache)

	m.metrics.AddUDPNatEntry()
	m.running.Add(1)
	go func() {
		entry.timedCopy(ses, m.metrics)
		m.metrics.RemoveUDPNatEntry()
		if pc := m.del(clientAddr.String()); pc != nil {
			pc.Close()
		}
		m.running.Done()
	}()
	return entry
}

func (m *natmap) AddSession(sid uint64, ses *session) {
	m.Lock()
	defer m.Unlock()

	m.sidConn[sid] = ses

	m.cleanUpSessions()
}

// cleanUpSessions enumerates through the session table
// and removes sessions that satisfy these conditions:
// - last seen over 30 seconds ago.
// - have no corresponding NAT entry.
func (m *natmap) cleanUpSessions() {
	nowEpoch := time.Now().Unix()
	for sid, ses := range m.sidConn {
		if nowEpoch-ses.lastSeenTime > 30 && m.keyConn[ses.lastSeenAddr.String()] == nil {
			delete(m.sidConn, sid)
		}
	}
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

type session struct {
	// sid stores session ID for Shadowsocks 2022 Edition methods.
	sid []byte

	// pid stores packet ID for Shadowsocks 2022 Edition methods.
	pid uint64

	// Stores reference to target conn.
	targetConn onet.UDPPacketConn

	// The UDPAddr where the last client packet was received from.
	// Use this.String() as key to look up the NAT table.
	lastSeenAddr *net.UDPAddr

	// Unix epoch timestamp when the last client packet was received.
	lastSeenTime int64

	// Provides sliding window replay protection.
	filter *wgreplay.Filter

	// Only used by 2022-blake3-aes-256-gcm.
	// Initialized with session subkey.
	aead cipher.AEAD
}

func newSession(sid []byte, lastSeenAddr *net.UDPAddr, aead cipher.AEAD) *session {
	return &session{
		sid:          sid,
		pid:          ss.SeparateHeaderMinServerPacketID, // Server packet ID starts from 2^63.
		lastSeenAddr: lastSeenAddr,
		lastSeenTime: time.Now().Unix(),
		filter:       &wgreplay.Filter{},
		aead:         aead,
	}
}
