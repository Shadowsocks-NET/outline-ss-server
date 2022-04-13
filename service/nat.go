package service

import (
	"crypto/cipher"
	"math/rand"
	"net"
	"sync"
	"time"

	onet "github.com/Shadowsocks-NET/outline-ss-server/net"
	"github.com/Shadowsocks-NET/outline-ss-server/service/metrics"
	ss "github.com/Shadowsocks-NET/outline-ss-server/shadowsocks"
	"github.com/Shadowsocks-NET/outline-ss-server/socks"
	"go.uber.org/zap"
	wgreplay "golang.zx2c4.com/wireguard/replay"
)

type natconn struct {
	// For legacy Shadowsocks servers, each natconn is mapped to one session,
	// which is referenced here.
	//
	// For Shadowsocks 2022 servers, look up the session table instead.
	session *session

	// swg is session wait group. Wait until no sessions exist on this natconn,
	// then this natconn can be removed.
	swg sync.WaitGroup

	// Reference to access key's cipher.
	cipher *ss.Cipher

	keyID string

	// We store the client location in the NAT map to avoid recomputing it
	// for every downstream packet in a UDP-based connection.
	clientLocation string

	// oobCache stores the interface index and IP where the requests are received from the client.
	// This is used to send UDP packets from the correct interface and IP.
	oobCache []byte

	// The UDPConn where the last client packet was received from.
	lastSeenConn onet.UDPPacketConn
}

func (c *natconn) WriteToUDP(buf []byte, dst *net.UDPAddr) (int, error) {
	return c.session.WriteToUDP(buf, dst)
}

func (c *natconn) ReadFromUDP(buf []byte) (int, *net.UDPAddr, error) {
	return c.session.ReadFromUDP(buf)
}

// timedCopy copies from targetConn to clientConn until read timeout.
// Pass Shadowsocks 2022 session as ses.
func (c *natconn) timedCopy(ses *session, sm metrics.ShadowsocksMetrics) {
	// pkt is used for in-place encryption of downstream UDP packets, with the layout
	// [padding?][salt][address][body][tag][extra]
	// Padding is only used if the address is IPv4.
	pkt := make([]byte, UDPPacketBufferSize)
	saltSize := c.cipher.SaltSize()
	cipherConfig := c.cipher.Config()

	// Leave enough room at the beginning of the packet for a max-length header (i.e. IPv6).
	var bodyStart int

	switch {
	case cipherConfig.UDPHasSeparateHeader:
		bodyStart = ss.UDPServerMessageHeaderFixedLength + ss.MaxPaddingLength + socks.SocksAddressIPv6Length
	case cipherConfig.IsSpec2022:
		bodyStart = 24 + ss.UDPServerMessageHeaderFixedLength + ss.MaxPaddingLength + socks.SocksAddressIPv6Length
	default:
		bodyStart = saltSize + socks.SocksAddressIPv6Length
	}

	expired := false

	for {
		var bodyLen, proxyClientBytes int
		var lastSeenAddr *net.UDPAddr
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
				lastSeenAddr = ses.lastSeenAddr
				bodyLen, raddr, err = ses.ReadFromUDP(readBuf)
			default:
				lastSeenAddr = c.session.lastSeenAddr
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

			socksAddrLen := socks.SocksAddressIPv6Length
			if raddr.IP.To4() != nil {
				socksAddrLen = socks.SocksAddressIPv4Length
			}

			switch {
			case cipherConfig.IsSpec2022:
				var paddingLen int
				if raddr.Port == 53 {
					paddingLen = rand.Intn(ss.MaxPaddingLength + 1)
				}
				headerStart = bodyStart - ss.UDPServerMessageHeaderFixedLength - paddingLen - socksAddrLen
				ss.WriteUDPHeader(pkt[headerStart:], ss.HeaderTypeServerPacket, ses.ssid, ses.spid, ses.csid, raddr, nil, paddingLen)
				ses.spid++
			default:
				headerStart = bodyStart - socksAddrLen
				socks.WriteUDPAddrAsSocksAddr(pkt[headerStart:], raddr)
			}

			// `plainTextBuf` concatenates the SOCKS address and body:
			// [padding?][salt][address][body][tag][unused]
			// |-- addrStart -|[plaintextBuf ]
			plaintextBuf := pkt[headerStart : bodyStart+bodyLen]

			switch {
			case cipherConfig.UDPHasSeparateHeader:
				pktStart = headerStart
			case cipherConfig.IsSpec2022:
				pktStart = headerStart - 24
			default:
				pktStart = headerStart - saltSize
			}

			// `packBuf` adds space for the salt and tag.
			// `buf` shows the space that was used.
			// [padding?][salt][address][body][tag][unused]
			//           [            packBuf             ]
			//           [          buf           ]
			packBuf := pkt[pktStart:]

			switch {
			case cipherConfig.UDPHasSeparateHeader:
				buf, err = ss.PackAesWithSeparateHeader(packBuf, plaintextBuf, c.cipher, ses.saead)
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
			logger.Warn(connError.Message,
				zap.Stringer("listenAddress", c.lastSeenConn.LocalAddr()),
				zap.Stringer("clientAddress", lastSeenAddr),
				zap.Error(connError.Cause),
			)
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

func (m *natmap) GetByClientSessionID(csid uint64) *session {
	m.RLock()
	defer m.RUnlock()
	return m.sidConn[csid]
}

func (m *natmap) AddNatEntry(clientAddr *net.UDPAddr, clientConn onet.UDPPacketConn, cipher *ss.Cipher, clientLocation, keyID string, ses *session) *natconn {
	entry := &natconn{
		session:        ses,
		cipher:         cipher,
		keyID:          keyID,
		clientLocation: clientLocation,
		lastSeenConn:   clientConn,
	}

	m.Lock()
	defer m.Unlock()

	m.keyConn[clientAddr.String()] = entry
	return entry
}

func (m *natmap) StartNatconn(clientAddr *net.UDPAddr, entry *natconn, cipherConfig ss.CipherConfig) {
	m.metrics.AddUDPNatEntry()
	m.running.Add(1)
	go func() {
		switch {
		case cipherConfig.IsSpec2022:
			entry.swg.Wait()
		default:
			entry.timedCopy(nil, m.metrics)
			entry.session.targetConn.Close()
		}

		m.Lock()
		delete(m.keyConn, clientAddr.String())
		m.Unlock()

		m.metrics.RemoveUDPNatEntry()
		m.running.Done()
	}()
}

func (m *natmap) AddSession(csid uint64, ses *session, entry *natconn) {
	m.Lock()
	m.sidConn[csid] = ses
	m.Unlock()

	entry.swg.Add(1)
	go func() {
		entry.timedCopy(ses, m.metrics)
		ses.targetConn.Close()

		m.Lock()
		delete(m.sidConn, csid)
		m.Unlock()

		entry.swg.Done()
	}()
}

func (m *natmap) Close() error {
	m.Lock()
	defer m.Unlock()

	var err error
	now := time.Now()
	for _, pc := range m.keyConn {
		if pc.session != nil {
			if e := pc.session.targetConn.SetReadDeadline(now); e != nil {
				err = e
			}
		}
	}
	for _, ses := range m.sidConn {
		if e := ses.targetConn.SetReadDeadline(now); e != nil {
			err = e
		}
	}
	return err
}

type session struct {
	// csid stores client session ID for Shadowsocks 2022 Edition methods.
	csid []byte

	// ssid stores server session ID for Shadowsocks 2022 Edition methods.
	ssid []byte

	// spid stores server packet ID for Shadowsocks 2022 Edition methods.
	spid uint64

	// Stores reference to target conn.
	targetConn onet.UDPPacketConn

	// NAT timeout to apply for non-DNS packets.
	defaultTimeout time.Duration

	// Current read deadline of targetConn. Used to avoid decreasing the
	// deadline. Initially zero.
	readDeadline time.Time

	// If the connection has only sent one DNS query, it will close
	// if it receives a DNS response.
	fastClose sync.Once

	// The UDPAddr where the last client packet was received from.
	// Use this.String() as key to look up the NAT table.
	lastSeenAddr *net.UDPAddr

	// Unix epoch timestamp when the last client packet was received.
	lastSeenTime int64

	// cfilter is the client session's sliding window filter.
	// It rejects duplicate or out-of-window incoming client packets.
	cfilter *wgreplay.Filter

	// Only used by 2022-blake3-aes-256-gcm.
	// Initialized with client session subkey.
	caead cipher.AEAD

	// Only used by 2022-blake3-aes-256-gcm.
	// Initialized with server session subkey.
	saead cipher.AEAD
}

func newSession(csid, ssid []byte, defaultTimeout time.Duration, caead, saead cipher.AEAD) *session {
	return &session{
		csid:           csid,
		ssid:           ssid,
		defaultTimeout: defaultTimeout,
		lastSeenTime:   time.Now().Unix(),
		cfilter:        &wgreplay.Filter{},
		caead:          caead,
		saead:          saead,
	}
}

func isDNS(addr *net.UDPAddr) bool {
	return addr.Port == 53
}

func (s *session) onWrite(addr *net.UDPAddr) {
	// Fast close is only allowed if there has been exactly one write,
	// and it was a DNS query.
	isDNS := isDNS(addr)
	isFirstWrite := s.readDeadline.IsZero()
	if !isDNS || !isFirstWrite {
		// Disable fast close.  (Idempotent.)
		s.fastClose.Do(func() {})
	}

	timeout := s.defaultTimeout
	if isDNS {
		// Shorten timeout as required by RFC 5452 Section 10.
		timeout = 17 * time.Second
	}

	newDeadline := time.Now().Add(timeout)
	if newDeadline.After(s.readDeadline) {
		s.readDeadline = newDeadline
		s.targetConn.SetReadDeadline(newDeadline)
	}
}

func (s *session) onRead(addr *net.UDPAddr) {
	s.fastClose.Do(func() {
		if isDNS(addr) {
			// The next ReadFrom() should time out immediately.
			s.targetConn.SetReadDeadline(time.Now())
		}
	})
}

func (s *session) WriteToUDP(buf []byte, dst *net.UDPAddr) (int, error) {
	s.onWrite(dst)
	return s.targetConn.WriteToUDP(buf, dst)
}

func (s *session) ReadFromUDP(buf []byte) (int, *net.UDPAddr, error) {
	n, addr, err := s.targetConn.ReadFromUDP(buf)
	if err == nil {
		s.onRead(addr)
	}
	return n, addr, err
}
