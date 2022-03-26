package client

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"time"

	onet "github.com/Shadowsocks-NET/outline-ss-server/net"
	"github.com/Shadowsocks-NET/outline-ss-server/service"
	ss "github.com/Shadowsocks-NET/outline-ss-server/shadowsocks"
	"github.com/Shadowsocks-NET/outline-ss-server/slicepool"
	"github.com/Shadowsocks-NET/outline-ss-server/socks"
	"github.com/database64128/tfo-go"
	wgreplay "golang.zx2c4.com/wireguard/replay"
)

const (
	// This code contains an optimization to send the initial client payload along with
	// the Shadowsocks handshake.  This saves one packet during connection, and also
	// reduces the distinctiveness of the connection pattern.
	//
	// Normally, the initial payload will be sent as soon as the socket is connected,
	// except for delays due to inter-process communication.  However, some protocols
	// expect the server to send data first, in which case there is no client payload.
	// We therefore use a short delay, longer than any reasonable IPC but shorter than
	// typical network latency.  (In an Android emulator, the 90th percentile delay
	// was ~1 ms.)  If no client payload is received by this time, we connect without it.
	helloWait = 100 * time.Millisecond

	// Defines the space to reserve in front of a slice for making an outgoing Shadowsocks client message.
	ShadowsocksPacketConnFrontReserve = 24 + ss.UDPClientMessageHeaderFixedLength + ss.MaxPaddingLength + socks.MaxAddrLen
)

var (
	// udpPool stores the byte slices used for storing encrypted packets.
	udpPool = slicepool.MakePool(service.UDPPacketBufferSize)

	ErrRepeatedSalt = errors.New("server stream has repeated salt")
)

// Client is a client for Shadowsocks TCP and UDP connections.
type Client interface {
	// DialTCP connects to `raddr` over TCP though a Shadowsocks proxy.
	// `laddr` is a local bind address, a local address is automatically chosen if nil.
	// `raddr` is the target socks address.
	DialTCP(laddr *net.TCPAddr, raddr []byte, dialerTFO bool) (onet.DuplexConn, error)

	// ListenUDP starts a new Shadowsocks UDP session and returns a connection that
	// can be used to relay UDP packets though the proxy.
	// `laddr` is a local bind address, a local address is automatically chosen if nil.
	// For Shadowsocks 2022, this encapsulation does not support multiplexing several sessions
	// into one proxy connection.
	ListenUDP(laddr *net.UDPAddr) (ShadowsocksPacketConn, error)

	// Cipher gets the underlying Shadowsocks cipher used by the client.
	Cipher() *ss.Cipher
}

// NewClient creates a client that routes connections to a Shadowsocks proxy listening at
// `host:port`, with authentication parameters `cipher` (AEAD) and `password`.
// TODO: add a dialer argument to support proxy chaining and transport changes.
func NewClient(address, method, password string, saltPool *service.SaltPool) (Client, error) {
	cipher, err := ss.NewCipher(method, password)
	if err != nil {
		return nil, err
	}

	return &ssClient{
		address:  address,
		cipher:   cipher,
		saltPool: saltPool,
	}, nil
}

type ssClient struct {
	address  string
	cipher   *ss.Cipher
	saltPool *service.SaltPool
}

func (c *ssClient) Cipher() *ss.Cipher {
	return c.cipher
}

// DialTCP implements the Client DialTCP method.
func (c *ssClient) DialTCP(laddr *net.TCPAddr, raddr []byte, dialerTFO bool) (onet.DuplexConn, error) {
	dialer := tfo.Dialer{
		DisableTFO: !dialerTFO,
	}
	dialer.LocalAddr = laddr
	proxyConn, err := dialer.Dial("tcp", c.address)
	if err != nil {
		return nil, err
	}

	ssw, err := ss.NewShadowsocksWriter(proxyConn, c.cipher, nil, raddr, c.cipher.Config().IsSpec2022)
	if err != nil {
		proxyConn.Close()
		return nil, err
	}
	time.AfterFunc(helloWait, func() {
		ssw.Flush()
	})

	ssr := ss.NewShadowsocksReader(proxyConn, c.cipher)

	return &duplexConnAdaptor{
		DuplexConn:   proxyConn.(onet.DuplexConn),
		r:            ssr,
		w:            ssw,
		cipherConfig: c.cipher.Config(),
		saltPool:     c.saltPool,
	}, nil
}

type duplexConnAdaptor struct {
	onet.DuplexConn
	r                 ss.Reader
	w                 *ss.Writer
	cipherConfig      ss.CipherConfig
	isHeaderProcessed bool
	saltPool          *service.SaltPool
}

func (dc *duplexConnAdaptor) readHeader() ([]byte, error) {
	initPayload, err := ss.ParseTCPRespHeader(dc.r, dc.w.Salt(), dc.cipherConfig)
	if err != nil {
		dc.Close()
		return nil, err
	}

	// 2022 spec: check salt
	if dc.cipherConfig.IsSpec2022 && !dc.saltPool.Add(*(*[32]byte)(dc.r.Salt())) {
		io.Copy(io.Discard, dc.r)
		dc.Close()
		return nil, ErrRepeatedSalt
	}

	return initPayload, nil
}

func (dc *duplexConnAdaptor) Read(b []byte) (n int, err error) {
	if !dc.isHeaderProcessed {
		var initPayload []byte
		initPayload, err = dc.readHeader()
		if err != nil {
			return 0, err
		}
		dc.isHeaderProcessed = true

		if len(initPayload) > 0 {
			n = copy(b, initPayload)
			if n < len(initPayload) {
				err = io.ErrShortBuffer
			}
			return
		}
	}

	return dc.r.Read(b)
}

func (dc *duplexConnAdaptor) WriteTo(w io.Writer) (n int64, err error) {
	if !dc.isHeaderProcessed {
		initPayload, err := dc.readHeader()
		if err != nil {
			return 0, err
		}
		dc.isHeaderProcessed = true

		if len(initPayload) > 0 {
			wn, err := w.Write(initPayload)
			n = int64(wn)
			if err != nil {
				return n, err
			}
		}
	}

	cn, err := io.Copy(w, dc.r)
	n += cn
	return
}

func (dc *duplexConnAdaptor) CloseRead() error {
	return dc.DuplexConn.CloseRead()
}

func (dc *duplexConnAdaptor) Write(b []byte) (int, error) {
	return dc.w.Write(b)
}

func (dc *duplexConnAdaptor) ReadFrom(r io.Reader) (int64, error) {
	return io.Copy(dc.w, r)
}

func (dc *duplexConnAdaptor) CloseWrite() error {
	return dc.DuplexConn.CloseWrite()
}

// ListenUDP implements the Client ListenUDP method.
func (c *ssClient) ListenUDP(laddr *net.UDPAddr) (ShadowsocksPacketConn, error) {
	proxyAddr, err := net.ResolveUDPAddr("udp", c.address)
	if err != nil {
		return nil, err
	}

	proxyConn, err := net.DialUDP("udp", laddr, proxyAddr)
	if err != nil {
		return nil, err
	}

	return newPacketConn(proxyConn, c.cipher)
}

// ShadowsocksPacketConn adds zero-copy methods for reading from
// and writing to a Shadowsocks UDP proxy.
type ShadowsocksPacketConn interface {
	net.PacketConn

	// RemoteAddr returns the remote proxy's address.
	RemoteAddr() net.Addr

	// ReadFromZeroCopy eliminates copying by requiring that a big enough buffer is passed for reading.
	ReadFromZeroCopy(b []byte) (socksAddrStart, payloadStart, payloadLength int, err error)

	// WriteToZeroCopy minimizes copying by requiring that enough space is reserved in b.
	// The socks address is still being copied into the buffer.
	//
	// You should reserve 24 + ss.UDPClientMessageHeaderFixedLength + ss.MaxPaddingLength + socks.MaxAddrLen
	// in the beginning, and cipher.TagSize() in the end.
	//
	// start points to where the actual payload (excluding header) starts.
	// length is payload length.
	WriteToZeroCopy(b []byte, start, length int, socksAddr []byte) (n int, err error)
}

type packetConn struct {
	*net.UDPConn
	cipher *ss.Cipher

	// csid stores client session ID for Shadowsocks 2022 Edition methods.
	csid []byte

	// cpid stores client packet ID for Shadowsocks 2022 Edition methods.
	cpid uint64

	// caead is the client session's AEAD cipher.
	// Only used by 2022-blake3-aes-256-gcm.
	// Initialized with client session subkey.
	caead cipher.AEAD

	// cssid stores the current server session ID for Shadowsocks 2022 Edition methods.
	cssid []byte

	// csaead is the current server session's AEAD cipher.
	// Only used by 2022-blake3-aes-256-gcm.
	// Initialized with the current server session subkey.
	csaead cipher.AEAD

	// csfilter is the current server session's sliding window filter.
	csfilter *wgreplay.Filter

	// ossid stores the old server session ID for Shadowsocks 2022 Edition methods.
	ossid []byte

	// osaead is the oldl server session's AEAD cipher.
	// Only used by 2022-blake3-aes-256-gcm.
	// Initialized with the old server session subkey.
	osaead cipher.AEAD

	// osfilter is the old server session's sliding window filter.
	osfilter *wgreplay.Filter

	// osLastSeenTime is the last time when we received a packet from the old server session.
	osLastSeenTime time.Time
}

func newPacketConn(proxyConn *net.UDPConn, c *ss.Cipher) (*packetConn, error) {
	// Random session ID
	csid := make([]byte, 8)
	err := ss.Blake3KeyedHashSaltGenerator.GetSalt(csid)
	if err != nil {
		return nil, err
	}

	// Separate header client AEAD
	var caead cipher.AEAD
	caead, err = c.NewAEAD(csid)
	if err != nil {
		return nil, err
	}

	return &packetConn{
		UDPConn:  proxyConn,
		cipher:   c,
		csid:     csid,
		csfilter: &wgreplay.Filter{},
		caead:    caead,
	}, nil
}

func (c *packetConn) RemoteAddr() net.Addr {
	return c.UDPConn.RemoteAddr()
}

// WriteTo encrypts `b` and writes to `addr` through the proxy.
func (c *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	lazySlice := udpPool.LazySlice()
	cipherBuf := lazySlice.Acquire()
	defer lazySlice.Release()

	cipherConfig := c.cipher.Config()

	// Calculate where to start writing header
	var headerStart int

	switch {
	case cipherConfig.UDPHasSeparateHeader: // Starts at 0
	case cipherConfig.IsSpec2022:
		headerStart = 24
	default:
		headerStart = c.cipher.SaltSize()
	}

	// Write header
	n, err := ss.WriteClientUDPHeader(cipherBuf[headerStart:], cipherConfig, c.csid, c.cpid, addr, 1452)
	if err != nil {
		return 0, err
	}
	if cipherConfig.IsSpec2022 {
		c.cpid++
	}

	// Copy payload
	copy(cipherBuf[headerStart+n:], b)

	var buf []byte
	plaintextLen := n + len(b)

	switch {
	case cipherConfig.UDPHasSeparateHeader:
		buf, err = ss.PackAesWithSeparateHeader(cipherBuf, cipherBuf[headerStart:headerStart+plaintextLen], c.cipher, c.caead)
	default:
		buf, err = ss.Pack(cipherBuf, cipherBuf[headerStart:headerStart+plaintextLen], c.cipher)
	}

	if err != nil {
		return 0, err
	}

	_, err = c.UDPConn.Write(buf)
	return len(b), err
}

func (c *packetConn) WriteToZeroCopy(b []byte, start, length int, socksAddr []byte) (n int, err error) {
	cipherConfig := c.cipher.Config()

	// Calculate where to start writing socks address, header
	socksAddrStart := start - len(socksAddr)
	var paddingLen int
	var headerStart int
	var packetStart int

	if cipherConfig.IsSpec2022 && len(socksAddr) > 1 && socksAddr[len(socksAddr)-2] == 0 && socksAddr[len(socksAddr)-1] == 53 {
		paddingLen = rand.Intn(ss.MaxPaddingLength + 1)
	}

	switch {
	case cipherConfig.UDPHasSeparateHeader:
		headerStart = socksAddrStart - paddingLen - ss.UDPClientMessageHeaderFixedLength
		packetStart = headerStart
	case cipherConfig.IsSpec2022:
		headerStart = socksAddrStart - paddingLen - ss.UDPClientMessageHeaderFixedLength
		packetStart = headerStart - 24
	default:
		headerStart = socksAddrStart
		packetStart = headerStart - c.cipher.SaltSize()
	}

	// Write header
	switch {
	case cipherConfig.IsSpec2022:
		ss.WriteUDPHeader(b[headerStart:], ss.HeaderTypeClientPacket, c.csid, c.cpid, nil, nil, socksAddr, paddingLen)
		c.cpid++
	default:
		copy(b[headerStart:], socksAddr)
	}

	var buf []byte
	switch {
	case cipherConfig.UDPHasSeparateHeader:
		buf, err = ss.PackAesWithSeparateHeader(b[packetStart:], b[headerStart:start+length], c.cipher, c.caead)
	default:
		buf, err = ss.Pack(b[packetStart:], b[headerStart:start+length], c.cipher)
	}

	if err != nil {
		return 0, err
	}

	_, err = c.UDPConn.Write(buf)
	return len(b), err
}

// ReadFrom reads from the embedded PacketConn and decrypts into `b`.
func (c *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	lazySlice := udpPool.LazySlice()
	cipherBuf := lazySlice.Acquire()
	defer lazySlice.Release()

	n, err := c.UDPConn.Read(cipherBuf)
	if err != nil {
		return 0, nil, err
	}

	// Decrypt in-place.
	_, socksAddr, payload, err := c.unpackAndValidatePacket(nil, cipherBuf[:n])
	if err != nil {
		return 0, nil, err
	}

	addr, err := socksAddr.Addr("udp")
	if err != nil {
		return 0, nil, err
	}

	n = copy(b, payload)
	if n < len(payload) {
		err = io.ErrShortBuffer
	}

	return n, addr, err
}

func (c *packetConn) ReadFromZeroCopy(b []byte) (socksAddrStart, payloadStart, payloadLength int, err error) {
	n, err := c.UDPConn.Read(b)
	if err != nil {
		return
	}

	socksAddrStart, socksAddr, payload, err := c.unpackAndValidatePacket(nil, b[:n])
	payloadStart = socksAddrStart + len(socksAddr)
	payloadLength = len(payload)
	return
}

// unpackAndValidatePacket unpacks an encrypted packet, validates the packet,
// and returns the payload (without header) and the address.
func (c *packetConn) unpackAndValidatePacket(dst, src []byte) (socksAddrStart int, socksAddr socks.Addr, payload []byte, err error) {
	cipherConfig := c.cipher.Config()
	var plaintextStart int
	var buf []byte

	const (
		currentServerSession = iota
		oldServerSession
		newServerSession
	)

	var sessionStatus int
	var ssid []byte
	var saead cipher.AEAD
	var sfilter *wgreplay.Filter

	switch {
	case cipherConfig.UDPHasSeparateHeader:
		if dst == nil {
			dst = src
		}

		// Decrypt separate header
		err = ss.DecryptSeparateHeader(c.cipher, dst, src)
		if err != nil {
			return
		}

		// Check server session id
		switch {
		case bytes.Equal(c.cssid, dst[:8]): // is current server session
			sessionStatus = currentServerSession
			ssid = c.cssid
			saead = c.csaead
			sfilter = c.csfilter
		case bytes.Equal(c.ossid, dst[:8]): // is old server session
			sessionStatus = oldServerSession
			ssid = c.ossid
			saead = c.osaead
			sfilter = c.osfilter
		default: // is a new server session
			// When a server session changes, there's a replay window of less than 60 seconds,
			// during which an adversary can replay packets with a valid timestamp from the old session.
			// To protect against such attacks, and to simplify implementation and save resources,
			// we only save information for one previous session.
			//
			// In an unlikely event where the server session changed more than once within 60s,
			// we simply drop new server sessions.
			if time.Since(c.osLastSeenTime) < 60*time.Second {
				err = ss.ErrTooManyServerSessions
				return
			}
			sessionStatus = newServerSession
			ssid = dst[:8]
			saead, err = c.cipher.NewAEAD(ssid)
			if err != nil {
				return
			}
			// Delay sfilter creation after validation to avoid a possibly unnecessary allocation.
		}

		// Unpack
		buf, err = ss.UnpackAesWithSeparateHeader(dst, src, nil, c.cipher, saead)
		if err != nil {
			return
		}

	case cipherConfig.IsSpec2022:
		plaintextStart, buf, err = ss.Unpack(dst, src, c.cipher)
		if err != nil {
			return
		}

		// Check server session id
		switch {
		case bytes.Equal(c.cssid, buf[:8]): // is current server session
			sessionStatus = currentServerSession
			ssid = c.cssid
			sfilter = c.csfilter
		case bytes.Equal(c.ossid, buf[:8]): // is old server session
			sessionStatus = oldServerSession
			ssid = c.ossid
			sfilter = c.osfilter
		default: // is a new server session
			if time.Since(c.osLastSeenTime) < 60*time.Second {
				err = ss.ErrTooManyServerSessions
				return
			}
			sessionStatus = newServerSession
			ssid = buf[:8]
			// Delay sfilter creation after validation to avoid a possibly unnecessary allocation.
		}

	default:
		plaintextStart, buf, err = ss.Unpack(dst, src, c.cipher)
		if err != nil {
			return
		}
	}

	socksAddrStart, socksAddr, payload, err = ss.ParseUDPHeader(buf, ss.HeaderTypeServerPacket, c.csid, cipherConfig)
	if err != nil {
		return
	}
	socksAddrStart += plaintextStart

	if cipherConfig.IsSpec2022 {
		pid := binary.BigEndian.Uint64(buf[8:])
		if sessionStatus == newServerSession {
			sfilter = &wgreplay.Filter{}
		}
		if !sfilter.ValidateCounter(pid, math.MaxUint64) {
			err = fmt.Errorf("detected replay packet, server session id %v, packet id %d", ssid, pid)
			return
		}
		switch sessionStatus {
		case oldServerSession:
			// Update old session's last seen time.
			c.osLastSeenTime = time.Now()
		case newServerSession:
			// Move current to old.
			c.ossid = c.cssid
			c.osaead = c.csaead
			c.osfilter = c.csfilter
			c.osLastSeenTime = time.Now()
			// Save temporary vars to current.
			c.cssid = ssid
			c.csaead = saead
			c.csfilter = sfilter
		}
	}

	return
}
