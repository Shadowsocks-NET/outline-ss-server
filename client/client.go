package client

import (
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
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

	ShadowsocksPacketConnFrontReserve = 24 + 8 + 8 + 1 + 8 + 2 + ss.MaxPaddingLength + socks.MaxAddrLen
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
	// `raddr` has the form `host:port`, where `host` can be a domain name or IP address.
	DialTCP(laddr *net.TCPAddr, raddr string, dialerTFO bool) (onet.DuplexConn, error)

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
func (c *ssClient) DialTCP(laddr *net.TCPAddr, raddr string, dialerTFO bool) (onet.DuplexConn, error) {
	dialer := tfo.Dialer{
		DisableTFO: !dialerTFO,
	}
	dialer.LocalAddr = laddr
	proxyConn, err := dialer.Dial("tcp", c.address)
	if err != nil {
		return nil, err
	}

	socksaddr, err := socks.ParseAddr(raddr)
	if err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("failed to parse address: %w", err)
	}

	ssw, err := ss.NewShadowsocksWriter(proxyConn, c.cipher, nil, socksaddr, c.cipher.Config().IsSpec2022)
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

func (dc *duplexConnAdaptor) readHeader() error {
	err := ss.ParseTCPRespHeader(dc.r, dc.w.Salt(), dc.cipherConfig)
	if err != nil {
		dc.Close()
		return err
	}

	// 2022 spec: check salt
	if dc.cipherConfig.IsSpec2022 && !dc.saltPool.Add(*(*[32]byte)(dc.r.Salt())) {
		io.Copy(io.Discard, dc.r)
		dc.Close()
		return ErrRepeatedSalt
	}

	return nil
}

func (dc *duplexConnAdaptor) Read(b []byte) (int, error) {
	if !dc.isHeaderProcessed {
		err := dc.readHeader()
		if err != nil {
			return 0, err
		}
		dc.isHeaderProcessed = true
	}

	return dc.r.Read(b)
}

func (dc *duplexConnAdaptor) WriteTo(w io.Writer) (int64, error) {
	if !dc.isHeaderProcessed {
		err := dc.readHeader()
		if err != nil {
			return 0, err
		}
		dc.isHeaderProcessed = true
	}

	return io.Copy(w, dc.r)
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

	// ReadFromZeroCopy eliminates copying by requiring that a big enough buffer is passed for reading.
	ReadFromZeroCopy(b []byte) (payload []byte, address string, err error)

	// WriteToZeroCopy minimizes copying by requiring that enough space is reserved in b.
	// The socks address is still being copied into the buffer.
	//
	// You should reserve 24 + 8 + 8 + 1 + 8 + 2 + ss.MaxPaddingLength + socks.MaxAddrLen in the beginning,
	// and cipher.TagSize() in the end.
	//
	// start points to where the actual payload (excluding header) starts.
	// length is payload length.
	WriteToZeroCopy(b []byte, start, length int, socksAddr []byte) (n int, err error)
}

type packetConn struct {
	*net.UDPConn
	cipher *ss.Cipher

	// sid stores session ID for Shadowsocks 2022 Edition methods.
	sid []byte

	// pid stores packet ID for Shadowsocks 2022 Edition methods.
	pid uint64

	// Provides sliding window replay protection.
	filter *wgreplay.Filter

	// Only used by 2022-blake3-aes-256-gcm.
	// Initialized with session subkey.
	aead cipher.AEAD
}

func newPacketConn(proxyConn *net.UDPConn, c *ss.Cipher) (*packetConn, error) {
	// Random session ID
	sid := make([]byte, 8)
	err := ss.Blake3KeyedHashSaltGenerator.GetSalt(sid)
	if err != nil {
		return nil, err
	}

	// Separate header AEAD
	var aead cipher.AEAD
	aead, err = c.NewAEAD(sid)
	if err != nil {
		return nil, err
	}

	return &packetConn{
		UDPConn: proxyConn,
		cipher:  c,
		sid:     sid,
		filter:  &wgreplay.Filter{},
		aead:    aead,
	}, nil
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
	n, err := ss.WriteClientUDPHeader(cipherBuf[headerStart:], cipherConfig, c.sid, c.pid, addr, 1452)
	if err != nil {
		return 0, err
	}
	if cipherConfig.IsSpec2022 {
		c.pid++
	}

	// Copy payload
	copy(cipherBuf[headerStart+n:], b)

	var buf []byte
	plaintextLen := n + len(b)

	switch {
	case cipherConfig.UDPHasSeparateHeader:
		buf, err = ss.PackAesWithSeparateHeader(cipherBuf, cipherBuf[headerStart:headerStart+plaintextLen], c.cipher, c.aead)
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

	if cipherConfig.IsSpec2022 && socksAddr[len(socksAddr)-2] == 0 && socksAddr[len(socksAddr)-1] == 53 {
		paddingLen = rand.Intn(ss.MaxPaddingLength + 1)
	}

	switch {
	case cipherConfig.UDPHasSeparateHeader:
		headerStart = socksAddrStart - paddingLen - 2 - 8 - 1 - 8 - 8
		packetStart = headerStart
	case cipherConfig.IsSpec2022:
		headerStart = socksAddrStart - paddingLen - 2 - 8 - 1 - 8 - 8
		packetStart = headerStart - 24
	default:
		headerStart = socksAddrStart
		packetStart = headerStart - c.cipher.SaltSize()
	}

	// Write header
	switch {
	case cipherConfig.IsSpec2022:
		ss.WriteUDPHeader(b[headerStart:], ss.HeaderTypeClientPacket, c.sid, c.pid, nil, socksAddr, paddingLen)
		c.pid++
	default:
		copy(b[headerStart:], socksAddr)
	}

	var buf []byte
	switch {
	case cipherConfig.UDPHasSeparateHeader:
		buf, err = ss.PackAesWithSeparateHeader(b[packetStart:], b[headerStart:start+length], c.cipher, c.aead)
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
	payload, address, err := ss.UnpackAndValidatePacket(c.cipher, c.aead, c.filter, c.sid, nil, cipherBuf[:n])
	if err != nil {
		return 0, nil, err
	}

	n = copy(b, payload)
	if n < len(payload) {
		err = io.ErrShortBuffer
	}

	return n, NewAddr(address, "udp"), err
}

func (c *packetConn) ReadFromZeroCopy(b []byte) (payload []byte, address string, err error) {
	n, err := c.UDPConn.Read(b)
	if err != nil {
		return
	}

	payload, address, err = ss.UnpackAndValidatePacket(c.cipher, c.aead, c.filter, c.sid, nil, b[:n])
	return
}

type addr struct {
	address string
	network string
}

func (a *addr) String() string {
	return a.address
}

func (a *addr) Network() string {
	return a.network
}

// NewAddr returns a net.Addr that holds an address of the form `host:port` with a domain name or IP as host.
// Used for SOCKS addressing.
func NewAddr(address, network string) net.Addr {
	return &addr{
		address: address,
		network: network,
	}
}
