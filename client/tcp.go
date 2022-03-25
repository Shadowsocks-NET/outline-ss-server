package client

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"

	onet "github.com/Shadowsocks-NET/outline-ss-server/net"
	"github.com/Shadowsocks-NET/outline-ss-server/socks"
	"github.com/database64128/tfo-go"
	"go.uber.org/zap"
)

type TCPTunnel struct {
	listenAddress string
	listenerTFO   bool
	dialerTFO     bool

	client     Client
	listener   *net.TCPListener
	handshaker Handshaker
}

func (s *TCPTunnel) String() string {
	return fmt.Sprint("TCP ", s.handshaker.String(), " relay service")
}

func (s *TCPTunnel) Start() error {
	lc := tfo.ListenConfig{
		DisableTFO: !s.listenerTFO,
	}
	l, err := lc.Listen(context.Background(), "tcp", s.listenAddress)
	if err != nil {
		return err
	}
	s.listener = l.(*net.TCPListener)

	go func() {
		defer s.listener.Close()

		for {
			clientConn, err := l.(*net.TCPListener).AcceptTCP()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				logger.Warn("Failed to accept TCP connection",
					zap.Stringer("service", s),
					zap.String("listenAddress", s.listenAddress),
					zap.Error(err),
				)
				continue
			}

			go s.handleConn(clientConn)
		}
	}()
	logger.Info("Started listener", zap.Stringer("service", s), zap.String("listenAddress", s.listenAddress))
	return nil
}

func (s *TCPTunnel) handleConn(clientConn *net.TCPConn) {
	defer clientConn.Close()

	socksaddr, err := s.handshaker.Handshake(clientConn)
	if err != nil {
		logger.Warn("Failed to handshake with client",
			zap.Stringer("service", s),
			zap.Stringer("clientConnLocalAddress", clientConn.LocalAddr()),
			zap.Stringer("clientConnRemoteAddress", clientConn.RemoteAddr()),
			zap.Error(err),
		)
		return
	}
	if socksaddr == nil {
		// Keep the connection open until EOF.
		// Example use case: SOCKS5 UDP ASSOCIATE command.
		logger.Debug("Keeping TCP connection open for UDP association",
			zap.Stringer("service", s),
			zap.Stringer("clientConnLocalAddress", clientConn.LocalAddr()),
			zap.Stringer("clientConnRemoteAddress", clientConn.RemoteAddr()),
		)

		b := make([]byte, 1)
		_, err = io.ReadFull(clientConn, b)
		if err != nil && err != io.ErrUnexpectedEOF {
			logger.Warn("TCP connection for UDP association failed",
				zap.Stringer("service", s),
				zap.Stringer("clientConnLocalAddress", clientConn.LocalAddr()),
				zap.Stringer("clientConnRemoteAddress", clientConn.RemoteAddr()),
				zap.Error(err),
			)
		}
		return
	}

	logger.Debug("Dialing target",
		zap.Stringer("service", s),
		zap.Stringer("clientConnLocalAddress", clientConn.LocalAddr()),
		zap.Stringer("clientConnRemoteAddress", clientConn.RemoteAddr()),
		zap.Stringer("targetAddress", socksaddr),
		zap.Bool("dialerTFO", s.dialerTFO),
	)

	proxyConn, err := s.client.DialTCP(nil, socksaddr, s.dialerTFO)
	if err != nil {
		logger.Warn("Failed to dial target via proxy",
			zap.Stringer("service", s),
			zap.Stringer("clientConnLocalAddress", clientConn.LocalAddr()),
			zap.Stringer("clientConnRemoteAddress", clientConn.RemoteAddr()),
			zap.Stringer("targetAddress", socksaddr),
			zap.Error(err),
		)
		return
	}
	defer proxyConn.Close()

	logger.Info("Relaying",
		zap.Stringer("service", s),
		zap.Stringer("clientConnRemoteAddress", clientConn.RemoteAddr()),
		zap.Stringer("proxyConnRemoteAddress", proxyConn.RemoteAddr()),
		zap.Stringer("targetAddress", socksaddr),
	)

	err = relay(clientConn, proxyConn)
	if err != nil {
		logger.Warn("TCP relay failed",
			zap.Stringer("service", s),
			zap.Stringer("clientConnLocalAddress", clientConn.LocalAddr()),
			zap.Stringer("clientConnRemoteAddress", clientConn.RemoteAddr()),
			zap.Stringer("proxyConnLocalAddress", proxyConn.LocalAddr()),
			zap.Stringer("proxyConnRemoteAddress", proxyConn.RemoteAddr()),
			zap.Error(err),
		)
	}
}

func relay(leftConn, rightConn onet.DuplexConn) error {
	ch := make(chan error, 1)

	go func() {
		_, err := io.Copy(leftConn, rightConn)
		leftConn.CloseWrite()
		ch <- err
	}()

	_, err := io.Copy(rightConn, leftConn)
	rightConn.CloseWrite()

	innerErr := <-ch

	if err != nil {
		return err
	}
	if innerErr != nil {
		return innerErr
	}
	return nil
}

func (s *TCPTunnel) Stop() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// Handshaker handles the handshake with clientConn for TCPTunnel.
//
// An implementation of Handshaker must be thread-safe.
// Handshake(1) may be called simultaneously from different goroutines.
//
// If both the returned socks address and error are nil, the connection is kept open until EOF.
type Handshaker interface {
	String() string
	Handshake(*net.TCPConn) (socks.Addr, error)
}

// SimpleTunnelHandshaker simply tunnels traffic between clientConn and proxyConn.
type SimpleTunnelHandshaker struct {
	remoteSocksAddr socks.Addr
}

func NewSimpleTunnelHandshaker(remoteSocksAddr socks.Addr) *SimpleTunnelHandshaker {
	return &SimpleTunnelHandshaker{
		remoteSocksAddr: remoteSocksAddr,
	}
}

func (h *SimpleTunnelHandshaker) String() string {
	return "simple tunnel"
}

func (h *SimpleTunnelHandshaker) Handshake(_ *net.TCPConn) (socks.Addr, error) {
	return h.remoteSocksAddr, nil
}

// SimpleSocks5Handshaker is a minimal implementation of SOCKS5 server.
// SOCKS5 spec: https://datatracker.ietf.org/doc/html/rfc1928
type SimpleSocks5Handshaker struct {
	enableTCP bool
	enableUDP bool
}

func NewSimpleSocks5Handshaker(enableTCP, enableUDP bool) *SimpleSocks5Handshaker {
	return &SimpleSocks5Handshaker{
		enableTCP: enableTCP,
		enableUDP: enableUDP,
	}
}

func (h *SimpleSocks5Handshaker) String() string {
	return "simple SOCKS5"
}

func (h *SimpleSocks5Handshaker) Handshake(conn *net.TCPConn) (socks.Addr, error) {
	buf := make([]byte, socks.MaxAddrLen)

	// Authenticate.
	// Read VER, NMETHODS.
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return nil, err
	}
	// Check VER.
	if buf[0] != 5 {
		return nil, fmt.Errorf("unsupported socks version %d", buf[0])
	}
	// Check NMETHODS.
	nmethods := buf[1]
	if nmethods < 1 {
		return nil, fmt.Errorf("NMETHODS is %d", nmethods)
	}
	// Read METHODS.
	if _, err := io.ReadFull(conn, buf[:nmethods]); err != nil {
		return nil, err
	}
	// Check METHODS.
	if bytes.IndexByte(buf[:nmethods], 0) == -1 {
		return nil, fmt.Errorf("no supported authentication method, only 0 (no authentication) is supported")
	}
	// Write method selection message (VER METHOD).
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return nil, err
	}

	// Read request.
	// Read VER CMD RSV.
	if _, err := io.ReadFull(conn, buf[:3]); err != nil {
		return nil, err
	}
	// Check VER.
	if buf[0] != 5 {
		return nil, fmt.Errorf("unsupported socks version %d", buf[0])
	}
	cmd := buf[1]
	// Read ATYP DST.ADDR DST.PORT.
	n, err := socks.ReadAddr(buf, conn)
	if err != nil {
		return nil, fmt.Errorf("failed to read socks address: %w", err)
	}
	addr := buf[:n]

	switch {
	case cmd == socks.CmdConnect && h.enableTCP:
		err = replyWithStatus(conn, socks.Succeeded)
	case cmd == socks.CmdUDPAssociate && h.enableUDP:
		bndAddr, err := socks.ParseAddr(conn.LocalAddr().String())
		if err != nil {
			replyWithStatus(conn, socks.ErrAddressNotSupported)
			return nil, fmt.Errorf("failed to parse conn.LocalAddr().String(): %w", err)
		}
		_, err = conn.Write(append([]byte{5, 0, 0}, bndAddr...))
		// Set addr to nil to indicate blocking.
		addr = nil
	default:
		err = replyWithStatus(conn, socks.ErrCommandNotSupported)
	}

	return addr, err
}

func replyWithStatus(conn *net.TCPConn, socks5err byte) error {
	_, err := conn.Write([]byte{5, socks5err, 0, 1, 0, 0, 0, 0, 0, 0})
	return err
}

type SimpleHttpConnectHandshaker struct{}

func (h *SimpleHttpConnectHandshaker) String() string {
	return "simple HTTP/1.1 CONNECT"
}

func (h *SimpleHttpConnectHandshaker) Handshake(conn *net.TCPConn) (socks.Addr, error) {
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return nil, err
	}

	if req.Method != http.MethodConnect {
		if err := send418(conn); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("unsupported HTTP method %s", req.Method)
	}

	socksAddr, err := socks.ParseAddr(req.Host)
	if err != nil {
		if err := send418(conn); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("bad Host header %s", req.Host)
	}

	if _, err := fmt.Fprint(conn, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return nil, err
	}
	return socksAddr, nil
}

func send418(w io.Writer) error {
	if _, err := fmt.Fprint(w, "HTTP/1.1 418 I'm a teapot\r\n\r\n"); err != nil {
		return err
	}
	return nil
}

// ShadowsocksNoneHandshaker implements the 'none' mode of Shadowsocks.
type ShadowsocksNoneHandshaker struct{}

func (h *ShadowsocksNoneHandshaker) String() string {
	return "Shadowsocks none"
}

func (h *ShadowsocksNoneHandshaker) Handshake(conn *net.TCPConn) (socks.Addr, error) {
	return socks.AddrFromReader(conn)
}

func NewTCPSimpleTunnelService(tunnelListenAddress string, tunnelRemoteSocksAddr socks.Addr, listenerTFO, dialerTFO bool, client Client) Service {
	return &TCPTunnel{
		listenAddress: tunnelListenAddress,
		listenerTFO:   listenerTFO,
		dialerTFO:     dialerTFO,
		client:        client,
		handshaker:    NewSimpleTunnelHandshaker(tunnelRemoteSocksAddr),
	}
}

func NewTCPSimpleSocks5Service(socks5ListenAddress string, enableTCP, enableUDP, listenerTFO, dialerTFO bool, client Client) Service {
	return &TCPTunnel{
		listenAddress: socks5ListenAddress,
		listenerTFO:   listenerTFO,
		dialerTFO:     dialerTFO,
		client:        client,
		handshaker:    NewSimpleSocks5Handshaker(enableTCP, enableUDP),
	}
}

func NewTCPSimpleHttpConnectService(httpListenAddress string, listenerTFO, dialerTFO bool, client Client) Service {
	return &TCPTunnel{
		listenAddress: httpListenAddress,
		listenerTFO:   listenerTFO,
		dialerTFO:     dialerTFO,
		client:        client,
		handshaker:    &SimpleHttpConnectHandshaker{},
	}
}

func NewTCPShadowsocksNoneService(ssNoneListenAddress string, listenerTFO, dialerTFO bool, client Client) Service {
	return &TCPTunnel{
		listenAddress: ssNoneListenAddress,
		listenerTFO:   listenerTFO,
		dialerTFO:     dialerTFO,
		client:        client,
		handshaker:    &ShadowsocksNoneHandshaker{},
	}
}
