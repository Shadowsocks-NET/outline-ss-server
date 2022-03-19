package client

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"time"

	onet "github.com/Shadowsocks-NET/outline-ss-server/net"
	"github.com/Shadowsocks-NET/outline-ss-server/service"
	"github.com/Shadowsocks-NET/outline-ss-server/socks"
	"github.com/database64128/tfo-go"
)

type Service interface {
	Name() string
	Start() error
	Stop() error
}

type TCPTunnel struct {
	tunnelListenAddress string
	tunnelRemoteAddress string

	listenerTFO bool
	dialerTFO   bool

	client   Client
	listener *net.TCPListener
}

func NewTCPTunnelService(tunnelListenAddress, tunnelRemoteAddress string, listenerTFO, dialerTFO bool, client Client) Service {
	return &TCPTunnel{
		tunnelListenAddress: tunnelListenAddress,
		tunnelRemoteAddress: tunnelRemoteAddress,
		listenerTFO:         listenerTFO,
		dialerTFO:           dialerTFO,
		client:              client,
	}
}

func (s *TCPTunnel) Name() string {
	return "TCP tunnel service"
}

func (s *TCPTunnel) Start() error {
	go s.listen()
	return nil
}

func (s *TCPTunnel) listen() {
	lc := tfo.ListenConfig{
		DisableTFO: !s.listenerTFO,
	}
	l, err := lc.Listen(context.Background(), "tcp", s.tunnelListenAddress)
	if err != nil {
		log.Print(err)
		return
	}
	defer l.Close()

	s.listener = l.(*net.TCPListener)

	for {
		clientconn, err := l.(*net.TCPListener).AcceptTCP()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Print(err)
			continue
		}

		go func() {
			proxyconn, err := s.client.DialTCP(nil, s.tunnelRemoteAddress, s.dialerTFO)
			if err != nil {
				log.Print(err)
			}
			defer proxyconn.Close()

			err = relay(clientconn, proxyconn)
			if err != nil {
				log.Print(err)
			}
		}()
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
		s.listener.Close()
	}
	return nil
}

type UDPTunnel struct {
	tunnelListenAddress string
	tunnelRemoteAddress string

	multiplexUDP bool
	natTimeout   time.Duration

	client Client
	conn   *net.UDPConn
}

func NewUDPTunnelService(tunnelListenAddress, tunnelRemoteAddress string, multiplexUDP bool, natTimeout time.Duration, client Client) Service {
	return &UDPTunnel{
		tunnelListenAddress: tunnelListenAddress,
		tunnelRemoteAddress: tunnelRemoteAddress,
		multiplexUDP:        multiplexUDP,
		natTimeout:          natTimeout,
		client:              client,
	}
}

func (s *UDPTunnel) Name() string {
	return "UDP tunnel service"
}

func (s *UDPTunnel) Start() error {
	go s.listen()
	return nil
}

func (s *UDPTunnel) listen() {
	laddr, err := net.ResolveUDPAddr("udp", s.tunnelListenAddress)
	if err != nil {
		log.Fatal(err)
	}

	conn, err := service.ListenUDP("udp", laddr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	s.conn = conn.(*net.UDPConn)

	nm := newNATmap(s.natTimeout)
	defer nm.Close()

	packetBuf := make([]byte, service.UDPPacketBufferSize)
	oobBuf := make([]byte, service.UDPOOBBufferSize)

	socksAddr, err := socks.ParseAddr(s.tunnelRemoteAddress)
	if err != nil {
		log.Fatal(err)
	}

	for {
		n, oobn, _, clientAddr, err := s.conn.ReadMsgUDP(packetBuf[ShadowsocksPacketConnFrontReserve:], oobBuf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Print(err)
			continue
		}

		oobCache := service.GetOobForCache(oobBuf[:oobn])
		proxyConn := nm.GetByClientAddress(clientAddr.String())
		if proxyConn == nil {
			spc, err := s.client.ListenUDP(nil)
			if err != nil {
				log.Print(err)
				continue
			}

			proxyConn = nm.Add(clientAddr, s.conn, oobCache, spc)
		} else {
			proxyConn.oobCache = oobCache
		}

		_, err = proxyConn.WriteToZeroCopy(packetBuf, ShadowsocksPacketConnFrontReserve, n, socksAddr)
		if err != nil {
			log.Print(err)
		}
	}
}

func (s *UDPTunnel) Stop() error {
	if s.conn != nil {
		s.conn.Close()
	}
	return nil
}
