package client

import (
	"context"
	"errors"
	"io"
	"log"
	"net"

	onet "github.com/Shadowsocks-NET/outline-ss-server/net"
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

	client Client
	conn   *net.UDPConn
}

func NewUDPTunnelService(tunnelListenAddress, tunnelRemoteAddress string, client Client) Service {
	return &UDPTunnel{
		tunnelListenAddress: tunnelListenAddress,
		tunnelRemoteAddress: tunnelRemoteAddress,
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

	s.conn, err = net.ListenUDP("udp", laddr)
	if err != nil {
		log.Fatal(err)
	}
	defer s.conn.Close()

	// proxyconn, err := s.client.ListenUDP(nil)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// defer proxyconn.Close()

	// for {
	// 	lazySlice := UDPPool.LazySlice()
	// 	b := lazySlice.Acquire()
	// 	defer lazySlice.Release()

	// 	n, oobn, flags, raddr, err := s.conn.(*net.UDPConn).ReadMsgUDP(b, oob)
	// }
}

func (s *UDPTunnel) Stop() error {
	if s.conn != nil {
		s.conn.Close()
	}
	return nil
}
