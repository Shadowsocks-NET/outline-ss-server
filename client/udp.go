package client

import (
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/Shadowsocks-NET/outline-ss-server/service"
	ss "github.com/Shadowsocks-NET/outline-ss-server/shadowsocks"
	"github.com/Shadowsocks-NET/outline-ss-server/socks"
)

type UDPTunnel struct {
	listenAddress string
	multiplexUDP  bool
	natTimeout    time.Duration

	client       Client
	conn         *net.UDPConn
	packetParser PacketParser
}

func (s *UDPTunnel) Name() string {
	return fmt.Sprint("UDP ", s.packetParser.Name(), " service")
}

func (s *UDPTunnel) Start() error {
	go s.listen()
	log.Printf("Started %s listening on %s", s.Name(), s.listenAddress)
	return nil
}

func (s *UDPTunnel) listen() {
	laddr, err := net.ResolveUDPAddr("udp", s.listenAddress)
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

	for {
		n, oobn, _, clientAddr, err := s.conn.ReadMsgUDP(packetBuf[ShadowsocksPacketConnFrontReserve:], oobBuf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Print(err)
			continue
		}

		payloadStart, payloadLength, detachedSocksAddr, err := s.packetParser.ParsePacket(packetBuf, ShadowsocksPacketConnFrontReserve, n)
		if err != nil {
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

		_, err = proxyConn.WriteToZeroCopy(packetBuf, payloadStart, payloadLength, detachedSocksAddr)
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

// PacketParser parses an incoming packet and returns payload start index, payload length,
// a detached socks address (if applicable), or an error.
//
// The detached socks address is only returned when the payload does not start with a socks address.
type PacketParser interface {
	Name() string
	ParsePacket(pkt []byte, start, length int) (payloadStart, payloadLength int, detachedSocksAddr []byte, err error)
}

// SimpleTunnelPacketParser simply relays packets between clientConn and proxyConn.
type SimpleTunnelPacketParser struct {
	remoteSocksAddr socks.Addr
}

func NewSimpleTunnelPacketParser(remoteSocksAddr socks.Addr) *SimpleTunnelPacketParser {
	return &SimpleTunnelPacketParser{
		remoteSocksAddr: remoteSocksAddr,
	}
}

func (p *SimpleTunnelPacketParser) Name() string {
	return "simple tunnel"
}

func (p *SimpleTunnelPacketParser) ParsePacket(_ []byte, start, length int) (payloadStart, payloadLength int, detachedSocksAddr []byte, err error) {
	return start, length, p.remoteSocksAddr, nil
}

// SimpleSocks5PacketParser is a minimal implementation of SOCKS5 UDP server.
// It unconditionally accepts SOCKS5 UDP packets, no matter a corresponding UDP association exists or not.
type SimpleSocks5PacketParser struct{}

func (p *SimpleSocks5PacketParser) Name() string {
	return "simple SOCKS5"
}

func (p *SimpleSocks5PacketParser) ParsePacket(pkt []byte, start, length int) (payloadStart, payloadLength int, detachedSocksAddr []byte, err error) {
	payloadStart = start + 3
	if len(pkt) <= payloadStart {
		return 0, 0, nil, ss.ErrShortPacket
	}

	// Validate RSV FRAG.
	if pkt[start] != 0 || pkt[start+1] != 0 || pkt[start+2] != 0 {
		return 0, 0, nil, fmt.Errorf("unexpected RSV FRAG: %v, RSV must be 0, fragmentation is not supported", pkt[start:start+3])
	}

	// Validate socks address.
	_, err = socks.SplitAddr(pkt[payloadStart:])
	if err != nil {
		return 0, 0, nil, fmt.Errorf("socks address validation failed: %w", err)
	}

	payloadLength = length
	return
}

// ShadowsocksNonePacketParser implements the 'none' mode of Shadowsocks.
type ShadowsocksNonePacketParser struct{}

func (p *ShadowsocksNonePacketParser) Name() string {
	return "Shadowsocks none"
}

func (p *ShadowsocksNonePacketParser) ParsePacket(pkt []byte, start, length int) (payloadStart, payloadLength int, detachedSocksAddr []byte, err error) {
	// Validate socks address.
	_, err = socks.SplitAddr(pkt[start:])
	if err != nil {
		return 0, 0, nil, fmt.Errorf("socks address validation failed: %w", err)
	}

	payloadStart = start
	payloadLength = length
	return
}

func NewUDPSimpleTunnelService(tunnelListenAddress string, tunnelRemoteSocksAddr socks.Addr, multiplexUDP bool, natTimeout time.Duration, client Client) Service {
	return &UDPTunnel{
		listenAddress: tunnelListenAddress,
		multiplexUDP:  multiplexUDP,
		natTimeout:    natTimeout,
		client:        client,
		packetParser:  NewSimpleTunnelPacketParser(tunnelRemoteSocksAddr),
	}
}

func NewUDPSimpleSocks5Service(socks5ListenAddress string, multiplexUDP bool, natTimeout time.Duration, client Client) Service {
	return &UDPTunnel{
		listenAddress: socks5ListenAddress,
		multiplexUDP:  multiplexUDP,
		natTimeout:    natTimeout,
		client:        client,
		packetParser:  &SimpleSocks5PacketParser{},
	}
}

func NewUDPShadowsocksNoneService(ssNoneListenAddress string, multiplexUDP bool, natTimeout time.Duration, client Client) Service {
	return &UDPTunnel{
		listenAddress: ssNoneListenAddress,
		multiplexUDP:  multiplexUDP,
		natTimeout:    natTimeout,
		client:        client,
		packetParser:  &ShadowsocksNonePacketParser{},
	}
}
