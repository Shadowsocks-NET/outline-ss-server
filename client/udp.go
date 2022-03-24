package client

import (
	"errors"
	"fmt"
	"net"
	"time"

	onet "github.com/Shadowsocks-NET/outline-ss-server/net"
	"github.com/Shadowsocks-NET/outline-ss-server/service"
	ss "github.com/Shadowsocks-NET/outline-ss-server/shadowsocks"
	"github.com/Shadowsocks-NET/outline-ss-server/socks"
	"go.uber.org/zap"
)

type UDPTunnel struct {
	listenAddress string
	multiplexUDP  bool
	natTimeout    time.Duration

	client        Client
	conn          *net.UDPConn
	packetAdapter PacketAdapter
}

func (s *UDPTunnel) String() string {
	return fmt.Sprint("UDP ", s.packetAdapter.String(), " service")
}

func (s *UDPTunnel) Start() error {
	laddr, err := net.ResolveUDPAddr("udp", s.listenAddress)
	if err != nil {
		return err
	}

	conn, err, serr := onet.ListenUDP("udp", laddr)
	if err != nil {
		return err
	}
	if serr != nil {
		logger.Warn("Failed to set IP_PKTINFO, IPV6_RECVPKTINFO socket options",
			zap.Stringer("service", s),
			zap.String("listenAddress", s.listenAddress),
			zap.Error(serr),
		)
	}
	s.conn = conn.(*net.UDPConn)

	go func() {
		defer s.conn.Close()

		nm := newNATmap(s.natTimeout)
		defer nm.Close()

		packetBuf := make([]byte, service.UDPPacketBufferSize)
		oobBuf := make([]byte, service.UDPOOBBufferSize)

		for {
			n, oobn, _, clientAddr, err := s.conn.ReadMsgUDP(packetBuf[ShadowsocksPacketConnFrontReserve:], oobBuf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					break
				}
				logger.Warn("Failed to read from UDPConn",
					zap.Stringer("service", s),
					zap.String("listenAddress", s.listenAddress),
					zap.Error(err),
				)
				continue
			}

			payloadStart, payloadLength, detachedSocksAddr, err := s.packetAdapter.ParsePacket(packetBuf, ShadowsocksPacketConnFrontReserve, n)
			if err != nil {
				logger.Warn("Failed to parse client packet",
					zap.Stringer("service", s),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", clientAddr),
					zap.Error(err),
				)
				continue
			}

			oobCache, err := onet.GetOobForCache(oobBuf[:oobn])
			if err != nil {
				logger.Debug("Failed to process OOB",
					zap.Stringer("service", s),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", clientAddr),
					zap.Error(err),
				)
			}

			proxyConn := nm.GetByClientAddress(clientAddr.String())
			if proxyConn == nil {
				logger.Info("New UDP session",
					zap.Stringer("service", s),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", clientAddr),
				)

				spc, err := s.client.ListenUDP(nil)
				if err != nil {
					logger.Warn("Failed to open UDP proxy session",
						zap.Stringer("service", s),
						zap.String("listenAddress", s.listenAddress),
						zap.Stringer("clientAddress", clientAddr),
						zap.Error(err),
					)
					continue
				}

				proxyConn = nm.Add(clientAddr, s.conn, oobCache, spc, s.packetAdapter)
			} else {
				logger.Debug("found UDP session in NAT table",
					zap.Stringer("service", s),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", clientAddr),
					zap.Stringer("proxyConnLocalAddress", proxyConn.LocalAddr()),
					zap.Stringer("proxyConnRemoteAddress", proxyConn.RemoteAddr()),
					zap.Duration("defaultTimeout", proxyConn.defaultTimeout),
					zap.Time("readDeadline", proxyConn.readDeadline),
				)

				proxyConn.oobCache = oobCache
			}

			_, err = proxyConn.WriteToZeroCopy(packetBuf, payloadStart, payloadLength, detachedSocksAddr)
			if err != nil {
				logger.Warn("Failed to relay packet",
					zap.Stringer("service", s),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", clientAddr),
					zap.Stringer("proxyConnLocalAddress", proxyConn.LocalAddr()),
					zap.Stringer("proxyConnRemoteAddress", proxyConn.RemoteAddr()),
					zap.Error(err),
				)
			}
		}
	}()
	logger.Info("Started listener", zap.Stringer("service", s), zap.String("listenAddress", s.listenAddress))
	return nil
}

func (s *UDPTunnel) Stop() error {
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

// PacketAdapter translates packets between a local interface and the proxy interface.
type PacketAdapter interface {
	String() string

	// ParsePacket parses an incoming packet and returns payload start index, payload length,
	// a detached socks address (if applicable), or an error.
	//
	// The detached socks address is only returned when the payload does not start with a socks address.
	ParsePacket(pkt []byte, start, length int) (payloadStart, payloadLength int, detachedSocksAddr []byte, err error)

	// EncapsulatePacket encapsulates the decrypted packet from proxy
	// into a new form so it's ready to be sent on the local interface.
	// The encapsulation must not extend beyond the range of the full decrypted packet.
	EncapsulatePacket(decryptedFullPacket []byte, socksAddrStart, payloadStart, payloadLength int) (pkt []byte, err error)
}

// SimpleTunnelPacketAdapter simply relays packets between clientConn and proxyConn.
type SimpleTunnelPacketAdapter struct {
	remoteSocksAddr socks.Addr
}

func NewSimpleTunnelPacketAdapter(remoteSocksAddr socks.Addr) *SimpleTunnelPacketAdapter {
	return &SimpleTunnelPacketAdapter{
		remoteSocksAddr: remoteSocksAddr,
	}
}

func (p *SimpleTunnelPacketAdapter) String() string {
	return "simple tunnel"
}

func (p *SimpleTunnelPacketAdapter) ParsePacket(_ []byte, start, length int) (payloadStart, payloadLength int, detachedSocksAddr []byte, err error) {
	return start, length, p.remoteSocksAddr, nil
}

func (p *SimpleTunnelPacketAdapter) EncapsulatePacket(decryptedFullPacket []byte, _, payloadStart, payloadLength int) (pkt []byte, err error) {
	return decryptedFullPacket[payloadStart : payloadStart+payloadLength], nil
}

// SimpleSocks5PacketAdapter is a minimal implementation of SOCKS5 UDP server.
// It unconditionally accepts SOCKS5 UDP packets, no matter a corresponding UDP association exists or not.
type SimpleSocks5PacketAdapter struct{}

func (p *SimpleSocks5PacketAdapter) String() string {
	return "simple SOCKS5"
}

func (p *SimpleSocks5PacketAdapter) ParsePacket(pkt []byte, start, length int) (payloadStart, payloadLength int, detachedSocksAddr []byte, err error) {
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

func (p *SimpleSocks5PacketAdapter) EncapsulatePacket(decryptedFullPacket []byte, socksAddrStart, payloadStart, payloadLength int) (pkt []byte, err error) {
	start := socksAddrStart - 3
	// RSV
	decryptedFullPacket[start] = 0
	decryptedFullPacket[start+1] = 0
	// FRAG
	decryptedFullPacket[start+2] = 0
	return decryptedFullPacket[start : payloadStart+payloadLength], nil
}

// ShadowsocksNonePacketAdapter implements the 'none' mode of Shadowsocks.
type ShadowsocksNonePacketAdapter struct{}

func (p *ShadowsocksNonePacketAdapter) String() string {
	return "Shadowsocks none"
}

func (p *ShadowsocksNonePacketAdapter) ParsePacket(pkt []byte, start, length int) (payloadStart, payloadLength int, detachedSocksAddr []byte, err error) {
	// Validate socks address.
	_, err = socks.SplitAddr(pkt[start:])
	if err != nil {
		return 0, 0, nil, fmt.Errorf("socks address validation failed: %w", err)
	}

	payloadStart = start
	payloadLength = length
	return
}

func (p *ShadowsocksNonePacketAdapter) EncapsulatePacket(decryptedFullPacket []byte, socksAddrStart, payloadStart, payloadLength int) (pkt []byte, err error) {
	return decryptedFullPacket[socksAddrStart : payloadStart+payloadLength], nil
}

func NewUDPSimpleTunnelService(tunnelListenAddress string, tunnelRemoteSocksAddr socks.Addr, multiplexUDP bool, natTimeout time.Duration, client Client) Service {
	return &UDPTunnel{
		listenAddress: tunnelListenAddress,
		multiplexUDP:  multiplexUDP,
		natTimeout:    natTimeout,
		client:        client,
		packetAdapter: NewSimpleTunnelPacketAdapter(tunnelRemoteSocksAddr),
	}
}

func NewUDPSimpleSocks5Service(socks5ListenAddress string, multiplexUDP bool, natTimeout time.Duration, client Client) Service {
	return &UDPTunnel{
		listenAddress: socks5ListenAddress,
		multiplexUDP:  multiplexUDP,
		natTimeout:    natTimeout,
		client:        client,
		packetAdapter: &SimpleSocks5PacketAdapter{},
	}
}

func NewUDPShadowsocksNoneService(ssNoneListenAddress string, multiplexUDP bool, natTimeout time.Duration, client Client) Service {
	return &UDPTunnel{
		listenAddress: ssNoneListenAddress,
		multiplexUDP:  multiplexUDP,
		natTimeout:    natTimeout,
		client:        client,
		packetAdapter: &ShadowsocksNonePacketAdapter{},
	}
}
