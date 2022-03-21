package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Shadowsocks-NET/outline-ss-server/client"
	"github.com/Shadowsocks-NET/outline-ss-server/service"
	"github.com/Shadowsocks-NET/outline-ss-server/socks"
)

const (
	// A UDP NAT timeout of at least 5 minutes is recommended in RFC 4787 Section 4.3.
	defaultNatTimeout time.Duration = 5 * time.Minute
)

func main() {
	var address string
	var method string
	var psk string

	var tunnelListenAddress string
	var tunnelRemoteAddress string
	var tunnelTCP bool
	var tunnelUDP bool

	var socks5ListenAddress string
	var socks5EnableTCP bool
	var socks5EnableUDP bool

	var ssNoneListenAddress string
	var ssNoneEnableTCP bool
	var ssNoneEnableUDP bool

	var TCPFastOpen bool
	var listenerTFO bool
	var dialerTFO bool

	var multiplexUDP bool
	var natTimeout time.Duration

	flag.StringVar(&address, "address", "", "shadowsocks server address host:port")
	flag.StringVar(&method, "method", "chacha20-ietf-poly1305", "shadowsocks server method")
	flag.StringVar(&psk, "psk", "", "shadowsocks server pre-shared key")

	flag.StringVar(&tunnelListenAddress, "tunnelListenAddress", "", "shadowsocks tunnel local listen address")
	flag.StringVar(&tunnelRemoteAddress, "tunnelRemoteAddress", "", "shadowsocks tunnel remote address")
	flag.BoolVar(&tunnelTCP, "tunnelTCP", false, "Whether to tunnel TCP traffic")
	flag.BoolVar(&tunnelUDP, "tunnelUDP", false, "Whether to tunnel UDP traffic")

	flag.StringVar(&socks5ListenAddress, "socks5ListenAddress", "", "SOCKS5 proxy listen address")
	flag.BoolVar(&socks5EnableTCP, "socks5EnableTCP", false, "Enables SOCKS5 TCP proxy")
	flag.BoolVar(&socks5EnableUDP, "socks5EnableUDP", false, "Enables SOCKS5 UDP proxy")

	flag.StringVar(&ssNoneListenAddress, "ssNoneListenAddress", "", "Shadowsocks None proxy listen address")
	flag.BoolVar(&ssNoneEnableTCP, "ssNoneEnableTCP", false, "Enables Shadowsocks None TCP proxy")
	flag.BoolVar(&ssNoneEnableUDP, "ssNoneEnableUDP", false, "Enables Shadowsocks None UDP proxy")

	flag.BoolVar(&TCPFastOpen, "tfo", false, "Enables TFO for both TCP listener and dialer")
	flag.BoolVar(&listenerTFO, "tfo_listener", false, "Enables TFO for TCP listener")
	flag.BoolVar(&dialerTFO, "tfo_dialer", false, "Enables TFO for TCP listener")

	flag.BoolVar(&multiplexUDP, "muxUDP", false, "Whether to multiplex all UDP sessions into one UDPConn")
	flag.DurationVar(&natTimeout, "natTimeout", defaultNatTimeout, "UDP NAT timeout")

	flag.Parse()

	if TCPFastOpen {
		listenerTFO = true
		dialerTFO = true
	}

	saltPool := service.NewSaltPool()

	c, err := client.NewClient(address, method, psk, saltPool)
	if err != nil {
		log.Fatal(err)
	}

	var services []client.Service

	var tunnelRemoteSocksAddr socks.Addr
	if tunnelRemoteAddress != "" {
		tunnelRemoteSocksAddr, err = socks.ParseAddr(tunnelRemoteAddress)
		if err != nil {
			log.Fatal(err)
		}
	}

	if tunnelTCP {
		s := client.NewTCPSimpleTunnelService(tunnelListenAddress, tunnelRemoteSocksAddr, listenerTFO, dialerTFO, c)
		s.Start()
		services = append(services, s)
	}

	if tunnelUDP {
		s := client.NewUDPSimpleTunnelService(tunnelListenAddress, tunnelRemoteSocksAddr, multiplexUDP, natTimeout, c)
		s.Start()
		services = append(services, s)
	}

	if socks5EnableTCP {
		s := client.NewTCPSimpleSocks5Service(socks5ListenAddress, socks5EnableTCP, socks5EnableUDP, listenerTFO, dialerTFO, c)
		s.Start()
		services = append(services, s)
	}

	if socks5EnableUDP {
		s := client.NewUDPSimpleSocks5Service(socks5ListenAddress, multiplexUDP, natTimeout, c)
		s.Start()
		services = append(services, s)
	}

	if ssNoneEnableTCP {
		s := client.NewTCPShadowsocksNoneService(ssNoneListenAddress, listenerTFO, dialerTFO, c)
		s.Start()
		services = append(services, s)
	}

	if ssNoneEnableUDP {
		s := client.NewUDPShadowsocksNoneService(ssNoneListenAddress, multiplexUDP, natTimeout, c)
		s.Start()
		services = append(services, s)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh

	log.Printf("Received %s, stopping...", sig.String())

	for _, s := range services {
		s.Stop()
		log.Printf("Stopped %s", s.Name())
	}
}
