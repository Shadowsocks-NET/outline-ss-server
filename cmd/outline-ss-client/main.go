package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Shadowsocks-NET/outline-ss-server/client"
	"github.com/Shadowsocks-NET/outline-ss-server/logging"
	"github.com/Shadowsocks-NET/outline-ss-server/service"
	"github.com/Shadowsocks-NET/outline-ss-server/socks"
	"go.uber.org/zap"
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

	var httpListenAddress string
	var httpEnable bool

	var TCPFastOpen bool
	var listenerTFO bool
	var dialerTFO bool

	var natTimeout time.Duration

	var suppressTimestamps bool
	var logLevel string

	flag.StringVar(&address, "address", "", "shadowsocks server address host:port")
	flag.StringVar(&method, "method", "2022-blake3-aes-256-gcm", "shadowsocks server method")
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

	flag.StringVar(&httpListenAddress, "httpListenAddress", "", "HTTP/1.1 CONNECT proxy listen address")
	flag.BoolVar(&httpEnable, "httpEnable", false, "Enables HTTP/1.1 CONNECT proxy")

	flag.BoolVar(&TCPFastOpen, "tfo", false, "Enables TFO for both TCP listener and dialer")
	flag.BoolVar(&listenerTFO, "tfoListener", false, "Enables TFO for TCP listener")
	flag.BoolVar(&dialerTFO, "tfoDialer", false, "Enables TFO for TCP dialer")

	flag.DurationVar(&natTimeout, "natTimeout", defaultNatTimeout, "UDP NAT timeout")

	flag.BoolVar(&suppressTimestamps, "suppressTimestamps", false, "Omit timestamps in logs")
	flag.StringVar(&logLevel, "logLevel", "info", "Set custom log level. Available levels: debug, info, warn, error, dpanic, panic, fatal")

	flag.Parse()

	if TCPFastOpen {
		listenerTFO = true
		dialerTFO = true
	}

	if suppressTimestamps {
		log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))
	}

	logger, err := logging.NewProductionConsole(suppressTimestamps, logLevel)
	if err != nil {
		log.Fatal(err)
	}
	defer logger.Sync()
	client.SetLogger(logger)

	saltPool := service.NewSaltPool()

	c, err := client.NewClient(address, method, psk, saltPool)
	if err != nil {
		logger.Fatal("Failed to create Shadowsocks client", zap.Error(err))
	}

	var services []client.Service

	var tunnelRemoteSocksAddr socks.Addr
	if tunnelRemoteAddress != "" {
		tunnelRemoteSocksAddr, err = socks.ParseAddr(tunnelRemoteAddress)
		if err != nil {
			logger.Fatal("Failed to parse tunnel remote address",
				zap.String("tunnelRemoteAddress", tunnelRemoteAddress),
				zap.Error(err),
			)
		}
	}

	if tunnelTCP {
		s := client.NewTCPSimpleTunnelService(tunnelListenAddress, tunnelRemoteSocksAddr, listenerTFO, dialerTFO, c)
		err = s.Start()
		if err != nil {
			logger.Fatal("Failed to start service",
				zap.Stringer("service", s),
				zap.Error(err),
			)
		}
		services = append(services, s)
	}

	if tunnelUDP {
		s := client.NewUDPSimpleTunnelService(tunnelListenAddress, tunnelRemoteSocksAddr, natTimeout, c)
		err = s.Start()
		if err != nil {
			logger.Fatal("Failed to start service",
				zap.Stringer("service", s),
				zap.Error(err),
			)
		}
		services = append(services, s)
	}

	if socks5EnableTCP {
		s := client.NewTCPSimpleSocks5Service(socks5ListenAddress, socks5EnableTCP, socks5EnableUDP, listenerTFO, dialerTFO, c)
		err = s.Start()
		if err != nil {
			logger.Fatal("Failed to start service",
				zap.Stringer("service", s),
				zap.Error(err),
			)
		}
		services = append(services, s)
	}

	if socks5EnableUDP {
		s := client.NewUDPSimpleSocks5Service(socks5ListenAddress, natTimeout, c)
		err = s.Start()
		if err != nil {
			logger.Fatal("Failed to start service",
				zap.Stringer("service", s),
				zap.Error(err),
			)
		}
		services = append(services, s)
	}

	if httpEnable {
		s := client.NewTCPSimpleHttpConnectService(httpListenAddress, listenerTFO, dialerTFO, c)
		err = s.Start()
		if err != nil {
			logger.Fatal("Failed to start service",
				zap.Stringer("service", s),
				zap.Error(err),
			)
		}
		services = append(services, s)
	}

	if ssNoneEnableTCP {
		s := client.NewTCPShadowsocksNoneService(ssNoneListenAddress, listenerTFO, dialerTFO, c)
		err = s.Start()
		if err != nil {
			logger.Fatal("Failed to start service",
				zap.Stringer("service", s),
				zap.Error(err),
			)
		}
		services = append(services, s)
	}

	if ssNoneEnableUDP {
		s := client.NewUDPShadowsocksNoneService(ssNoneListenAddress, natTimeout, c)
		err = s.Start()
		if err != nil {
			logger.Fatal("Failed to start service",
				zap.Stringer("service", s),
				zap.Error(err),
			)
		}
		services = append(services, s)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh

	logger.Info("Received signal, stopping...", zap.Stringer("signal", sig))

	for _, s := range services {
		s.Stop()
		logger.Info("Stopped service", zap.Stringer("service", s))
	}
}
