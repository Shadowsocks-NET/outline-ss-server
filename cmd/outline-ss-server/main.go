package main

import (
	"container/list"
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Shadowsocks-NET/outline-ss-server/logging"
	onet "github.com/Shadowsocks-NET/outline-ss-server/net"
	"github.com/Shadowsocks-NET/outline-ss-server/service"
	"github.com/Shadowsocks-NET/outline-ss-server/service/metrics"
	ss "github.com/Shadowsocks-NET/outline-ss-server/shadowsocks"
	"github.com/database64128/tfo-go"
	"github.com/oschwald/geoip2-golang"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

var (
	version = "dev"
	logger  *zap.Logger
)

const (
	// 59 seconds is most common timeout for servers that do not respond to invalid requests
	//TODO: Consider removing this since we now use a random timeout.
	tcpReadTimeout time.Duration = 59 * time.Second

	// A UDP NAT timeout of at least 5 minutes is recommended in RFC 4787 Section 4.3.
	defaultNatTimeout time.Duration = 5 * time.Minute
)

type ssPort struct {
	tcpService service.TCPService
	udpService service.UDPService
	cipherList service.CipherList
}

type SSServer struct {
	natTimeout      time.Duration
	m               metrics.ShadowsocksMetrics
	replayCache     service.ReplayCache
	saltPool        *service.SaltPool
	ports           map[int]*ssPort
	blockPrivateNet bool
	listenerTFO     bool
	dialerTFO       bool
	udpPreferIPv6   bool
}

func (s *SSServer) startPort(portNum int) (err error) {
	lc := tfo.ListenConfig{
		DisableTFO: !s.listenerTFO,
	}
	listener, err := lc.Listen(context.Background(), "tcp", fmt.Sprintf(":%d", portNum))
	if err != nil {
		return fmt.Errorf("failed to start TCP on port %v: %v", portNum, err)
	}
	udpPacketConn, err, serr := onet.ListenUDP("udp", fmt.Sprintf(":%d", portNum), 0)
	if err != nil {
		return fmt.Errorf("failed to start UDP on port %v: %v", portNum, err)
	}
	if serr != nil {
		logger.Warn("Failed to set IP_PKTINFO, IPV6_RECVPKTINFO socket options",
			zap.Error(serr),
		)
	}
	logger.Info("Started TCP and UDP listeners", zap.Int("port", portNum))
	port := &ssPort{cipherList: service.NewCipherList()}
	// TODO: Register initial data metrics at zero.
	port.tcpService = service.NewTCPService(port.cipherList, &s.replayCache, s.saltPool, s.m, tcpReadTimeout, s.dialerTFO)
	port.udpService = service.NewUDPService(s.natTimeout, port.cipherList, s.m, s.udpPreferIPv6)
	if s.blockPrivateNet {
		port.tcpService.SetTargetIPValidator(onet.RequirePublicIP)
		port.udpService.SetTargetIPValidator(onet.RequirePublicIP)
	}
	s.ports[portNum] = port
	go port.tcpService.Serve(listener.(*net.TCPListener))
	go port.udpService.Serve(udpPacketConn)
	return nil
}

func (s *SSServer) removePort(portNum int) error {
	port, ok := s.ports[portNum]
	if !ok {
		return fmt.Errorf("port %v doesn't exist", portNum)
	}
	tcpErr := port.tcpService.Stop()
	udpErr := port.udpService.Stop()
	delete(s.ports, portNum)
	if tcpErr != nil {
		return fmt.Errorf("failed to close listener on %v: %v", portNum, tcpErr)
	}
	if udpErr != nil {
		return fmt.Errorf("failed to close packetConn on %v: %v", portNum, udpErr)
	}
	logger.Info("Stopped TCP and UDP listeners", zap.Int("port", portNum))
	return nil
}

func (s *SSServer) loadConfig(filename string) error {
	config, err := readConfig(filename)
	if err != nil {
		return fmt.Errorf("failed to read config file %v: %v", filename, err)
	}

	portChanges := make(map[int]int)
	portCiphers := make(map[int]*list.List) // Values are *List of *CipherEntry.
	for _, keyConfig := range config.Keys {
		portChanges[keyConfig.Port] = 1
		cipherList, ok := portCiphers[keyConfig.Port]
		if !ok {
			cipherList = list.New()
			portCiphers[keyConfig.Port] = cipherList
		}
		cipher, err := ss.NewCipher(keyConfig.Cipher, keyConfig.Secret)
		if err != nil {
			return fmt.Errorf("failed to create cipher for key %v: %v", keyConfig.ID, err)
		}
		entry := service.MakeCipherEntry(keyConfig.ID, cipher, keyConfig.Secret)
		cipherList.PushBack(&entry)
	}
	for port := range s.ports {
		portChanges[port] = portChanges[port] - 1
	}
	for portNum, count := range portChanges {
		if count == -1 {
			if err := s.removePort(portNum); err != nil {
				return fmt.Errorf("failed to remove port %v: %v", portNum, err)
			}
		} else if count == +1 {
			if err := s.startPort(portNum); err != nil {
				return fmt.Errorf("failed to start port %v: %v", portNum, err)
			}
		}
	}
	for portNum, cipherList := range portCiphers {
		s.ports[portNum].cipherList.Update(cipherList)
	}
	logger.Info("Loaded access keys", zap.Int("keys", len(config.Keys)))
	s.m.SetNumAccessKeys(len(config.Keys), len(portCiphers))
	return nil
}

// Stop serving on all ports.
func (s *SSServer) Stop() error {
	for portNum := range s.ports {
		if err := s.removePort(portNum); err != nil {
			return err
		}
	}
	return nil
}

// RunSSServer starts a shadowsocks server running, and returns the server or an error.
func RunSSServer(filename string, natTimeout time.Duration, sm metrics.ShadowsocksMetrics, replayHistory int, blockPrivateNet, listenerTFO, dialerTFO, udpPreferIPv6 bool) (*SSServer, error) {
	server := &SSServer{
		natTimeout:      natTimeout,
		m:               sm,
		replayCache:     service.NewReplayCache(replayHistory),
		saltPool:        service.NewSaltPool(),
		ports:           make(map[int]*ssPort),
		blockPrivateNet: blockPrivateNet,
		listenerTFO:     listenerTFO,
		dialerTFO:       dialerTFO,
		udpPreferIPv6:   udpPreferIPv6,
	}
	err := server.loadConfig(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to load config file %v: %v", filename, err)
	}
	sigHup := make(chan os.Signal, 1)
	signal.Notify(sigHup, syscall.SIGHUP)
	go func() {
		for range sigHup {
			logger.Info("Updating config")
			if err := server.loadConfig(filename); err != nil {
				logger.Error("Failed to reload config", zap.Error(err))
			}
		}
	}()
	return server, nil
}

type Config struct {
	Keys []struct {
		ID     string
		Port   int
		Cipher string
		Secret string
	}
}

func readConfig(filename string) (*Config, error) {
	config := Config{}
	configData, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(configData, &config)
	return &config, err
}

func main() {
	var (
		configFile      string
		metricsAddr     string
		ipCountryDbPath string
		natTimeout      time.Duration
		replayHistory   int
		blockPrivateNet bool
		tfo             bool
		listenerTFO     bool
		dialerTFO       bool
		udpPreferIPv6   bool
		ver             bool

		suppressTimestamps bool
		logLevel           string

		err error
	)

	flag.StringVar(&configFile, "config", "", "Configuration filename")
	flag.StringVar(&metricsAddr, "metrics", "", "Address for the Prometheus metrics")
	flag.StringVar(&ipCountryDbPath, "ip_country_db", "", "Path to the ip-to-country mmdb file")
	flag.DurationVar(&natTimeout, "udptimeout", defaultNatTimeout, "UDP tunnel timeout")
	flag.IntVar(&replayHistory, "replay_history", 0, "Replay buffer size (# of handshakes)")
	flag.BoolVar(&blockPrivateNet, "block_private_net", false, "Block access to private IP addresses")
	flag.BoolVar(&ver, "version", false, "The version of the server")

	flag.BoolVar(&tfo, "tfo", false, "Enables TFO for both TCP listener and dialer")
	flag.BoolVar(&listenerTFO, "tfoListener", false, "Enables TFO for TCP listener")
	flag.BoolVar(&dialerTFO, "tfoDialer", false, "Enables TFO for TCP dialer")

	flag.BoolVar(&udpPreferIPv6, "udpPreferIPv6", false, "Prefer IPv6 addresses when resolving domain names for UDP targets")

	flag.BoolVar(&suppressTimestamps, "suppressTimestamps", false, "Omit timestamps in logs")
	flag.StringVar(&logLevel, "logLevel", "info", "Set custom log level. Available levels: debug, info, warn, error, dpanic, panic, fatal")

	flag.Parse()

	if ver {
		fmt.Println(version)
		return
	}

	if configFile == "" {
		flag.Usage()
		return
	}

	if suppressTimestamps {
		log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))
	}

	logger, err = logging.NewProductionConsole(suppressTimestamps, logLevel)
	if err != nil {
		log.Fatal(err)
	}
	defer logger.Sync()
	service.SetLogger(logger)

	if metricsAddr != "" {
		http.Handle("/metrics", promhttp.Handler())
		go func() {
			err := http.ListenAndServe(metricsAddr, nil)
			if err != nil {
				logger.Fatal("Failed to start metrics HTTP server", zap.Error(err))
			}
		}()
		logger.Info(fmt.Sprintf("Started metrics http server at http://%s/metrics", metricsAddr))
	}

	var ipCountryDB *geoip2.Reader
	if ipCountryDbPath != "" {
		ipCountryDB, err = geoip2.Open(ipCountryDbPath)
		if err != nil {
			logger.Fatal("Failed to open GeoIP database",
				zap.String("path", ipCountryDbPath),
				zap.Error(err),
			)
		}
		logger.Info("Loaded GeoIP database from file", zap.String("path", ipCountryDbPath))
		defer ipCountryDB.Close()
	}
	m := metrics.NewPrometheusShadowsocksMetrics(ipCountryDB, prometheus.DefaultRegisterer)
	m.SetBuildInfo(version)

	if tfo {
		listenerTFO = true
		dialerTFO = true
	}

	s, err := RunSSServer(configFile, natTimeout, m, replayHistory, blockPrivateNet, listenerTFO, dialerTFO, udpPreferIPv6)
	if err != nil {
		logger.Fatal("Failed to start Shadowsocks server", zap.Error(err))
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh

	logger.Info("Received signal, stopping...", zap.Stringer("signal", sig))

	s.Stop()
}
