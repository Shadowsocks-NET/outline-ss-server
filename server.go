// Copyright 2018 Jigsaw Operations LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Jigsaw-Code/outline-ss-server/metrics"
	"github.com/Jigsaw-Code/outline-ss-server/shadowsocks"
	"github.com/op/go-logging"
	"github.com/oschwald/geoip2-golang"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/shadowsocks/go-shadowsocks2/core"
	"github.com/shadowsocks/go-shadowsocks2/shadowaead"
	"golang.org/x/crypto/ssh/terminal"
	"gopkg.in/yaml.v2"
)

var logger *logging.Logger

const tcpReadTimeout time.Duration = 59 * time.Second

func init() {
	var prefix = "%{level:.1s}%{time:2006-01-02T15:04:05.000Z07:00} %{pid} %{shortfile}]"
	if terminal.IsTerminal(int(os.Stderr.Fd())) {
		// Add color only if the output is the terminal
		prefix = strings.Join([]string{"%{color}", prefix, "%{color:reset}"}, "")
	}
	logging.SetFormatter(logging.MustStringFormatter(strings.Join([]string{prefix, " %{message}"}, "")))
	logging.SetBackend(logging.NewLogBackend(os.Stderr, "", 0))
	logger = logging.MustGetLogger("")
}

type SSPort struct {
	tcpService shadowsocks.TCPService
	udpService shadowsocks.UDPService
	cipherList shadowsocks.CipherList
}

type SSServer struct {
	natTimeout time.Duration
	m          metrics.ShadowsocksMetrics
	ports      map[int]*SSPort
}

func (s *SSServer) startPort(portNum int) error {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{Port: portNum})
	if err != nil {
		return fmt.Errorf("Failed to start TCP on port %v: %v", portNum, err)
	}
	packetConn, err := net.ListenUDP("udp", &net.UDPAddr{Port: portNum})
	if err != nil {
		return fmt.Errorf("Failed to start UDP on port %v: %v", portNum, err)
	}
	logger.Infof("Listening TCP and UDP on port %v", portNum)
	port := &SSPort{cipherList: shadowsocks.NewCipherList()}
	// TODO: Register initial data metrics at zero.
	port.tcpService = shadowsocks.NewTCPService(listener, &port.cipherList, s.m, tcpReadTimeout)
	port.udpService = shadowsocks.NewUDPService(packetConn, s.natTimeout, &port.cipherList, s.m)
	s.ports[portNum] = port
	go port.udpService.Start()
	go port.tcpService.Start()
	return nil
}

func (s *SSServer) removePort(portNum int) error {
	port, ok := s.ports[portNum]
	if !ok {
		return fmt.Errorf("Port %v doesn't exist", portNum)
	}
	tcpErr := port.tcpService.Stop()
	udpErr := port.udpService.Stop()
	delete(s.ports, portNum)
	if tcpErr != nil {
		return fmt.Errorf("Failed to close listener on %v: %v", portNum, tcpErr)
	}
	if udpErr != nil {
		return fmt.Errorf("Failed to close packetConn on %v: %v", portNum, udpErr)
	}
	logger.Infof("Stopped TCP and UDP on port %v", portNum)
	return nil
}

func (s *SSServer) loadConfig(filename string) error {
	config, err := readConfig(filename)
	if err != nil {
		return fmt.Errorf("Failed to read config file %v: %v", filename, err)
	}

	portChanges := make(map[int]int)
	portCiphers := make(map[int]shadowsocks.CipherList)
	for _, keyConfig := range config.Keys {
		portChanges[keyConfig.Port] = 1
		cipherList, ok := portCiphers[keyConfig.Port]
		if !ok {
			cipherList = shadowsocks.NewCipherList()
			portCiphers[keyConfig.Port] = cipherList
		}
		cipher, err := core.PickCipher(keyConfig.Cipher, nil, keyConfig.Secret)
		if err != nil {
			if err == core.ErrCipherNotSupported {
				return fmt.Errorf("Cipher %v for key %v is not supported", keyConfig.Cipher, keyConfig.ID)
			}
			return fmt.Errorf("Failed to create cipher for key %v: %v", keyConfig.ID, err)
		}
		aead, ok := cipher.(shadowaead.Cipher)
		if !ok {
			return fmt.Errorf("Only AEAD ciphers are supported. Found %v", keyConfig.Cipher)
		}
		cipherList.PushBack(keyConfig.ID, aead)
	}
	for port := range s.ports {
		portChanges[port] = portChanges[port] - 1
	}
	for portNum, count := range portChanges {
		if count == -1 {
			if err := s.removePort(portNum); err != nil {
				return fmt.Errorf("Failed to remove port %v: %v", portNum, err)
			}
		} else if count == +1 {
			if err := s.startPort(portNum); err != nil {
				return fmt.Errorf("Failed to start port %v: %v", portNum, err)
			}
		}
	}
	for portNum, cipherList := range portCiphers {
		s.ports[portNum].cipherList = cipherList
	}
	logger.Infof("Loaded %v access keys", len(config.Keys))
	s.m.SetNumAccessKeys(len(config.Keys), len(portCiphers))
	return nil
}

func runSSServer(filename string, natTimeout time.Duration, sm metrics.ShadowsocksMetrics) error {
	server := &SSServer{natTimeout: natTimeout, m: sm, ports: make(map[int]*SSPort)}
	err := server.loadConfig(filename)
	if err != nil {
		return fmt.Errorf("Failed to load config file %v: %v", filename, err)
	}
	sigHup := make(chan os.Signal, 1)
	signal.Notify(sigHup, syscall.SIGHUP)
	go func() {
		for range sigHup {
			logger.Info("Updating config")
			if err := server.loadConfig(filename); err != nil {
				logger.Errorf("Could not reload config: %v", err)
			}
		}
	}()
	return nil
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
	configData, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(configData, &config)
	return &config, err
}

func main() {
	var flags struct {
		ConfigFile  string
		MetricsAddr string
		IPCountryDB string
		Verbose     bool
		natTimeout  time.Duration
	}
	flag.StringVar(&flags.ConfigFile, "config", "", "Configuration filename")
	flag.StringVar(&flags.MetricsAddr, "metrics", "", "Address for the Prometheus metrics")
	flag.StringVar(&flags.IPCountryDB, "ip_country_db", "", "Path to the GeoLite2-Country.mmdb file")
	flag.DurationVar(&flags.natTimeout, "udptimeout", 5*time.Minute, "UDP tunnel timeout")
	flag.BoolVar(&flags.Verbose, "verbose", false, "Enables verbose logging output")

	flag.Parse()

	if flags.Verbose {
		logging.SetLevel(logging.DEBUG, "")
	} else {
		logging.SetLevel(logging.INFO, "")
	}

	if flags.ConfigFile == "" {
		flag.Usage()
		return
	}

	if flags.MetricsAddr != "" {
		http.Handle("/metrics", promhttp.Handler())
		go func() {
			logger.Fatal(http.ListenAndServe(flags.MetricsAddr, nil))
		}()
		logger.Infof("Metrics on http://%v/metrics", flags.MetricsAddr)
	}

	var ipCountryDB *geoip2.Reader
	var err error
	if flags.IPCountryDB != "" {
		logger.Infof("Using IP-Country database at %v", flags.IPCountryDB)
		ipCountryDB, err = geoip2.Open(flags.IPCountryDB)
		if err != nil {
			log.Fatalf("Could not open geoip database at %v: %v", flags.IPCountryDB, err)
		}
		defer ipCountryDB.Close()
	}
	err = runSSServer(flags.ConfigFile, flags.natTimeout, metrics.NewShadowsocksMetrics(ipCountryDB))
	if err != nil {
		logger.Fatal(err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}
