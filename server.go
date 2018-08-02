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
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Jigsaw-Code/outline-ss-server/metrics"
	onet "github.com/Jigsaw-Code/outline-ss-server/net"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/shadowsocks/go-shadowsocks2/core"
	ssnet "github.com/shadowsocks/go-shadowsocks2/net"
	"github.com/shadowsocks/go-shadowsocks2/shadowaead"
	"github.com/shadowsocks/go-shadowsocks2/socks"
	"gopkg.in/yaml.v2"
)

var config struct {
	UDPTimeout time.Duration
}

type SSPort struct {
	m                metrics.TCPMetrics
	accessKeyMetrics *metrics.MetricsMap
	netMetrics       *metrics.MetricsMap
	listener         *net.TCPListener
	packetConn       net.PacketConn
	keys             map[string]shadowaead.Cipher
}

func findAccessKey(clientConn onet.DuplexConn, cipherList map[string]shadowaead.Cipher) (string, onet.DuplexConn, error) {
	if len(cipherList) == 0 {
		return "", nil, errors.New("Empty cipher list")
	} else if len(cipherList) == 1 {
		for id, cipher := range cipherList {
			return id, shadowaead.NewConn(clientConn, cipher).(onet.DuplexConn), nil
		}
	}
	// buffer saves the bytes read from shadowConn, in order to allow for replays.
	var buffer bytes.Buffer
	// Try each cipher until we find one that authenticates successfully.
	// This assumes that all ciphers are AEAD.
	// TODO: Reorder list to try previously successful ciphers first for the client IP.
	// TODO: Ban and log client IPs with too many failures too quick to protect against DoS.
	for id, cipher := range cipherList {
		log.Printf("Trying key %v", id)
		// tmpReader reuses the bytes read so far, falling back to shadowConn if it needs more
		// bytes. All bytes read from shadowConn are saved in buffer.
		tmpReader := io.MultiReader(bytes.NewReader(buffer.Bytes()), io.TeeReader(clientConn, &buffer))
		// Override the Reader of shadowConn so we can reset it for each cipher test.
		cipherReader := shadowaead.NewShadowsocksReader(tmpReader, cipher)
		// Read should read just enough data to authenticate the payload size.
		_, err := cipherReader.Read(make([]byte, 0))
		if err != nil {
			log.Printf("Failed key %v: %v", id, err)
			continue
		}
		log.Printf("Selected key %v", id)
		// We don't need to replay the bytes anymore, but we don't want to drop those
		// read so far.
		ssr := shadowaead.NewShadowsocksReader(io.MultiReader(&buffer, clientConn), cipher)
		ssw := shadowaead.NewShadowsocksWriter(clientConn, cipher)
		return id, ssnet.WrapConn(clientConn, ssr, ssw).(onet.DuplexConn), nil
	}
	return "", nil, fmt.Errorf("could not find valid key")
}

func getNetKey(addr net.Addr) (string, error) {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return "", err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "", errors.New("Failed to parse ip")
	}
	ipNet := net.IPNet{IP: ip}
	if ip.To4() != nil {
		ipNet.Mask = net.CIDRMask(24, 32)
	} else {
		ipNet.Mask = net.CIDRMask(32, 128)
	}
	return ipNet.String(), nil
}

type connectionError struct {
	// TODO: create status enums and move to metrics.go
	status  string
	message string
	cause   error
}

// Listen on addr for incoming connections.
func (port *SSPort) run() {
	go udpRemote(port.packetConn, port.keys)
	for {
		var clientConn onet.DuplexConn
		clientConn, err := port.listener.AcceptTCP()
		port.m.AddOpenTCPConnection()
		if err != nil {
			log.Printf("failed to accept: %v", err)
			return
		}

		go func() (connError *connectionError) {
			connStart := time.Now()
			clientConn.(*net.TCPConn).SetKeepAlive(true)
			netKey, err := getNetKey(clientConn.RemoteAddr())
			if err != nil {
				netKey = "INVALID"
			}
			keyID := ""
			var proxyMetrics metrics.ProxyMetrics
			clientConn = metrics.MeasureConn(clientConn, &proxyMetrics.ProxyClient, &proxyMetrics.ClientProxy)
			defer func() {
				connEnd := time.Now()
				connDuration := connEnd.Sub(connStart)
				clientConn.Close()
				status := "OK"
				if connError != nil {
					log.Printf("ERROR %v: %v", connError.message, connError.cause)
					status = connError.status
				}
				log.Printf("Done with status %v, duration %v", status, connDuration)
				port.m.AddClosedTCPConnection(keyID, status, proxyMetrics, connDuration)
				port.accessKeyMetrics.Add(keyID, proxyMetrics)
				log.Printf("Key %v: %s", keyID, metrics.SPrintMetrics(port.accessKeyMetrics.Get(keyID)))
				port.netMetrics.Add(netKey, proxyMetrics)
				log.Printf("Net %v: %s", netKey, metrics.SPrintMetrics(port.netMetrics.Get(netKey)))
			}()

			keyID, clientConn, err := findAccessKey(clientConn, port.keys)
			if err != nil {
				return &connectionError{"ERR_CIPHER", "Failed to find a valid cipher", err}
			}

			tgt, err := socks.ReadAddr(clientConn)
			if err != nil {
				return &connectionError{"ERR_READ_ADDRESS", "Failed to get target address", err}
			}

			c, err := net.Dial("tcp", tgt.String())
			if err != nil {
				return &connectionError{"ERR_CONNECT", "Failed to connect to target", err}
			}
			var tgtConn onet.DuplexConn = c.(*net.TCPConn)
			defer tgtConn.Close()
			tgtConn.(*net.TCPConn).SetKeepAlive(true)
			tgtConn = metrics.MeasureConn(tgtConn, &proxyMetrics.ProxyTarget, &proxyMetrics.TargetProxy)

			// TODO: Disable logging in production. This is sensitive.
			log.Printf("proxy %s <-> %s", clientConn.RemoteAddr(), tgt)
			_, _, err = onet.Relay(clientConn, tgtConn)
			if err != nil {
				return &connectionError{"ERR_RELAY", "Failed to relay traffic", err}
			}
			return nil
		}()
	}
}

type SSServer struct {
	m                metrics.TCPMetrics
	accessKeyMetrics *metrics.MetricsMap
	netMetrics       *metrics.MetricsMap
	ports            map[int]*SSPort
}

func (s *SSServer) startPort(portNum int) error {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{Port: portNum})
	if err != nil {
		return fmt.Errorf("Failed to start TCP on port %v: %v", portNum, err)
	}
	packetConn, err := net.ListenUDP("udp", &net.UDPAddr{Port: portNum})
	if err != nil {
		return fmt.Errorf("ERROR Failed to start UDP on port %v: %v", portNum, err)
	}
	log.Printf("INFO Listening TCP and UDP on port %v", portNum)
	port := &SSPort{m: s.m, accessKeyMetrics: s.accessKeyMetrics, netMetrics: s.netMetrics,
		listener: listener, packetConn: packetConn, keys: make(map[string]shadowaead.Cipher)}
	s.ports[portNum] = port
	go port.run()
	return nil
}

func (s *SSServer) removePort(portNum int) error {
	port, ok := s.ports[portNum]
	if !ok {
		return fmt.Errorf("Port %v doesn't exist", portNum)
	}
	tcpErr := port.listener.Close()
	udpErr := port.packetConn.Close()
	delete(s.ports, portNum)
	if tcpErr != nil {
		return fmt.Errorf("Failed to close listener on %v: %v", portNum, tcpErr)
	}
	if udpErr != nil {
		return fmt.Errorf("Failed to close packetConn on %v: %v", portNum, udpErr)
	}
	log.Printf("INFO Stopped TCP and UDP on port %v", portNum)
	return nil
}

func (s *SSServer) loadConfig(filename string) error {
	config, err := readConfig(filename)
	if err != nil {
		return fmt.Errorf("Failed to read config file %v: %v", filename, err)
	}

	portChanges := make(map[int]int)
	portKeys := make(map[int]map[string]shadowaead.Cipher)
	for _, keyConfig := range config.Keys {
		portChanges[keyConfig.Port] = 1
		keys, ok := portKeys[keyConfig.Port]
		if !ok {
			keys = make(map[string]shadowaead.Cipher)
			portKeys[keyConfig.Port] = keys
		}
		cipher, err := core.PickCipher(keyConfig.Cipher, nil, keyConfig.Secret)
		if err != nil {
			return fmt.Errorf("Failed to create cipher for key %v: %v", keyConfig.ID, err)
		}
		aead, ok := cipher.(shadowaead.Cipher)
		if !ok {
			return fmt.Errorf("Only AEAD ciphers are supported. Found %v", keyConfig.Cipher)
		}
		keys[keyConfig.ID] = aead
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
	for portNum, keys := range portKeys {
		s.ports[portNum].keys = keys
	}
	return nil
}

func runSSServer(filename string) error {
	server := &SSServer{m: metrics.NewPrometheusTCPMetrics(), accessKeyMetrics: metrics.NewMetricsMap(),
		netMetrics: metrics.NewMetricsMap(), ports: make(map[int]*SSPort)}
	err := server.loadConfig(filename)
	if err != nil {
		return fmt.Errorf("Failed to load config file %v: %v", filename, err)
	}
	sigHup := make(chan os.Signal, 1)
	signal.Notify(sigHup, syscall.SIGHUP)
	go func() {
		for range sigHup {
			log.Printf("Updating config")
			if err := server.loadConfig(filename); err != nil {
				log.Printf("ERROR Could not reload config: %v", err)
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
	}
	flag.StringVar(&flags.ConfigFile, "config", "", "config filename")
	flag.StringVar(&flags.MetricsAddr, "metrics", "", "address for the Prometheus metrics")
	flag.Parse()

	if flags.ConfigFile == "" {
		flag.Usage()
		return
	}

	if flags.MetricsAddr != "" {
		http.Handle("/metrics", promhttp.Handler())
		go func() {
			log.Fatal(http.ListenAndServe(flags.MetricsAddr, nil))
		}()
		log.Printf("Metrics on http://%v/metrics", flags.MetricsAddr)
	}

	err := runSSServer(flags.ConfigFile)
	if err != nil {
		log.Fatal(err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}
