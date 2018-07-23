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
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Jigsaw-Code/outline-ss-server/metrics"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/shadowsocks/go-shadowsocks2/core"
	ssnet "github.com/shadowsocks/go-shadowsocks2/net"
	"github.com/shadowsocks/go-shadowsocks2/shadowaead"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

var config struct {
	UDPTimeout time.Duration
}

func shadowConn(conn ssnet.DuplexConn, cipherList []shadowaead.Cipher) (ssnet.DuplexConn, int, error) {
	cipher, index, shadowReader, err := findCipher(conn, cipherList)
	if err != nil {
		return nil, -1, err
	}
	shadowWriter := shadowaead.NewShadowsocksWriter(conn, cipher)
	return ssnet.WrapDuplexConn(conn, shadowReader, shadowWriter), index, nil
}

func findCipher(clientReader io.Reader, cipherList []shadowaead.Cipher) (shadowaead.Cipher, int, io.Reader, error) {
	if len(cipherList) == 0 {
		return nil, -1, nil, errors.New("Empty cipher list")
	} else if len(cipherList) == 1 {
		return cipherList[0], 0, shadowaead.NewShadowsocksReader(clientReader, cipherList[0]), nil
	}
	// buffer saves the bytes read from shadowConn, in order to allow for replays.
	var buffer bytes.Buffer
	// Try each cipher until we find one that authenticates successfully.
	// This assumes that all ciphers are AEAD.
	// TODO: Reorder list to try previously successful ciphers first for the client IP.
	// TODO: Ban and log client IPs with too many failures too quick to protect against DoS.
	for i, cipher := range cipherList {
		log.Printf("Trying cipher %v", i)
		// tmpReader reuses the bytes read so far, falling back to shadowConn if it needs more
		// bytes. All bytes read from shadowConn are saved in buffer.
		tmpReader := io.MultiReader(bytes.NewReader(buffer.Bytes()), io.TeeReader(clientReader, &buffer))
		// Override the Reader of shadowConn so we can reset it for each cipher test.
		cipherReader := shadowaead.NewShadowsocksReader(tmpReader, cipher)
		// Read should read just enough data to authenticate the payload size.
		_, err := cipherReader.Read(make([]byte, 0))
		if err != nil {
			log.Printf("Failed cipher %v: %v", i, err)
			continue
		}
		log.Printf("Selected cipher %v", i)
		// We don't need to replay the bytes anymore, but we don't want to drop those
		// read so far.
		return cipher, i, shadowaead.NewShadowsocksReader(io.MultiReader(&buffer, clientReader), cipher), nil
	}
	return nil, -1, nil, fmt.Errorf("could not find valid cipher")
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
func tcpRemote(addr string, cipherList []shadowaead.Cipher, m metrics.TCPMetrics) {
	accessKeyMetrics := metrics.NewMetricsMap()
	netMetrics := metrics.NewMetricsMap()
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("failed to listen on %s: %v", addr, err)
		return
	}

	log.Printf("listening TCP on %s", addr)
	for {
		var clientConn ssnet.DuplexConn
		clientConn, err := l.(*net.TCPListener).AcceptTCP()
		m.AddOpenTCPConnection()
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
			accessKey := "INVALID"
			var proxyMetrics metrics.ProxyMetrics
			clientConn = metrics.MeasureConn(clientConn, &proxyMetrics.ProxyClient, &proxyMetrics.ClientProxy)
			defer func() {
				connEnd := time.Now()
				connDuration := connEnd.Sub(connStart)
				clientConn.Close()
				status := "OK"
				if connError != nil {
					log.Printf("%v: %v", connError.message, connError.cause)
					status = connError.status
				}
				log.Printf("Done with status %v, duration %v", status, connDuration)
				m.AddClosedTCPConnection(accessKey, status, connDuration)
				accessKeyMetrics.Add(accessKey, proxyMetrics)
				log.Printf("Key %v: %s", accessKey, metrics.SPrintMetrics(accessKeyMetrics.Get(accessKey)))
				netMetrics.Add(netKey, proxyMetrics)
				log.Printf("Net %v: %s", netKey, metrics.SPrintMetrics(netMetrics.Get(netKey)))
			}()

			clientConn, index, err := shadowConn(clientConn, cipherList)
			if err != nil {
				return &connectionError{"ERR_CIPHER", "Failed to find a valid cipher", err}
			}
			accessKey = strconv.Itoa(index)

			tgt, err := socks.ReadAddr(clientConn)
			if err != nil {
				return &connectionError{"ERR_READ_ADDRESS", "Failed to get target address", err}
			}

			c, err := net.Dial("tcp", tgt.String())
			if err != nil {
				return &connectionError{"ERR_CONNECT", "Failed to connect to target", err}
			}
			var tgtConn ssnet.DuplexConn = c.(*net.TCPConn)
			defer tgtConn.Close()
			tgtConn.(*net.TCPConn).SetKeepAlive(true)
			tgtConn = metrics.MeasureConn(tgtConn, &proxyMetrics.ProxyTarget, &proxyMetrics.TargetProxy)

			log.Printf("proxy %s <-> %s", clientConn.RemoteAddr(), tgt)
			_, _, err = ssnet.Relay(clientConn, tgtConn)
			if err != nil {
				return &connectionError{"ERR_RELAY", "Failed to relay traffic", err}
			}
			return nil
		}()
	}
}

type cipherList []shadowaead.Cipher

func main() {

	var flags struct {
		Server      string
		Ciphers     cipherList
		MetricsAddr string
	}

	flag.StringVar(&flags.Server, "s", "", "server listen address")
	flag.Var(&flags.Ciphers, "u", "available ciphers: "+strings.Join(core.ListCipher(), " "))
	flag.DurationVar(&config.UDPTimeout, "udptimeout", 5*time.Minute, "UDP tunnel timeout")
	flag.StringVar(&flags.MetricsAddr, "metrics", "", "address for the Prometheus metrics")
	flag.Parse()

	if flags.Server == "" || len(flags.Ciphers) == 0 {
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

	go udpRemote(flags.Server, flags.Ciphers)
	go tcpRemote(flags.Server, flags.Ciphers, metrics.NewPrometheusTCPMetrics())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}

func (sl *cipherList) Set(flagValue string) error {
	e := strings.SplitN(flagValue, ":", 2)
	if len(e) != 2 {
		return fmt.Errorf("Missing colon")
	}
	cipher, err := core.PickCipher(e[0], nil, e[1])
	if err != nil {
		return err
	}
	aead, ok := cipher.(shadowaead.Cipher)
	if !ok {
		log.Fatal("Only AEAD ciphers are supported")
	}
	*sl = append(*sl, aead)
	return nil
}

func (sl *cipherList) String() string {
	return fmt.Sprint(*sl)
}
