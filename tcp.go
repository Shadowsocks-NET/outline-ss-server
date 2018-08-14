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
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/Jigsaw-Code/outline-ss-server/metrics"
	onet "github.com/Jigsaw-Code/outline-ss-server/net"

	"github.com/shadowsocks/go-shadowsocks2/shadowaead"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

func findAccessKey(clientConn onet.DuplexConn, cipherList map[string]shadowaead.Cipher) (string, onet.DuplexConn, error) {
	if len(cipherList) == 0 {
		return "", nil, errors.New("Empty cipher list")
	} else if len(cipherList) == 1 {
		for id, cipher := range cipherList {
			reader := shadowaead.NewShadowsocksReader(clientConn, cipher)
			writer := shadowaead.NewShadowsocksWriter(clientConn, cipher)
			return id, onet.WrapConn(clientConn, reader, writer), nil
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
		return id, onet.WrapConn(clientConn, ssr, ssw).(onet.DuplexConn), nil
	}
	return "", nil, fmt.Errorf("could not find valid key")
}

func runTCPService(listener *net.TCPListener, ciphers *map[string]shadowaead.Cipher, m metrics.ShadowsocksMetrics) {
	for {
		var clientConn onet.DuplexConn
		clientConn, err := listener.AcceptTCP()
		if err != nil {
			log.Printf("failed to accept: %v", err)
			continue
		}
		m.AddOpenTCPConnection()

		go func() (connError *connectionError) {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("ERROR Panic in TCP handler: %v", r)
				}
			}()
			connStart := time.Now()
			clientConn.(*net.TCPConn).SetKeepAlive(true)
			keyID := ""
			var proxyMetrics metrics.ProxyMetrics
			clientConn = metrics.MeasureConn(clientConn, &proxyMetrics.ProxyClient, &proxyMetrics.ClientProxy)
			defer func() {
				connEnd := time.Now()
				connDuration := connEnd.Sub(connStart)
				clientConn.Close()
				status := "OK"
				if connError != nil {
					log.Printf("ERROR [TCP] %v: %v", connError.message, connError.cause)
					status = connError.status
				}
				log.Printf("Done with status %v, duration %v", status, connDuration)
				m.AddClosedTCPConnection(keyID, status, proxyMetrics, connDuration)
			}()

			keyID, clientConn, err := findAccessKey(clientConn, *ciphers)
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
