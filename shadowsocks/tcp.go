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

package shadowsocks

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	logging "github.com/op/go-logging"

	"github.com/Jigsaw-Code/outline-ss-server/metrics"
	onet "github.com/Jigsaw-Code/outline-ss-server/net"

	"github.com/shadowsocks/go-shadowsocks2/shadowaead"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

func findAccessKey(clientConn onet.DuplexConn, cipherList map[string]shadowaead.Cipher) (string, onet.DuplexConn, error) {
	if len(cipherList) == 0 {
		return "", nil, errors.New("Empty cipher list")
	}
	// replayBuffer saves the bytes read from shadowConn, in order to allow for replays.
	var replayBuffer bytes.Buffer
	// Try each cipher until we find one that authenticates successfully.
	// This assumes that all ciphers are AEAD.
	// TODO: Reorder list to try previously successful ciphers first for the client IP.
	// TODO: Ban and log client IPs with too many failures too quick to protect against DoS.
	for id, cipher := range cipherList {
		// tmpReader reads first from the replayBuffer and then from clientConn if it needs more
		// bytes. All bytes read from clientConn are saved in replayBuffer for future replays.
		tmpReader := io.MultiReader(bytes.NewReader(replayBuffer.Bytes()), io.TeeReader(clientConn, &replayBuffer))
		cipherReader := NewShadowsocksReader(tmpReader, cipher)
		// Read should read just enough data to authenticate the payload size.
		_, err := cipherReader.Read(make([]byte, 0))
		if err != nil {
			if logger.IsEnabledFor(logging.DEBUG) {
				logger.Debugf("Failed TCP cipher %v: %v", id, err)
			}
			continue
		}
		if logger.IsEnabledFor(logging.DEBUG) {
			logger.Debugf("Selected TCP cipher %v", id)
		}
		// We don't need to keep storing and replaying the bytes anymore, but we don't want to drop
		// those already read into the replayBuffer.
		ssr := NewShadowsocksReader(io.MultiReader(&replayBuffer, clientConn), cipher)
		ssw := NewShadowsocksWriter(clientConn, cipher)
		return id, onet.WrapConn(clientConn, ssr, ssw).(onet.DuplexConn), nil
	}
	return "", nil, fmt.Errorf("could not find valid key")
}

type tcpService struct {
	listener  *net.TCPListener
	ciphers   *map[string]shadowaead.Cipher
	m         metrics.ShadowsocksMetrics
	isRunning bool
}

func NewTCPService(listener *net.TCPListener, ciphers *map[string]shadowaead.Cipher, m metrics.ShadowsocksMetrics) TCPService {
	return &tcpService{listener: listener, ciphers: ciphers, m: m}
}

type TCPService interface {
	Start()
	Stop() error
}

func (s *tcpService) Start() {
	s.isRunning = true
	for s.isRunning {
		var clientConn onet.DuplexConn
		clientConn, err := s.listener.AcceptTCP()
		if err != nil {
			if !s.isRunning {
				return
			}
			logger.Errorf("Failed to accept: %v", err)
		}

		go func() (connError *onet.ConnectionError) {
			clientLocation, err := s.m.GetLocation(clientConn.RemoteAddr())
			if err != nil {
				logger.Warningf("Failed location lookup: %v", err)
			}
			logger.Debugf("Got location \"%v\" for IP %v", clientLocation, clientConn.RemoteAddr().String())
			s.m.AddOpenTCPConnection(clientLocation)
			defer func() {
				if r := recover(); r != nil {
					logger.Errorf("Panic in TCP handler: %v", r)
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
					logger.Debugf("TCP Error: %v: %v", connError.Message, connError.Cause)
					status = connError.Status
				}
				logger.Debugf("Done with status %v, duration %v", status, connDuration)
				s.m.AddClosedTCPConnection(clientLocation, keyID, status, proxyMetrics, connDuration)
			}()

			keyID, clientConn, err := findAccessKey(clientConn, *s.ciphers)
			if err != nil {
				return &onet.ConnectionError{"ERR_CIPHER", "Failed to find a valid cipher", err}
			}

			tgtAddr, err := socks.ReadAddr(clientConn)
			if err != nil {
				return &onet.ConnectionError{"ERR_READ_ADDRESS", "Failed to get target address", err}
			}
			tgtTCPAddr, err := net.ResolveTCPAddr("tcp", tgtAddr.String())
			if err != nil {
				return &onet.ConnectionError{"ERR_RESOLVE_ADDRESS", fmt.Sprintf("Failed to resolve target address %v", tgtAddr.String()), err}
			}
			if !tgtTCPAddr.IP.IsGlobalUnicast() {
				return &onet.ConnectionError{"ERR_ADDRESS_INVALID", fmt.Sprintf("Target address is not global unicast: %v", tgtAddr.String()), err}
			}

			tgtTCPConn, err := net.DialTCP("tcp", nil, tgtTCPAddr)
			if err != nil {
				return &onet.ConnectionError{"ERR_CONNECT", "Failed to connect to target", err}
			}
			defer tgtTCPConn.Close()
			tgtTCPConn.SetKeepAlive(true)
			tgtConn := metrics.MeasureConn(tgtTCPConn, &proxyMetrics.ProxyTarget, &proxyMetrics.TargetProxy)

			// TODO: Disable logging in production. This is sensitive.
			logger.Debugf("proxy %s <-> %s", clientConn.RemoteAddr().String(), tgtConn.RemoteAddr().String())
			_, _, err = onet.Relay(clientConn, tgtConn)
			if err != nil {
				return &onet.ConnectionError{"ERR_RELAY", "Failed to relay traffic", err}
			}
			return nil
		}()
	}
}

func (s *tcpService) Stop() error {
	s.isRunning = false
	return s.listener.Close()
}
