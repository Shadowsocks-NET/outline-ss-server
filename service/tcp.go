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

package service

import (
	"bytes"
	"container/list"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync"
	"syscall"
	"time"

	onet "github.com/Shadowsocks-NET/outline-ss-server/net"
	"github.com/Shadowsocks-NET/outline-ss-server/service/metrics"
	ss "github.com/Shadowsocks-NET/outline-ss-server/shadowsocks"
	"github.com/database64128/tfo-go"
	"go.uber.org/zap"
)

func remoteIP(conn net.Conn) net.IP {
	addr := conn.RemoteAddr()
	if addr == nil {
		return nil
	}
	if tcpaddr, ok := addr.(*net.TCPAddr); ok {
		return tcpaddr.IP
	}
	ipstr, _, err := net.SplitHostPort(addr.String())
	if err == nil {
		return net.ParseIP(ipstr)
	}
	return nil
}

// bytesForKeyFinding is the number of bytes to read for finding the AccessKey.
// Is must satisfy provided >= bytesForKeyFinding >= required for every cipher in the list.
// provided = saltSize + 2 + 2 * cipher.TagSize, the minimum number of bytes we will see in a valid connection
// required = saltSize + 2 + cipher.TagSize, the number of bytes needed to authenticate the connection.
const bytesForKeyFinding = 50

func findAccessKey(clientReader io.Reader, clientIP net.IP, cipherList CipherList) (*CipherEntry, io.Reader, []byte, time.Duration, error) {
	// We snapshot the list because it may be modified while we use it.
	ciphers := cipherList.SnapshotForClientIP(clientIP)
	firstBytes := make([]byte, bytesForKeyFinding)
	if n, err := io.ReadFull(clientReader, firstBytes); err != nil {
		return nil, clientReader, nil, 0, fmt.Errorf("reading header failed after %d bytes: %v", n, err)
	}

	findStartTime := time.Now()
	entry, elt := findEntry(firstBytes, ciphers)
	timeToCipher := time.Since(findStartTime)
	if entry == nil {
		// TODO: Ban and log client IPs with too many failures too quick to protect against DoS.
		return nil, clientReader, nil, timeToCipher, fmt.Errorf("could not find valid TCP cipher")
	}

	// Move the active cipher to the front, so that the search is quicker next time.
	cipherList.MarkUsedByClientIP(elt, clientIP)
	salt := firstBytes[:entry.Cipher.SaltSize()]
	return entry, io.MultiReader(bytes.NewReader(firstBytes), clientReader), salt, timeToCipher, nil
}

// Implements a trial decryption search.  This assumes that all ciphers are AEAD.
func findEntry(firstBytes []byte, ciphers []*list.Element) (*CipherEntry, *list.Element) {
	// To hold the decrypted chunk length.
	chunkLenBuf := [2]byte{}
	for ci, elt := range ciphers {
		entry := elt.Value.(*CipherEntry)
		id, cipher := entry.ID, entry.Cipher
		saltsize := cipher.SaltSize()
		salt := firstBytes[:saltsize]
		cipherTextLength := 2 + cipher.TagSize()
		cipherText := firstBytes[saltsize : saltsize+cipherTextLength]
		_, err := ss.DecryptOnce(cipher, salt, chunkLenBuf[:0], cipherText)
		if err != nil {
			continue
		}
		logger.Debug("Found cipher entry",
			zap.Int("index", ci),
			zap.String("id", id),
		)
		return entry, elt
	}
	return nil, nil
}

type tcpService struct {
	mu          sync.RWMutex // Protects .listeners and .stopped
	listener    *net.TCPListener
	dialerTFO   bool
	stopped     bool
	ciphers     CipherList
	m           metrics.ShadowsocksMetrics
	running     sync.WaitGroup
	readTimeout time.Duration
	// `replayCache` is a pointer to SSServer.replayCache, to share the cache among all ports.
	replayCache       *ReplayCache
	saltPool          *SaltPool
	targetIPValidator onet.TargetIPValidator
}

// NewTCPService creates a TCPService
// `replayCache` is a pointer to SSServer.replayCache, to share the cache among all ports.
func NewTCPService(ciphers CipherList, replayCache *ReplayCache, saltPool *SaltPool, m metrics.ShadowsocksMetrics, timeout time.Duration, dialerTFO bool) TCPService {
	return &tcpService{
		dialerTFO:   dialerTFO,
		ciphers:     ciphers,
		m:           m,
		readTimeout: timeout,
		replayCache: replayCache,
		saltPool:    saltPool,
	}
}

// TCPService is a Shadowsocks TCP service that can be started and stopped.
type TCPService interface {
	// SetTargetIPValidator sets the function to be used to validate the target IP addresses.
	SetTargetIPValidator(targetIPValidator onet.TargetIPValidator)
	// Serve adopts the listener, which will be closed before Serve returns.  Serve returns an error unless Stop() was called.
	Serve(listener *net.TCPListener) error
	// Stop closes the listener but does not interfere with existing connections.
	Stop() error
	// GracefulStop calls Stop(), and then blocks until all resources have been cleaned up.
	GracefulStop() error
}

func (s *tcpService) SetTargetIPValidator(targetIPValidator onet.TargetIPValidator) {
	s.targetIPValidator = targetIPValidator
}

func dialTarget(address string, proxyMetrics *metrics.ProxyMetrics, targetIPValidator onet.TargetIPValidator, dialerTFO bool) (onet.DuplexConn, *onet.ConnectionError) {
	var ipError *onet.ConnectionError
	dialer := tfo.Dialer{
		DisableTFO: !dialerTFO,
	}
	if targetIPValidator != nil {
		dialer.Control = func(network, address string, c syscall.RawConn) error {
			ip, _, _ := net.SplitHostPort(address)
			ipError = targetIPValidator(net.ParseIP(ip))
			if ipError != nil {
				return errors.New(ipError.Message)
			}
			return nil
		}
	}
	tgtConn, err := dialer.Dial("tcp", address)
	if ipError != nil {
		return nil, ipError
	} else if err != nil {
		return nil, onet.NewConnectionError("ERR_CONNECT", "Failed to connect to target", err)
	}
	tgtTCPConn := tgtConn.(tfo.Conn)
	return metrics.MeasureConn(tgtTCPConn, &proxyMetrics.ProxyTarget, &proxyMetrics.TargetProxy), nil
}

func (s *tcpService) Serve(listener *net.TCPListener) error {
	s.mu.Lock()
	if s.listener != nil {
		s.mu.Unlock()
		listener.Close()
		return errors.New("Serve can only be called once")
	}
	if s.stopped {
		s.mu.Unlock()
		return listener.Close()
	}
	s.listener = listener
	s.running.Add(1)
	s.mu.Unlock()

	defer s.running.Done()
	for {
		clientTCPConn, err := listener.AcceptTCP()
		if err != nil {
			s.mu.RLock()
			stopped := s.stopped
			s.mu.RUnlock()
			if stopped {
				return nil
			}
			logger.Warn("Failed to accept TCP connection",
				zap.Stringer("listenAddress", listener.Addr()),
				zap.Error(err),
			)
			continue
		}

		s.running.Add(1)
		go func() {
			defer s.running.Done()
			s.handleConnection(clientTCPConn)
		}()
	}
}

func (s *tcpService) handleConnection(clientTCPConn tfo.Conn) {
	clientLocalAddr := clientTCPConn.LocalAddr().(*net.TCPAddr)
	clientRemoteAddr := clientTCPConn.RemoteAddr()
	clientLocation, err := s.m.GetLocation(clientRemoteAddr)
	if err != nil {
		logger.Warn("Location lookup failed",
			zap.Stringer("clientConnLocalAddress", clientLocalAddr),
			zap.Stringer("clientConnRemoteAddress", clientRemoteAddr),
			zap.Error(err),
		)
	}
	logger.Debug("Location lookup success",
		zap.Stringer("clientConnLocalAddress", clientLocalAddr),
		zap.Stringer("clientConnRemoteAddress", clientRemoteAddr),
		zap.String("location", clientLocation),
	)
	s.m.AddOpenTCPConnection(clientLocation)

	connStart := time.Now()
	var connDuration time.Duration

	// Set a random deadline to receive header. [5, 60]
	secs := rand.Intn(56)
	secs += 5
	clientTCPConn.SetReadDeadline(connStart.Add(time.Duration(secs) * time.Second))

	var proxyMetrics metrics.ProxyMetrics
	clientConn := metrics.MeasureConn(clientTCPConn, &proxyMetrics.ProxyClient, &proxyMetrics.ClientProxy)
	cipherEntry, clientReader, clientSalt, timeToCipher, keyErr := findAccessKey(clientConn, remoteIP(clientTCPConn), s.ciphers)

	connError := func() *onet.ConnectionError {
		if keyErr != nil {
			logger.Warn("Failed to find a valid cipher",
				zap.Stringer("clientConnLocalAddress", clientLocalAddr),
				zap.Stringer("clientConnRemoteAddress", clientRemoteAddr),
				zap.String("location", clientLocation),
				zap.Int64("bytesRead", proxyMetrics.ClientProxy),
				zap.NamedError("keyError", keyErr),
			)
			const status = "ERR_CIPHER"
			s.absorbProbe(clientLocalAddr.Port, clientConn, clientLocation, status, &proxyMetrics)
			return onet.NewConnectionError(status, "Failed to find a valid cipher", keyErr)
		}

		// For the new spec, salt check is performed after header decoding.
		if !cipherEntry.Cipher.Config().IsSpec2022 {
			isServerSalt := cipherEntry.SaltGenerator.IsServerSalt(clientSalt)
			// Only check the cache if findAccessKey succeeded and the salt is unrecognized.
			if isServerSalt || !s.replayCache.Add(cipherEntry.ID, clientSalt) {
				var status string
				if isServerSalt {
					status = "ERR_REPLAY_SERVER"
				} else {
					status = "ERR_REPLAY_CLIENT"
				}
				logger.Warn("Detected replay: repeated salt",
					zap.Stringer("clientConnLocalAddress", clientLocalAddr),
					zap.Stringer("clientConnRemoteAddress", clientRemoteAddr),
					zap.String("location", clientLocation),
					zap.Int64("bytesRead", proxyMetrics.ClientProxy),
					zap.Bool("isServerSalt", isServerSalt),
					zap.NamedError("keyError", keyErr),
				)
				s.absorbProbe(clientLocalAddr.Port, clientConn, clientLocation, status, &proxyMetrics)
				return onet.NewConnectionError(status, "Replay detected", nil)
			}
		}

		ssr := ss.NewShadowsocksReader(clientReader, cipherEntry.Cipher)
		tgtAddr, err := ss.ParseTCPReqHeader(ssr, cipherEntry.Cipher.Config(), ss.HeaderTypeClientStream)
		if err != nil {
			logger.Warn("Failed to parse header",
				zap.Stringer("clientConnLocalAddress", clientLocalAddr),
				zap.Stringer("clientConnRemoteAddress", clientRemoteAddr),
				zap.String("location", clientLocation),
				zap.Int64("bytesRead", proxyMetrics.ClientProxy),
				zap.Error(err),
			)
			target := &ss.DecryptionErr{}
			if errors.As(err, &target) {
				// Drain to prevent a close on cipher error.
				io.Copy(io.Discard, clientConn)
			}
			return onet.NewConnectionError("ERR_READ_HEADER", "Failed to read header", err)
		}

		// 2022 spec: check salt
		if cipherEntry.Cipher.Config().IsSpec2022 && !s.saltPool.Add(*(*[32]byte)(clientSalt)) {
			logger.Warn("Detected replay: repeated salt",
				zap.Stringer("clientConnLocalAddress", clientLocalAddr),
				zap.Stringer("clientConnRemoteAddress", clientRemoteAddr),
				zap.String("location", clientLocation),
				zap.Int64("bytesRead", proxyMetrics.ClientProxy),
			)
			s.absorbProbe(clientLocalAddr.Port, clientConn, clientLocation, "ERR_REPEATED_SALT", &proxyMetrics)
			return onet.NewConnectionError("ERR_REPLAY_SS2022", "Replay detected", nil)
		}

		// Clear read deadline.
		clientTCPConn.SetReadDeadline(time.Time{})

		tgtConn, dialErr := dialTarget(tgtAddr, &proxyMetrics, s.targetIPValidator, s.dialerTFO)
		if dialErr != nil {
			logger.Warn("Failed to dial target",
				zap.Stringer("clientConnLocalAddress", clientLocalAddr),
				zap.Stringer("clientConnRemoteAddress", clientRemoteAddr),
				zap.String("targetAddress", tgtAddr),
				zap.NamedError("dialError", dialErr.Cause),
			)
			return dialErr
		}
		defer tgtConn.Close()

		logger.Info("Relaying",
			zap.Stringer("clientConnRemoteAddress", clientRemoteAddr),
			zap.Stringer("targetConnRemoteAddress", tgtConn.RemoteAddr()),
			zap.String("targetAddress", tgtAddr),
		)

		var lazyWriteBuf []byte
		if cipherEntry.Cipher.Config().IsSpec2022 {
			lazyWriteBuf = clientSalt
		}
		ssw, err := ss.NewShadowsocksWriter(clientConn, cipherEntry.Cipher, cipherEntry.SaltGenerator, lazyWriteBuf, false)
		if err != nil {
			logger.Error("Failed to create Shadowsocks writer",
				zap.Stringer("clientConnRemoteAddress", clientRemoteAddr),
				zap.Stringer("targetConnRemoteAddress", tgtConn.RemoteAddr()),
				zap.String("targetAddress", tgtAddr),
				zap.Error(err),
			)
			return onet.NewConnectionError("ERR_CREATE_SS_WRITER", "Failed to create Shadowsocks writer", err)
		}

		fromClientErrCh := make(chan error)
		go func() {
			_, fromClientErr := ssr.WriteTo(tgtConn)
			if fromClientErr != nil {
				logger.Warn("Failed to relay client -> target",
					zap.Stringer("clientConnLocalAddress", clientLocalAddr),
					zap.Stringer("clientConnRemoteAddress", clientRemoteAddr),
					zap.String("targetAddress", tgtAddr),
					zap.Error(fromClientErr),
				)
				target := &ss.DecryptionErr{}
				if errors.As(fromClientErr, &target) {
					// Drain to prevent a close in the case of a cipher error.
					io.Copy(io.Discard, clientConn)
				}
			}
			// Send FIN to target.
			// We must do this after the drain is completed, otherwise the target will close its
			// connection with the proxy, which will, in turn, close the connection with the client.
			tgtConn.CloseWrite()
			logger.Debug("Closed write to targetConn",
				zap.Stringer("clientConnLocalAddress", clientLocalAddr),
				zap.Stringer("clientConnRemoteAddress", clientRemoteAddr),
				zap.String("targetAddress", tgtAddr),
				zap.Int64("bytesWritten", proxyMetrics.ProxyTarget),
			)
			fromClientErrCh <- fromClientErr
		}()
		_, fromTargetErr := ssw.ReadFrom(tgtConn)
		if fromTargetErr != nil {
			logger.Warn("Failed to relay target -> client",
				zap.Stringer("clientConnLocalAddress", clientLocalAddr),
				zap.Stringer("clientConnRemoteAddress", clientRemoteAddr),
				zap.String("targetAddress", tgtAddr),
				zap.Error(fromTargetErr),
			)
		}
		// Send FIN to client.
		clientConn.CloseWrite()
		logger.Debug("Closed write to clientConn",
			zap.Stringer("clientConnLocalAddress", clientLocalAddr),
			zap.Stringer("clientConnRemoteAddress", clientRemoteAddr),
			zap.String("targetAddress", tgtAddr),
			zap.Int64("bytesWritten", proxyMetrics.ProxyClient),
		)

		fromClientErr := <-fromClientErrCh

		connDuration = time.Since(connStart)
		logger.Debug("Done relaying",
			zap.Stringer("clientConnLocalAddress", clientLocalAddr),
			zap.Stringer("clientConnRemoteAddress", clientRemoteAddr),
			zap.String("targetAddress", tgtAddr),
			zap.Duration("connDuration", connDuration),
		)

		if fromClientErr != nil {
			return onet.NewConnectionError("ERR_RELAY_CLIENT", "Failed to relay traffic from client", fromClientErr)
		}
		if fromTargetErr != nil {
			return onet.NewConnectionError("ERR_RELAY_TARGET", "Failed to relay traffic from target", fromTargetErr)
		}
		return nil
	}()

	status := "OK"
	if connError != nil {
		// Already logged before returning the error.
		status = connError.Status
	}
	var id string
	if cipherEntry != nil {
		id = cipherEntry.ID
	}
	s.m.AddClosedTCPConnection(clientLocation, id, status, proxyMetrics, timeToCipher, connDuration)
	clientConn.Close() // Closing after the metrics are added aids integration testing.
}

// Keep the connection open until we hit the authentication deadline to protect against probing attacks
// `proxyMetrics` is a pointer because its value is being mutated by `clientConn`.
func (s *tcpService) absorbProbe(listenerPort int, clientConn io.ReadCloser, clientLocation, status string, proxyMetrics *metrics.ProxyMetrics) {
	_, drainErr := io.Copy(io.Discard, clientConn) // drain socket
	drainResult := drainErrToString(drainErr)
	s.m.AddTCPProbe(clientLocation, status, drainResult, listenerPort, *proxyMetrics)
}

func drainErrToString(drainErr error) string {
	netErr, ok := drainErr.(net.Error)
	switch {
	case drainErr == nil:
		return "eof"
	case ok && netErr.Timeout():
		return "timeout"
	default:
		return "other"
	}
}

func (s *tcpService) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopped = true
	if s.listener == nil {
		return nil
	}
	return s.listener.Close()
}

func (s *tcpService) GracefulStop() error {
	err := s.Stop()
	s.running.Wait()
	return err
}
