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
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"sync"
	"time"

	onet "github.com/Shadowsocks-NET/outline-ss-server/net"
	"github.com/Shadowsocks-NET/outline-ss-server/service/metrics"
	ss "github.com/Shadowsocks-NET/outline-ss-server/shadowsocks"
	"go.uber.org/zap"
)

const (
	UDPPacketBufferSize = 64 * 1024
	UDPOOBBufferSize    = 0x10 + 0x14 // unix.SizeofCmsghdr + unix.SizeofInet6Pktinfo
)

// UDPService is a running UDP shadowsocks proxy that can be stopped.
type UDPService interface {
	// SetTargetIPValidator sets the function to be used to validate the target IP addresses.
	SetTargetIPValidator(targetIPValidator onet.TargetIPValidator)
	// Serve adopts the clientConn, and will not return until it is closed by Stop().
	Serve(clientConn onet.UDPPacketConn) error
	// Stop closes the clientConn and prevents further forwarding of packets.
	Stop() error
	// GracefulStop calls Stop(), and then blocks until all resources have been cleaned up.
	GracefulStop() error
}

type udpService struct {
	mu                sync.RWMutex // Protects .clientConn and .stopped
	clientConn        onet.UDPPacketConn
	stopped           bool
	natTimeout        time.Duration
	ciphers           CipherList
	m                 metrics.ShadowsocksMetrics
	running           sync.WaitGroup
	targetIPValidator onet.TargetIPValidator
}

// NewUDPService creates a UDPService
func NewUDPService(natTimeout time.Duration, cipherList CipherList, m metrics.ShadowsocksMetrics) UDPService {
	return &udpService{
		natTimeout: natTimeout,
		ciphers:    cipherList,
		m:          m,
	}
}

func (s *udpService) SetTargetIPValidator(targetIPValidator onet.TargetIPValidator) {
	s.targetIPValidator = targetIPValidator
}

// Listen on addr for encrypted packets and basically do UDP NAT.
// We take the ciphers as a pointer because it gets replaced on config updates.
func (s *udpService) Serve(clientConn onet.UDPPacketConn) error {
	s.mu.Lock()
	if s.clientConn != nil {
		s.mu.Unlock()
		clientConn.Close()
		return errors.New("Serve can only be called once")
	}
	if s.stopped {
		s.mu.Unlock()
		return clientConn.Close()
	}
	s.clientConn = clientConn
	s.running.Add(1)
	s.mu.Unlock()
	defer s.running.Done()

	nm := newNATmap(s.natTimeout, s.m, &s.running)
	defer nm.Close()
	cipherBuf := make([]byte, UDPPacketBufferSize)
	oobBuf := make([]byte, UDPOOBBufferSize)
	textBuf := make([]byte, UDPPacketBufferSize)

	stopped := false
	for !stopped {
		func() (connError *onet.ConnectionError) {
			// Attempt to read an upstream packet.
			clientProxyBytes, clientConnOobBytes, _, clientAddr, err := clientConn.ReadMsgUDP(cipherBuf, oobBuf)
			if err != nil {
				s.mu.RLock()
				stopped = s.stopped
				s.mu.RUnlock()
				if stopped {
					return nil
				}
			}

			// An upstream packet should have been read.  Set up the metrics reporting
			// for this forwarding event.
			var clientLocation string
			var keyID string
			var proxyTargetBytes int
			var timeToCipher time.Duration
			clientLocalAddr := s.clientConn.LocalAddr().(*net.UDPAddr)

			defer func() {
				status := "OK"
				if connError != nil {
					status = connError.Status
				}
				s.m.AddUDPPacketFromClient(clientLocation, keyID, status, clientProxyBytes, proxyTargetBytes, timeToCipher)
			}()

			if err != nil {
				logger.Warn("Failed to read from clientConn",
					zap.Stringer("clientConnLocalAddress", clientLocalAddr),
					zap.Error(err),
				)
				return onet.NewConnectionError("ERR_READ", "Failed to read from client", err)
			}

			cipherData := cipherBuf[:clientProxyBytes]
			oobCache, err := onet.GetOobForCache(oobBuf[:clientConnOobBytes])
			if err != nil {
				logger.Debug("Failed to process OOB",
					zap.Stringer("clientAddress", clientAddr),
					zap.Stringer("clientConnLocalAddress", clientLocalAddr),
					zap.Error(err),
				)
			}

			var sid uint64
			var ses *session
			var isNewSession bool
			var payload []byte
			var tgtUDPAddr *net.UDPAddr
			targetConn := nm.GetByClientAddress(clientAddr.String())
			if targetConn == nil {
				var locErr error
				clientLocation, locErr = s.m.GetLocation(clientAddr)
				if locErr != nil {
					logger.Warn("Location lookup failed",
						zap.Stringer("clientAddress", clientAddr),
						zap.Stringer("clientConnLocalAddress", clientLocalAddr),
						zap.Error(err),
					)
				}
				logger.Debug("Location lookup success",
					zap.Stringer("clientAddress", clientAddr),
					zap.Stringer("clientConnLocalAddress", clientLocalAddr),
					zap.String("clientLocation", clientLocation),
				)

				var textData []byte
				var c *ss.Cipher
				unpackStart := time.Now()
				textData, keyID, c, sid, ses, isNewSession, err = s.findAccessKeyUDP(clientAddr, textBuf, cipherData, nm)
				timeToCipher = time.Since(unpackStart)

				if err != nil {
					logger.Debug("Failed to unpack initial packet",
						zap.Stringer("clientAddress", clientAddr),
						zap.Stringer("clientConnLocalAddress", clientLocalAddr),
						zap.String("clientLocation", clientLocation),
						zap.Error(err),
					)
					return onet.NewConnectionError("ERR_CIPHER", "Failed to unpack initial packet", err)
				}

				var onetErr *onet.ConnectionError
				cipherConfig := c.Config()
				if payload, tgtUDPAddr, onetErr = s.validatePacket(textData, cipherConfig, clientAddr, clientLocalAddr, clientLocation, sid, ses, isNewSession, nm); onetErr != nil {
					return onetErr
				}

				logger.Info("New UDP session",
					zap.Stringer("clientAddress", clientAddr),
					zap.Stringer("clientConnLocalAddress", clientLocalAddr),
					zap.Stringer("targetAddress", tgtUDPAddr),
				)

				udpConn, err := net.ListenUDP("udp", nil)
				if err != nil {
					logger.Error("Failed to create UDP socket", zap.Error(err))
					return onet.NewConnectionError("ERR_CREATE_SOCKET", "Failed to create UDP socket", err)
				}

				// Store reference to targetConn
				if cipherConfig.IsSpec2022 {
					ses.targetConn = udpConn
				}

				targetConn = nm.Add(clientAddr, clientConn, oobCache, c, udpConn, clientLocation, keyID, ses)
			} else {
				clientLocation = targetConn.clientLocation
				var textData []byte
				var onetErr *onet.ConnectionError

				unpackStart := time.Now()
				textData, sid, ses, isNewSession, onetErr = decryptAndGetOrCreateSession(targetConn.keyID, targetConn.cipher, clientAddr, nil, cipherData, cipherData[:16], nm)
				timeToCipher = time.Since(unpackStart)
				if onetErr != nil {
					return onetErr
				}

				// The key ID is known with confidence once decryption succeeds.
				keyID = targetConn.keyID

				if payload, tgtUDPAddr, onetErr = s.validatePacket(textData, targetConn.cipher.Config(), clientAddr, clientLocalAddr, clientLocation, sid, ses, isNewSession, nm); onetErr != nil {
					return onetErr
				}

				targetConn.oobCache = oobCache
			}

			switch {
			case targetConn.cipher.Config().IsSpec2022:
				targetConn.onWrite(tgtUDPAddr)
				proxyTargetBytes, err = ses.targetConn.WriteToUDP(payload, tgtUDPAddr)
			default:
				proxyTargetBytes, err = targetConn.WriteToUDP(payload, tgtUDPAddr)
			}

			if err != nil {
				logger.Debug("Failed to write to targetConn",
					zap.Stringer("clientAddress", clientAddr),
					zap.Stringer("clientConnLocalAddress", clientLocalAddr),
					zap.Stringer("targetAddress", tgtUDPAddr),
					zap.Error(err),
				)
				return onet.NewConnectionError("ERR_WRITE", "Failed to write to target", err)
			}

			return nil
		}()
	}
	return nil
}

// Decrypts src into dst. It tries each cipher until it finds one that authenticates
// correctly. dst and src must not overlap.
//
// For Shadowsocks 2022, a reference to the corresponding session is also returned.
// If the session does not currently exist, this function creates the session.
//
// ⚠️ Warning: The created session MUST also pass packet validation and sliding window filter,
// before it's safe to be added to the session table.
// Also do not update anything in the existing session before passing these tests.
func (s *udpService) findAccessKeyUDP(clientAddr *net.UDPAddr, dst, src []byte, nm *natmap) ([]byte, string, *ss.Cipher, uint64, *session, bool, error) {
	// Try each cipher until we find one that authenticates successfully. This assumes that all ciphers are AEAD.
	// We snapshot the list because it may be modified while we use it.
	snapshot := s.ciphers.SnapshotForClientIP(clientAddr.IP)

	for ci, entry := range snapshot {
		id, c := entry.Value.(*CipherEntry).ID, entry.Value.(*CipherEntry).Cipher

		buf, sid, ses, isNewSession, err := decryptAndGetOrCreateSession(id, c, clientAddr, dst, src, nil, nm)
		if err != nil {
			continue
		}

		logger.Debug("Found cipher entry",
			zap.Int("index", ci),
			zap.String("id", id),
		)
		// Move the active cipher to the front, so that the search is quicker next time.
		s.ciphers.MarkUsedByClientIP(entry, clientAddr.IP)
		return buf, id, c, sid, ses, isNewSession, nil
	}

	return nil, "", nil, 0, nil, false, errors.New("could not find a valid cipher")
}

// decryptAndGetOrCreateSession decrypts the packet and gets or creates its session.
// When called by findAccessKeyUDP, dst and src do not overlap, separateHeader must be nil,
// so we allocate a temporary slice to store the decrypted separate header.
// When called by Serve, dst is nil. separateHeader must point to src[:16] so an in-place decryption is done on the buffer.
func decryptAndGetOrCreateSession(id string, c *ss.Cipher, clientAddr *net.UDPAddr, dst, src, separateHeader []byte, nm *natmap) (buf []byte, csid uint64, ses *session, isNewSession bool, onetErr *onet.ConnectionError) {
	var err error
	cipherConfig := c.Config()

	switch {
	case cipherConfig.UDPHasSeparateHeader:
		if separateHeader == nil {
			separateHeader = make([]byte, 16)
		}

		// Decrypt separate header
		err = ss.DecryptSeparateHeader(c, separateHeader, src)
		if err != nil {
			onetErr = onet.NewConnectionError("ERR_CIPHER", "Failed to decrypt separate header", err)
			return
		}

		// Look up session table to see if we already have an AEAD instance for this session.
		csid = binary.BigEndian.Uint64(separateHeader)
		ses = nm.GetByClientSessionID(csid)
		isNewSession = ses == nil
		if isNewSession {
			var caead cipher.AEAD
			caead, err = c.NewAEAD(separateHeader[:8])
			if err != nil {
				onetErr = onet.NewConnectionError("ERR_CIPHER", "Failed to create client AEAD", err)
				return
			}

			ssid := make([]byte, 8)
			_, err = rand.Read(ssid)
			if err != nil {
				onetErr = onet.NewConnectionError("ERR_CIPHER", "Failed to generate random server session ID", err)
				return
			}

			var saead cipher.AEAD
			saead, err = c.NewAEAD(ssid)
			if err != nil {
				onetErr = onet.NewConnectionError("ERR_CIPHER", "Failed to create server AEAD", err)
				return
			}

			// Create session.
			ses = newSession(separateHeader[:8], ssid, caead, saead, clientAddr)
		}

		buf, err = ss.UnpackAesWithSeparateHeader(dst, src, separateHeader, c, ses.caead)
		if err != nil {
			onetErr = onet.NewConnectionError("ERR_CIPHER", "Failed to unpack", err)
			return
		}

	case cipherConfig.IsSpec2022:
		_, buf, err = ss.Unpack(dst, src, c)
		if err != nil {
			onetErr = onet.NewConnectionError("ERR_CIPHER", "Failed to unpack", err)
			return
		}

		csid = binary.BigEndian.Uint64(buf[:8])
		ses = nm.GetByClientSessionID(csid)
		isNewSession = ses == nil
		if isNewSession {
			ssid := make([]byte, 8)
			_, err = rand.Read(ssid)
			if err != nil {
				onetErr = onet.NewConnectionError("ERR_CIPHER", "Failed to generate random server session ID", err)
				return
			}
			ses = newSession(buf[:8], ssid, nil, nil, clientAddr)
		}

	default:
		_, buf, err = ss.Unpack(dst, src, c)
		if err != nil {
			onetErr = onet.NewConnectionError("ERR_CIPHER", "Failed to unpack", err)
			return
		}
	}

	return
}

// Given the decrypted contents of a UDP packet, return
// the payload and the destination address, or an error if
// this packet cannot or should not be forwarded.
func (s *udpService) validatePacket(textData []byte, cipherConfig ss.CipherConfig, clientAddr, clientLocalAddr *net.UDPAddr, clientLocation string, sid uint64, ses *session, isNewSession bool, nm *natmap) ([]byte, *net.UDPAddr, *onet.ConnectionError) {
	_, socksAddr, payload, err := ss.ParseUDPHeader(textData, ss.HeaderTypeClientPacket, nil, cipherConfig)
	if err != nil {
		logger.Warn("Failed to parse header",
			zap.Stringer("clientAddress", clientAddr),
			zap.Stringer("clientConnLocalAddress", clientLocalAddr),
			zap.String("clientLocation", clientLocation),
			zap.Error(err),
		)
		return nil, nil, onet.NewConnectionError("ERR_READ_HEADER", "Failed to read packet header", err)
	}

	tgtUDPAddr, err := socksAddr.UDPAddr()
	if err != nil {
		logger.Warn("Failed to resolve UDPAddr",
			zap.Stringer("clientAddress", clientAddr),
			zap.Stringer("clientConnLocalAddress", clientLocalAddr),
			zap.Stringer("targetAddress", socksAddr),
			zap.Error(err),
		)
		return nil, nil, onet.NewConnectionError("ERR_RESOLVE_ADDRESS", fmt.Sprintf("Failed to resolve target address %v", socksAddr.String()), err)
	}
	if s.targetIPValidator != nil {
		if err := s.targetIPValidator(tgtUDPAddr.IP); err != nil {
			logger.Debug("Rejected target IP", zap.Stringer("targetAddress", tgtUDPAddr), zap.Error(err.Cause))
			return nil, nil, err
		}
	}

	// For Shadowsocks 2022 Edition, we now have a decrypted packet.
	//
	// We have figured out whether this packet belongs to a new session
	// that we might need to add to the session table, or there's a network change
	// and the packet belongs to an existing session that we might need to update.
	//
	// The content of the packet has been authenticated by AEAD.
	// The header has been validated. Packets with bad timestamps have been thrown away.
	//
	// So now we just have to pass the final sliding window filter test,
	// then we can add the session to the session table, or update the session info,
	// and try to use the existing infrastructure of natconn to relay packets.
	if cipherConfig.IsSpec2022 {
		// Check against sliding window filter.
		// For new sessions, this means the received packet is checked into the filter.
		pid := binary.BigEndian.Uint64(textData[8:])

		if !ses.cfilter.ValidateCounter(pid, math.MaxUint64) {
			logger.Warn("Detected replay: repeated packet ID",
				zap.Stringer("clientAddress", clientAddr),
				zap.Stringer("clientConnLocalAddress", clientLocalAddr),
				zap.String("clientLocation", clientLocation),
				zap.Stringer("targetAddress", socksAddr),
				zap.Uint64("pid", pid),
				zap.Error(err),
			)
			return nil, nil, onet.NewConnectionError("ERR_PACKET_REPLAY", "Detected packet replay", nil)
		}

		// Update existing session or add new session to table.
		if isNewSession {
			nm.AddSession(sid, ses)
		} else {
			ses.lastSeenAddr = clientAddr
		}
	}

	return payload, tgtUDPAddr, nil
}

func (s *udpService) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopped = true
	if s.clientConn == nil {
		return nil
	}
	return s.clientConn.Close()
}

func (s *udpService) GracefulStop() error {
	err := s.Stop()
	s.running.Wait()
	return err
}
