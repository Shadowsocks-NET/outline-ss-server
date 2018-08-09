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
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/Jigsaw-Code/outline-ss-server/metrics"

	"sync"

	"github.com/shadowsocks/go-shadowsocks2/shadowaead"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

type mode int

const udpBufSize = 64 * 1024

// upack decripts src into dst. It tries each cipher until it finds one that authenticates
// correctly. dst and src must not overlap.
func unpack(dst, src []byte, ciphers map[string]shadowaead.Cipher) ([]byte, string, shadowaead.Cipher, error) {
	for id, cipher := range ciphers {
		log.Printf("Trying UDP cipher %v", id)
		buf, err := shadowaead.Unpack(dst, src, cipher)
		if err != nil {
			log.Printf("Failed UDP cipher %v: %v", id, err)
			continue
		}
		log.Printf("Selected UDP cipher %v", id)
		return buf, id, cipher, nil
	}
	return nil, "", nil, errors.New("could not find valid cipher")
}

// Listen on addr for encrypted packets and basically do UDP NAT.
func udpRemote(clientConn net.PacketConn, ciphers map[string]shadowaead.Cipher, m metrics.ShadowsocksMetrics) {
	defer clientConn.Close()

	nm := newNATmap(config.UDPTimeout, m)
	cipherBuf := make([]byte, udpBufSize)
	textBuf := make([]byte, udpBufSize)

	for {
		func() (connError *connectionError) {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("ERROR Panic in UDP loop: %v", r)
				}
			}()
			keyID := ""
			var clientProxyBytes, proxyTargetBytes int
			defer func() {
				status := "OK"
				if connError != nil {
					log.Printf("ERROR [UDP]: %v: %v", connError.message, connError.cause)
					status = connError.status
				}
				m.AddClientUDPPacket(keyID, status, clientProxyBytes, proxyTargetBytes)
			}()
			clientProxyBytes, clientAddr, err := clientConn.ReadFrom(cipherBuf)
			if err != nil {
				return &connectionError{"ERR_READ", "Failed to read from client", err}
			}
			defer log.Printf("UDP done with %v", clientAddr.String())
			log.Printf("Request from %v with %v bytes", clientAddr, clientProxyBytes)
			buf, keyID, cipher, err := unpack(textBuf, cipherBuf[:clientProxyBytes], ciphers)
			if err != nil {
				return &connectionError{"ERR_CIPHER", "Failed to upack data from client", err}
			}

			tgtAddr := socks.SplitAddr(buf)
			if tgtAddr == nil {
				return &connectionError{"ERR_READ_ADDRESS", "Failed to get target address", nil}
			}

			tgtUDPAddr, err := net.ResolveUDPAddr("udp", tgtAddr.String())
			if err != nil {
				return &connectionError{"ERR_RESOLVE_ADDRESS", fmt.Sprintf("Failed to resolve target address %v", tgtAddr.String()), err}
			}

			payload := buf[len(tgtAddr):]

			targetConn := nm.Get(clientAddr.String())
			if targetConn == nil {
				targetConn, err = net.ListenPacket("udp", "")
				if err != nil {
					return &connectionError{"ERR_CREATE_SOCKET", "Failed to create UDP socket", err}
				}
				// TODO: Add metrics for UDP traffic from target
				nm.Add(clientAddr, clientConn, cipher, targetConn, keyID)
			}
			log.Printf("DEBUG UDP Nat: client %v <-> proxy exit %v", clientAddr, targetConn.LocalAddr())

			proxyTargetBytes, err = targetConn.WriteTo(payload, tgtUDPAddr) // accept only UDPAddr despite the signature
			if err != nil {
				return &connectionError{"ERR_WRITE", "Failed to write to target", err}
			}
			return nil
		}()
	}
}

// Packet NAT table
type natmap struct {
	sync.RWMutex
	keyConn map[string]net.PacketConn
	timeout time.Duration
	metrics metrics.ShadowsocksMetrics
}

func newNATmap(timeout time.Duration, sm metrics.ShadowsocksMetrics) *natmap {
	m := &natmap{metrics: sm}
	m.keyConn = make(map[string]net.PacketConn)
	m.timeout = timeout
	return m
}

func (m *natmap) Get(key string) net.PacketConn {
	m.RLock()
	defer m.RUnlock()
	return m.keyConn[key]
}

func (m *natmap) set(key string, pc net.PacketConn) {
	m.Lock()
	defer m.Unlock()

	m.keyConn[key] = pc
}

func (m *natmap) del(key string) net.PacketConn {
	m.Lock()
	defer m.Unlock()

	pc, ok := m.keyConn[key]
	if ok {
		delete(m.keyConn, key)
		return pc
	}
	return nil
}

func (m *natmap) Add(clientAddr net.Addr, clientConn net.PacketConn, cipher shadowaead.Cipher, targetConn net.PacketConn, keyID string) {
	m.set(clientAddr.String(), targetConn)

	m.metrics.AddUdpNatEntry()
	go func() {
		timedCopy(clientAddr, clientConn, cipher, targetConn, m.timeout, keyID, m.metrics)
		m.metrics.RemoveUdpNatEntry()
		if pc := m.del(clientAddr.String()); pc != nil {
			pc.Close()
		}
	}()
}

// copy from src to dst at target with read timeout
func timedCopy(clientAddr net.Addr, clientConn net.PacketConn, cipher shadowaead.Cipher, targetConn net.PacketConn,
	timeout time.Duration, keyID string, sm metrics.ShadowsocksMetrics) {
	textBuf := make([]byte, udpBufSize)
	cipherBuf := make([]byte, udpBufSize)

	for {
		err := func() (connError *connectionError) {
			var targetProxyBytes, proxyClientBytes int
			defer func() {
				status := "OK"
				if connError != nil {
					log.Printf("ERROR [UDP]: %v: %v", connError.message, connError.cause)
					status = connError.status
				}
				sm.AddTargetUDPPacket(keyID, status, targetProxyBytes, proxyClientBytes)
			}()
			targetConn.SetReadDeadline(time.Now().Add(timeout))
			targetProxyBytes, raddr, err := targetConn.ReadFrom(textBuf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok {
					if netErr.Timeout() {
						return nil
					}
				}
				return &connectionError{"ERR_READ", "Failed to read from target", err}
			}

			srcAddr := socks.ParseAddr(raddr.String())
			log.Printf("DEBUG UDP response from %v to %v", srcAddr, clientAddr)
			// Shift data buffer to prepend with srcAddr.
			copy(textBuf[len(srcAddr):], textBuf[:targetProxyBytes])
			copy(textBuf, srcAddr)

			buf, err := shadowaead.Pack(cipherBuf, textBuf[:len(srcAddr)+targetProxyBytes], cipher)
			if err != nil {
				return &connectionError{"ERR_PACK", "Failed to pack data to client", err}
			}
			proxyClientBytes, err = clientConn.WriteTo(buf, clientAddr)
			if err != nil {
				return &connectionError{"ERR_WRITE", "Failed to write to client", err}
			}
			return nil
		}()
		if err == nil {
			break
		}
	}
}
