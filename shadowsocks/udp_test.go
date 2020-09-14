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
	"net"
	"sync"
	"testing"
	"time"

	logging "github.com/op/go-logging"
	"github.com/shadowsocks/go-shadowsocks2/core"
	"github.com/shadowsocks/go-shadowsocks2/shadowaead"
)

const timeout = 5 * time.Minute

var clientAddr = net.UDPAddr{IP: []byte{192, 0, 2, 1}, Port: 12345}
var targetAddr = net.UDPAddr{IP: []byte{192, 0, 2, 2}, Port: 54321}
var dnsAddr = net.UDPAddr{IP: []byte{192, 0, 2, 3}, Port: 53}
var natCipher shadowaead.Cipher

func init() {
	logging.SetLevel(logging.INFO, "")
	coreCipher, _ := core.PickCipher(testCipher, nil, "test password")
	natCipher = coreCipher.(shadowaead.Cipher)
}

type packet struct {
	addr    net.Addr
	payload []byte
	err     error
}

type fakePacketConn struct {
	net.PacketConn
	send     chan packet
	recv     chan packet
	deadline time.Time
}

func makePacketConn() *fakePacketConn {
	return &fakePacketConn{
		send: make(chan packet, 1),
		recv: make(chan packet),
	}
}

func (conn *fakePacketConn) SetReadDeadline(deadline time.Time) error {
	conn.deadline = deadline
	return nil
}

func (conn *fakePacketConn) WriteTo(payload []byte, addr net.Addr) (int, error) {
	conn.send <- packet{addr, payload, nil}
	return len(payload), nil
}

func (conn *fakePacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	pkt, ok := <-conn.recv
	if !ok {
		return 0, nil, errors.New("Receive closed")
	}
	n := copy(buffer, pkt.payload)
	if n < len(pkt.payload) {
		return n, pkt.addr, errors.New("Buffer was too short")
	}
	return n, pkt.addr, pkt.err
}

func (conn *fakePacketConn) Close() error {
	close(conn.send)
	close(conn.recv)
	return nil
}

func assertAlmostEqual(t *testing.T, a, b time.Time) {
	delta := a.Sub(b)
	limit := 100 * time.Millisecond
	if delta > limit || -delta > limit {
		t.Errorf("Times are not close: %v, %v", a, b)
	}
}

func TestNATEmpty(t *testing.T) {
	nat := newNATmap(timeout, &probeTestMetrics{}, &sync.WaitGroup{})
	if nat.Get("foo") != nil {
		t.Error("Expected nil value from empty NAT map")
	}
}

func setup() (*fakePacketConn, *fakePacketConn, *natconn) {
	nat := newNATmap(timeout, &probeTestMetrics{}, &sync.WaitGroup{})
	clientConn := makePacketConn()
	targetConn := makePacketConn()
	nat.Add(&clientAddr, clientConn, natCipher, targetConn, "ZZ", "key id")
	entry := nat.Get(clientAddr.String())
	return clientConn, targetConn, entry
}

func TestNATGet(t *testing.T) {
	_, targetConn, entry := setup()
	if entry == nil {
		t.Fatal("Failed to find target conn")
	}
	if entry.PacketConn != targetConn {
		t.Error("Mismatched connection returned")
	}
}

func TestNATWrite(t *testing.T) {
	_, targetConn, entry := setup()

	// Simulate one generic packet being sent
	buf := []byte{1}
	entry.WriteTo([]byte{1}, &targetAddr)
	assertAlmostEqual(t, targetConn.deadline, time.Now().Add(timeout))
	sent := <-targetConn.send
	if !bytes.Equal(sent.payload, buf) {
		t.Errorf("Mismatched payload: %v != %v", sent.payload, buf)
	}
	if sent.addr != &targetAddr {
		t.Errorf("Mismatched address: %v != %v", sent.addr, &targetAddr)
	}
}

func TestNATWriteDNS(t *testing.T) {
	_, targetConn, entry := setup()

	// Simulate one DNS query being sent.
	buf := []byte{1}
	entry.WriteTo(buf, &dnsAddr)
	// DNS-only connections have a fixed timeout of 17 seconds.
	assertAlmostEqual(t, targetConn.deadline, time.Now().Add(17*time.Second))
	sent := <-targetConn.send
	if !bytes.Equal(sent.payload, buf) {
		t.Errorf("Mismatched payload: %v != %v", sent.payload, buf)
	}
	if sent.addr != &dnsAddr {
		t.Errorf("Mismatched address: %v != %v", sent.addr, &targetAddr)
	}
}

func TestNATWriteDNSMultiple(t *testing.T) {
	_, targetConn, entry := setup()

	// Simulate three DNS queries being sent.
	buf := []byte{1}
	entry.WriteTo(buf, &dnsAddr)
	<-targetConn.send
	entry.WriteTo(buf, &dnsAddr)
	<-targetConn.send
	entry.WriteTo(buf, &dnsAddr)
	<-targetConn.send
	// DNS-only connections have a fixed timeout of 17 seconds.
	assertAlmostEqual(t, targetConn.deadline, time.Now().Add(17*time.Second))
}

func TestNATWriteMixed(t *testing.T) {
	_, targetConn, entry := setup()

	// Simulate both non-DNS and DNS packets being sent.
	buf := []byte{1}
	entry.WriteTo(buf, &targetAddr)
	<-targetConn.send
	entry.WriteTo(buf, &dnsAddr)
	<-targetConn.send
	// Mixed DNS and non-DNS connections should have the user-specified timeout.
	assertAlmostEqual(t, targetConn.deadline, time.Now().Add(timeout))
}

func TestNATFastClose(t *testing.T) {
	clientConn, targetConn, entry := setup()

	// Send one DNS query.
	query := []byte{1}
	entry.WriteTo(query, &dnsAddr)
	sent := <-targetConn.send
	// Send the response.
	response := []byte{1, 2, 3, 4, 5}
	received := packet{addr: &dnsAddr, payload: response}
	targetConn.recv <- received
	sent, ok := <-clientConn.send
	if !ok {
		t.Error("clientConn was closed")
	}
	if len(sent.payload) <= len(response) {
		t.Error("Packet is too short to be shadowsocks-AEAD")
	}
	if sent.addr != &clientAddr {
		t.Errorf("Address mismatch: %v != %v", sent.addr, clientAddr)
	}

	// targetConn should be scheduled to close immediately.
	assertAlmostEqual(t, targetConn.deadline, time.Now())
}

func TestNATNoFastClose_NotDNS(t *testing.T) {
	clientConn, targetConn, entry := setup()

	// Send one non-DNS packet.
	query := []byte{1}
	entry.WriteTo(query, &targetAddr)
	sent := <-targetConn.send
	// Send the response.
	response := []byte{1, 2, 3, 4, 5}
	received := packet{addr: &targetAddr, payload: response}
	targetConn.recv <- received
	sent, ok := <-clientConn.send
	if !ok {
		t.Error("clientConn was closed")
	}
	if len(sent.payload) <= len(response) {
		t.Error("Packet is too short to be shadowsocks-AEAD")
	}
	if sent.addr != &clientAddr {
		t.Errorf("Address mismatch: %v != %v", sent.addr, clientAddr)
	}
	// targetConn should be scheduled to close after the full timeout.
	assertAlmostEqual(t, targetConn.deadline, time.Now().Add(timeout))
}

func TestNATNoFastClose_MultipleDNS(t *testing.T) {
	clientConn, targetConn, entry := setup()

	// Send two DNS packets.
	query1 := []byte{1}
	entry.WriteTo(query1, &dnsAddr)
	<-targetConn.send
	query2 := []byte{2}
	entry.WriteTo(query2, &dnsAddr)
	<-targetConn.send

	// Send a response.
	response := []byte{1, 2, 3, 4, 5}
	received := packet{addr: &dnsAddr, payload: response}
	targetConn.recv <- received
	<-clientConn.send

	// targetConn should be scheduled to close after the DNS timeout.
	assertAlmostEqual(t, targetConn.deadline, time.Now().Add(17*time.Second))
}

// Implements net.Error
type fakeTimeoutError struct {
	error
}

func (e *fakeTimeoutError) Timeout() bool {
	return true
}

func (e *fakeTimeoutError) Temporary() bool {
	return false
}

func TestNATTimeout(t *testing.T) {
	_, targetConn, entry := setup()

	// Simulate a non-DNS initial packet.
	entry.WriteTo([]byte{1}, &targetAddr)
	<-targetConn.send
	// Simulate a read timeout.
	received := packet{err: &fakeTimeoutError{}}
	before := time.Now()
	targetConn.recv <- received
	// Wait for targetConn to close.
	if _, ok := <-targetConn.send; ok {
		t.Error("targetConn should be closed due to read timeout")
	}
	// targetConn should be closed as soon as the timeout error is received.
	assertAlmostEqual(t, before, time.Now())
}

// Simulates receiving invalid UDP packets on a server with 100 ciphers.
func BenchmarkUDPUnpackFail(b *testing.B) {
	cipherList, err := MakeTestCiphers(MakeTestSecrets(100))
	if err != nil {
		b.Fatal(err)
	}
	testPayload := MakeTestPayload(50)
	textBuf := make([]byte, udpBufSize)
	testIP := net.ParseIP("192.0.2.1")
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		findAccessKeyUDP(testIP, textBuf, testPayload, cipherList)
	}
}

// Simulates receiving valid UDP packets from 100 different users, each with
// their own cipher and IP address.
func BenchmarkUDPUnpackRepeat(b *testing.B) {
	const numCiphers = 100 // Must be <256
	cipherList, err := MakeTestCiphers(MakeTestSecrets(numCiphers))
	if err != nil {
		b.Fatal(err)
	}
	testBuf := make([]byte, udpBufSize)
	packets := [numCiphers][]byte{}
	ips := [numCiphers]net.IP{}
	_, snapshot := cipherList.SnapshotForClientIP(nil)
	for i, element := range snapshot {
		packets[i] = make([]byte, 0, udpBufSize)
		plaintext := MakeTestPayload(50)
		packets[i], err = shadowaead.Pack(make([]byte, udpBufSize), plaintext, element.Value.(*CipherEntry).Cipher)
		if err != nil {
			b.Error(err)
		}
		ips[i] = net.IPv4(192, 0, 2, byte(i))
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		cipherNumber := n % numCiphers
		ip := ips[cipherNumber]
		packet := packets[cipherNumber]
		_, _, _, err := findAccessKeyUDP(ip, testBuf, packet, cipherList)
		if err != nil {
			b.Error(err)
		}
	}
}

// Simulates receiving valid UDP packets from 100 different IP addresses,
// all using the same cipher.
func BenchmarkUDPUnpackSharedKey(b *testing.B) {
	cipherList, err := MakeTestCiphers(MakeTestSecrets(1)) // One widely shared key
	if err != nil {
		b.Fatal(err)
	}
	testBuf := make([]byte, udpBufSize)
	plaintext := MakeTestPayload(50)
	_, snapshot := cipherList.SnapshotForClientIP(nil)
	cipher := snapshot[0].Value.(*CipherEntry).Cipher
	packet, err := shadowaead.Pack(make([]byte, udpBufSize), plaintext, cipher)

	const numIPs = 100 // Must be <256
	ips := [numIPs]net.IP{}
	for i := 0; i < numIPs; i++ {
		ips[i] = net.IPv4(192, 0, 2, byte(i))
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		ip := ips[n%numIPs]
		_, _, _, err := findAccessKeyUDP(ip, testBuf, packet, cipherList)
		if err != nil {
			b.Error(err)
		}
	}
}

func TestUDPDoubleServe(t *testing.T) {
	cipherList, err := MakeTestCiphers(MakeTestSecrets(1))
	if err != nil {
		t.Fatal(err)
	}
	testMetrics := &probeTestMetrics{}
	const testTimeout = 200 * time.Millisecond
	s := NewUDPService(testTimeout, cipherList, testMetrics)

	c := make(chan error)
	for i := 0; i < 2; i++ {
		clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
		if err != nil {
			t.Fatalf("ListenUDP failed: %v", err)
		}
		go func() {
			err := s.Serve(clientConn)
			if err != nil {
				c <- err
				close(c)
			}
		}()
	}

	err = <-c
	if err == nil {
		t.Error("Expected an error from one of the two Serve calls")
	}

	if err := s.Stop(); err != nil {
		t.Error(err)
	}
}

func TestUDPEarlyStop(t *testing.T) {
	cipherList, err := MakeTestCiphers(MakeTestSecrets(1))
	if err != nil {
		t.Fatal(err)
	}
	testMetrics := &probeTestMetrics{}
	const testTimeout = 200 * time.Millisecond
	s := NewUDPService(testTimeout, cipherList, testMetrics)

	if err := s.Stop(); err != nil {
		t.Error(err)
	}
	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP failed: %v", err)
	}
	if err := s.Serve(clientConn); err != nil {
		t.Error(err)
	}
}
