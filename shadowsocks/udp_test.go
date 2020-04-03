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
	"net"
	"testing"

	logging "github.com/op/go-logging"
	"github.com/shadowsocks/go-shadowsocks2/shadowaead"
)

// Simulates receiving invalid UDP packets on a server with 100 ciphers.
func BenchmarkUDPUnpackFail(b *testing.B) {
	logging.SetLevel(logging.INFO, "")

	cipherList, _, err := MakeTestCiphers(100)
	if err != nil {
		b.Fatal(err)
	}
	testPayload := MakeTestPayload(50)
	textBuf := make([]byte, udpBufSize)
	testIP := net.ParseIP("192.0.2.1")
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		unpack(testIP, textBuf, testPayload, cipherList)
	}
}

// Simulates receiving valid UDP packets from 100 different users, each with
// their own cipher and IP address.
func BenchmarkUDPUnpackRepeat(b *testing.B) {
	logging.SetLevel(logging.INFO, "")

	const numCiphers = 100 // Must be <256
	cipherList, _, err := MakeTestCiphers(numCiphers)
	if err != nil {
		b.Fatal(err)
	}
	testBuf := make([]byte, udpBufSize)
	packets := [numCiphers][]byte{}
	ips := [numCiphers]net.IP{}
	for i, element := range cipherList.SnapshotForClientIP(nil) {
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
		_, _, _, err := unpack(ip, testBuf, packet, cipherList)
		if err != nil {
			b.Error(err)
		}
	}
}

// Simulates receiving valid UDP packets from 100 different IP addresses,
// all using the same cipher.
func BenchmarkUDPUnpackSharedKey(b *testing.B) {
	logging.SetLevel(logging.INFO, "")

	cipherList, _, err := MakeTestCiphers(1) // One widely shared key
	if err != nil {
		b.Fatal(err)
	}
	testBuf := make([]byte, udpBufSize)
	plaintext := MakeTestPayload(50)
	cipher := cipherList.SnapshotForClientIP(nil)[0].Value.(*CipherEntry).Cipher
	packet, err := shadowaead.Pack(make([]byte, udpBufSize), plaintext, cipher)

	const numIPs = 100 // Must be <256
	ips := [numIPs]net.IP{}
	for i := 0; i < numIPs; i++ {
		ips[i] = net.IPv4(192, 0, 2, byte(i))
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		ip := ips[n%numIPs]
		_, _, _, err := unpack(ip, testBuf, packet, cipherList)
		if err != nil {
			b.Error(err)
		}
	}
}
