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
	"fmt"
	"net"
	"testing"

	logging "github.com/op/go-logging"
	"github.com/shadowsocks/go-shadowsocks2/core"
	"github.com/shadowsocks/go-shadowsocks2/shadowaead"
)

func BenchmarkFindCipher(b *testing.B) {
	b.StopTimer()
	b.ResetTimer()

	logging.SetLevel(logging.INFO, "")
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		b.Fatalf("ListenTCP failed: %v", err)
	}

	const numCiphers = 100
	cipherList := make(map[string]shadowaead.Cipher)
	for i := 0; i < numCiphers; i++ {
		cipherID := fmt.Sprintf("id-%v", i)
		secret := fmt.Sprintf("secret-%v", i)
		cipher, err := core.PickCipher("chacha20-ietf-poly1305", nil, secret)
		if err != nil {
			b.Fatalf("Failed to create cipher %v: %v", i, err)
		}
		cipherList[cipherID] = cipher.(shadowaead.Cipher)
	}

	testPayload := []byte{
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
		21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
		41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60}

	for n := 0; n < b.N; n++ {
		go func() {
			conn, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				b.Fatalf("Failed to dial %v: %v", listener.Addr(), err)
			}
			conn.Write(testPayload)
			conn.Close()
		}()
		clientConn, err := listener.AcceptTCP()
		if err != nil {
			b.Fatalf("AcceptTCP failed: %v", err)
		}
		b.StartTimer()
		findAccessKey(clientConn, cipherList)
		b.StopTimer()
	}
}
