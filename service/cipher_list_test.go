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
	"container/list"
	"crypto/cipher"
	"math/rand"
	"net"
	"testing"

	ss "github.com/Jigsaw-Code/outline-ss-server/shadowsocks"
	"github.com/shadowsocks/go-shadowsocks2/shadowaead"
)

type fakeAEAD struct {
	cipher.AEAD
	overhead, nonceSize int
}

func (a *fakeAEAD) NonceSize() int {
	return a.nonceSize
}

func (a *fakeAEAD) Overhead() int {
	return a.overhead
}

type fakeCipher struct {
	shadowaead.Cipher
	saltsize  int
	decrypter *fakeAEAD
}

func (c *fakeCipher) SaltSize() int {
	return c.saltsize
}

func (c *fakeCipher) Decrypter(b []byte) (cipher.AEAD, error) {
	return c.decrypter, nil
}

func TestIncompatibleCiphers(t *testing.T) {
	l := list.New()
	l.PushBack(&CipherEntry{
		ID:     "short",
		Cipher: &fakeCipher{saltsize: 5, decrypter: &fakeAEAD{overhead: 3}}})
	l.PushBack(&CipherEntry{ID: "long", Cipher: &fakeCipher{saltsize: 50, decrypter: &fakeAEAD{overhead: 30}}})
	cipherList := NewCipherList()
	err := cipherList.Update(l)
	if err == nil {
		t.Error("Expected Update to fail due to incompatible ciphers")
	}
}

func TestMaxNonceSize(t *testing.T) {
	l := list.New()
	l.PushBack(&CipherEntry{
		ID:     "oversize nonce",
		Cipher: &fakeCipher{saltsize: 5, decrypter: &fakeAEAD{overhead: 3, nonceSize: 13}}})
	l.PushBack(&CipherEntry{ID: "long", Cipher: &fakeCipher{saltsize: 50, decrypter: &fakeAEAD{overhead: 30}}})
	cipherList := NewCipherList()
	err := cipherList.Update(l)
	if err == nil {
		t.Error("Expected Update to fail due to oversize nonce")
	}
}

func TestCompatibleCiphers(t *testing.T) {
	chacha20, _ := shadowaead.Chacha20Poly1305(make([]byte, 32))
	aes128, _ := shadowaead.AESGCM(make([]byte, 16))
	l := list.New()
	l.PushBack(&CipherEntry{ID: "aes128", Cipher: aes128})
	l.PushBack(&CipherEntry{ID: "chacha20", Cipher: chacha20})
	cipherList := NewCipherList()
	err := cipherList.Update(l)
	if err != nil {
		t.Error(err)
	}
}

func BenchmarkLocking(b *testing.B) {
	var ip net.IP

	ciphers, _ := MakeTestCiphers(ss.MakeTestSecrets(1))
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, entries := ciphers.SnapshotForClientIP(nil)
			ciphers.MarkUsedByClientIP(entries[0], ip)
		}
	})
}

func BenchmarkSnapshot(b *testing.B) {
	// Create a list of cipher entries in a random order.

	// Small cipher lists (N~1e3) fit entirely in cache, and are ~10 times
	// faster to copy (per entry) than very large cipher lists (N~1e5).
	const N = 1e3
	ciphers, _ := MakeTestCiphers(ss.MakeTestSecrets(N))

	// Shuffling simulates the behavior of a real server, where successive
	// ciphers are not expected to be nearby in memory.
	_, entries := ciphers.SnapshotForClientIP(nil)
	rand.Shuffle(N, func(i, j int) {
		entries[i], entries[j] = entries[j], entries[i]
	})
	for _, entry := range entries {
		// Reorder the list to match the shuffle
		// (actually in reverse, but it doesn't matter).
		ciphers.MarkUsedByClientIP(entry, nil)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			ciphers.SnapshotForClientIP(nil)
		}
	})
}
