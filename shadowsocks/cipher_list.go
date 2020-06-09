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
	"container/list"
	"fmt"
	"net"
	"sync"

	"github.com/shadowsocks/go-shadowsocks2/shadowaead"
)

// All ciphers must have a nonce size this big or smaller.
const maxNonceSize = 12

// Describes the size parameters of a cipher.
type cipherSize struct {
	salt, overhead int
}

// These are cipher size parameters supported by CipherList.
// To support TCP trial decryption, these sizes must not include
// too wide a range.  Otherwise, trial decryption for a large-size
// cipher could block indefinitely, when the client has actually
// sent a handshake for a short cipher.
//
// Ciphers do not need to have exactly the same size because a minimal
// handshake (from a short cipher) includes at least one additional
// AEAD tag, providing enough bytes for trial decryption with a
// longer cipher.
var supportedSizes = [...]cipherSize{
	{32, 16}, // chacha20poly1305, AES-256-GCM
	{24, 16}, // AES-192-GCM
	{16, 16}, // AES-128-GCM
}

// Minimum number of bytes to read for trial decryption of all supported
// ciphers.
var tcpHeader int

func init() {
	for _, s := range supportedSizes {
		t := s.salt + 2 + s.overhead
		if t > tcpHeader {
			tcpHeader = t
		}
	}
}

// CheckCipher checks whether the provided cipher is compatible with CipherList.
func CheckCipher(cipher shadowaead.Cipher) error {
	saltsize := cipher.SaltSize()
	aead, err := cipher.Decrypter(make([]byte, saltsize))
	if err != nil {
		return err
	}

	if aead.NonceSize() > maxNonceSize {
		return fmt.Errorf("Nonce size is too large: %d > %d", aead.NonceSize(), maxNonceSize)
	}
	size := cipherSize{saltsize, aead.Overhead()}

	for _, s := range supportedSizes {
		if s == size {
			return nil
		}
	}
	return fmt.Errorf("Unsupported cipher size: %v", size)
}

// CipherEntry holds a Cipher with an identifier.
// The public fields are constant, but lastAddress is mutable under cipherList.mu.
type CipherEntry struct {
	ID           string
	Cipher       shadowaead.Cipher
	lastClientIP net.IP
}

// CipherList is a thread-safe collection of CipherEntry elements that allows for
// snapshotting and moving to front.
type CipherList interface {
	SnapshotForClientIP(clientIP net.IP) []*list.Element
	MarkUsedByClientIP(e *list.Element, clientIP net.IP)
	// Update replaces the current contents of the CipherList with `contents`,
	// which is a List of *CipherEntry.  Update takes ownership of `contents`,
	// which must not be read or written after this call.
	Update(contents *list.List)
}

type cipherList struct {
	CipherList
	list *list.List
	mu   sync.RWMutex
}

// NewCipherList creates an empty CipherList
func NewCipherList() CipherList {
	return &cipherList{list: list.New()}
}

func matchesIP(e *list.Element, clientIP net.IP) bool {
	c := e.Value.(*CipherEntry)
	return clientIP != nil && clientIP.Equal(c.lastClientIP)
}

func (cl *cipherList) SnapshotForClientIP(clientIP net.IP) []*list.Element {
	cl.mu.RLock()
	defer cl.mu.RUnlock()
	cipherArray := make([]*list.Element, cl.list.Len())
	i := 0
	// First pass: put all ciphers with matching last known IP at the front.
	for e := cl.list.Front(); e != nil; e = e.Next() {
		if matchesIP(e, clientIP) {
			cipherArray[i] = e
			i++
		}
	}
	// Second pass: include all remaining ciphers in recency order.
	for e := cl.list.Front(); e != nil; e = e.Next() {
		if !matchesIP(e, clientIP) {
			cipherArray[i] = e
			i++
		}
	}
	return cipherArray
}

func (cl *cipherList) MarkUsedByClientIP(e *list.Element, clientIP net.IP) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	cl.list.MoveToFront(e)

	c := e.Value.(*CipherEntry)
	c.lastClientIP = clientIP
}

func (cl *cipherList) Update(src *list.List) {
	cl.mu.Lock()
	cl.list = src
	cl.mu.Unlock()
}
