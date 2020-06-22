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
	"math"
	"net"
	"sync"

	"github.com/shadowsocks/go-shadowsocks2/shadowaead"
)

// All ciphers must have a nonce size this big or smaller.
const maxNonceSize = 12

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
	// Returns a snapshot of the cipher list optimized for this client IP,
	// and also the number of bytes needed for TCP trial decryption.
	SnapshotForClientIP(clientIP net.IP) (int, []*list.Element)
	MarkUsedByClientIP(e *list.Element, clientIP net.IP)
	// Update replaces the current contents of the CipherList with `contents`,
	// which is a List of *CipherEntry.  Update takes ownership of `contents`,
	// which must not be read or written after this call.
	Update(contents *list.List) error
}

type cipherList struct {
	CipherList
	list         *list.List
	mu           sync.RWMutex
	tcpTrialSize int
}

// NewCipherList creates an empty CipherList
func NewCipherList() CipherList {
	return &cipherList{list: list.New()}
}

func matchesIP(e *list.Element, clientIP net.IP) bool {
	c := e.Value.(*CipherEntry)
	return clientIP != nil && clientIP.Equal(c.lastClientIP)
}

func (cl *cipherList) SnapshotForClientIP(clientIP net.IP) (int, []*list.Element) {
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
	return cl.tcpTrialSize, cipherArray
}

func (cl *cipherList) MarkUsedByClientIP(e *list.Element, clientIP net.IP) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	cl.list.MoveToFront(e)

	c := e.Value.(*CipherEntry)
	c.lastClientIP = clientIP
}

func tcpHeaderBounds(cipher shadowaead.Cipher) (requires, provides int, err error) {
	saltSize := cipher.SaltSize()

	aead, err := cipher.Decrypter(make([]byte, saltSize))
	if err != nil {
		return
	}

	if aead.NonceSize() > maxNonceSize {
		err = fmt.Errorf("Cipher has oversize nonce: %v", cipher)
		return
	}
	overhead := aead.Overhead()

	// We need at least this many bytes to assess whether a TCP stream corresponds
	// to this cipher.
	requires = saltSize + 2 + overhead
	// Any TCP stream for this cipher will deliver at least this many bytes before
	// requiring the proxy to act.
	provides = requires + overhead
	return
}

func (cl *cipherList) Update(src *list.List) error {
	maxRequired := 0
	minProvided := int(math.MaxInt32) // Very large initial value
	for e := src.Front(); e != nil; e = e.Next() {
		cipher := e.Value.(*CipherEntry).Cipher
		requires, provides, err := tcpHeaderBounds(cipher)
		if err != nil {
			return err
		}

		if requires > maxRequired {
			maxRequired = requires
		}
		if provides < minProvided {
			minProvided = provides
		}
	}
	if maxRequired > minProvided {
		return fmt.Errorf("List contains incompatible ciphers: %d > %d", maxRequired, minProvided)
	}

	cl.mu.Lock()
	cl.list = src
	cl.tcpTrialSize = maxRequired
	cl.mu.Unlock()
	return nil
}
