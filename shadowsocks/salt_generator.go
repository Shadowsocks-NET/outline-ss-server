// Copyright 2020 Jigsaw Operations LLC
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
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/shadowsocks/go-shadowsocks2/shadowaead"
	"golang.org/x/crypto/hkdf"
)

// SaltGenerator generates unique salts to use in Shadowsocks connections.
type SaltGenerator interface {
	// Returns a new salt
	GetSalt(salt []byte) error
}

type ServerSaltGenerator interface {
	SaltGenerator
	// IsServerSalt returns true if the salt was created by this generator
	// and is marked as server-originated.
	IsServerSalt(salt []byte) bool
}

// randomSaltGenerator generates a new random salt.
type randomSaltGenerator struct{}

// GetSalt outputs a random salt.
func (randomSaltGenerator) GetSalt(salt []byte) error {
	_, err := rand.Read(salt)
	return err
}

func (randomSaltGenerator) IsServerSalt(salt []byte) bool {
	return false
}

// RandomSaltGenerator is a basic SaltGenerator.
var RandomSaltGenerator ServerSaltGenerator = randomSaltGenerator{}

// serverSaltGenerator generates unique salts that are secretly marked.
type serverSaltGenerator struct {
	saltSize int
	key      []byte
}

// Number of bytes of salt to use as a marker.  Increasing this value reduces
// the false positive rate, but increases the likelihood of salt collisions.
// Must be less than or equal to the cipher overhead.
const markLen = 4

// For a random salt to be secure, it needs at least 16 bytes (128 bits) of
// entropy.  If adding the mark would reduce the entropy below this level,
// we generate an unmarked random salt.
const minEntropy = 16

// Constant to identify this marking scheme.
var serverSaltLabel = []byte("outline-server-salt")

// NewServerSaltGenerator returns a SaltGenerator whose output is apparently
// random, but is secretly marked as being issued by the server.
// This is useful to prevent the server from accepting its own output in a
// reflection attack.
func NewServerSaltGenerator(cipher shadowaead.Cipher, secret string) ServerSaltGenerator {
	if cipher.SaltSize()-markLen < minEntropy {
		// This cipher doesn't support server marking.
		return RandomSaltGenerator
	}

	// Shadowsocks already uses HKDF-SHA1 to derive the AEAD key, so we use
	// the same derivation with a different "info" to generate our HMAC key.
	keySource := hkdf.New(crypto.SHA1.New, []byte(secret), nil, serverSaltLabel)
	// The key can be any size, but matching the block size is most efficient.
	key := make([]byte, crypto.SHA1.Size())
	io.ReadFull(keySource, key)
	return serverSaltGenerator{cipher.SaltSize(), key}
}

func (sg serverSaltGenerator) splitSalt(salt []byte) (prefix, mark []byte) {
	prefixLen := len(salt) - markLen
	return salt[:prefixLen], salt[prefixLen:]
}

// getTag takes in a salt prefix and returns the tag.
func (sg serverSaltGenerator) getTag(prefix []byte) []byte {
	// Use HMAC-SHA1, even though SHA1 is broken, because HMAC-SHA1 is still
	// secure, and we're already using HKDF-SHA1.
	hmac := hmac.New(crypto.SHA1.New, sg.key)
	hmac.Write(prefix) // Hash.Write never returns an error.
	return hmac.Sum(nil)
}

// GetSalt returns an apparently random salt that can be identified
// as server-originated by anyone who knows the Shadowsocks key.
func (sg serverSaltGenerator) GetSalt(salt []byte) error {
	if len(salt) != sg.saltSize {
		return fmt.Errorf("Wrong salt size: %d != %d", len(salt), sg.saltSize)
	}
	prefix, mark := sg.splitSalt(salt)
	if _, err := rand.Read(prefix); err != nil {
		return err
	}
	tag := sg.getTag(prefix)
	copy(mark, tag)
	return nil
}

func (sg serverSaltGenerator) IsServerSalt(salt []byte) bool {
	if len(salt) != sg.saltSize {
		return false
	}
	prefix, mark := sg.splitSalt(salt)
	tag := sg.getTag(prefix)
	return bytes.Equal(tag[:markLen], mark)
}
