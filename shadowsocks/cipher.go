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
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// SuportedCipherNames lists the names of the AEAD ciphers that are supported.
func SuportedCipherNames() []string {
	names := make([]string, len(supportedAEADs))
	for i, spec := range supportedAEADs {
		names[i] = spec.name
	}
	return names
}

type aeadSpec struct {
	name        string
	newInstance func(key []byte) (cipher.AEAD, error)
	keySize     int
	tagSize     int
}

// List of supported AEAD ciphers, as specified at https://shadowsocks.org/en/spec/AEAD-Ciphers.html
var supportedAEADs = [...]aeadSpec{
	newAEADSpec("chacha20-ietf-poly1305", chacha20poly1305.New, chacha20poly1305.KeySize),
	newAEADSpec("aes-256-gcm", newAesGCM, 32),
	newAEADSpec("aes-192-gcm", newAesGCM, 24),
	newAEADSpec("aes-128-gcm", newAesGCM, 16),
}

func newAEADSpec(name string, newInstance func(key []byte) (cipher.AEAD, error), keySize int) aeadSpec {
	dummyAead, err := newInstance(make([]byte, keySize))
	if err != nil {
		panic(fmt.Sprintf("Failed to initialize AEAD %v", name))
	}
	return aeadSpec{name, newInstance, keySize, dummyAead.Overhead()}
}

func getAEADSpec(name string) (*aeadSpec, error) {
	name = strings.ToLower(name)
	for _, aeadSpec := range supportedAEADs {
		if aeadSpec.name == name {
			return &aeadSpec, nil
		}
	}
	return nil, fmt.Errorf("Unknown cipher %v", name)
}

func newAesGCM(key []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// Cipher encapsulates a Shadowsocks AEAD spec and a secret
type Cipher struct {
	aead   aeadSpec
	secret []byte
}

// SaltSize is the size of the salt for this Cipher
func (c *Cipher) SaltSize() int {
	return c.aead.keySize
}

// TagSize is the size of the AEAD tag for this Cipher
func (c *Cipher) TagSize() int {
	return c.aead.tagSize
}

var subkeyInfo = []byte("ss-subkey")

// NewAEAD creates the AEAD for this cipher
func (c *Cipher) NewAEAD(salt []byte) (cipher.AEAD, error) {
	sessionKey := make([]byte, c.aead.keySize)
	r := hkdf.New(sha1.New, c.secret, salt, subkeyInfo)
	if _, err := io.ReadFull(r, sessionKey); err != nil {
		return nil, err
	}
	return c.aead.newInstance(sessionKey)
}

// NewCipher creates a Cipher given a cipher name and a secret
func NewCipher(cipherName string, secretText string) (*Cipher, error) {
	secret := []byte(secretText)
	aeadSpec, err := getAEADSpec(cipherName)
	if err != nil {
		return nil, err
	}
	return &Cipher{*aeadSpec, secret}, nil
}

// Assumes all ciphers have NonceSize() <= 12.
var zeroNonce [12]byte

// DecryptOnce will decrypt the cipherText using the cipher and salt, appending the output to plainText.
func DecryptOnce(cipher *Cipher, salt []byte, plainText, cipherText []byte) ([]byte, error) {
	aead, err := cipher.NewAEAD(salt)
	if err != nil {
		return nil, err
	}
	if len(cipherText) < aead.Overhead() {
		return nil, io.ErrUnexpectedEOF
	}
	if cap(plainText)-len(plainText) < len(cipherText)-aead.Overhead() {
		return nil, io.ErrShortBuffer
	}
	return aead.Open(plainText, zeroNonce[:aead.NonceSize()], cipherText, nil)
}
