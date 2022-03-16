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
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"lukechampine.com/blake3"
)

// SupportedCipherNames lists the names of the AEAD ciphers that are supported.
func SupportedCipherNames() []string {
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
	saltSize    int
	tagSize     int
}

// List of supported AEAD ciphers, as specified at https://shadowsocks.org/en/spec/AEAD-Ciphers.html
var supportedAEADs = [...]aeadSpec{
	newAEADSpec("chacha20-poly1305", chacha20poly1305.New, chacha20poly1305.KeySize, 32),
	newAEADSpec("aes-256-gcm", newAesGCM, 32, 32),
	newAEADSpec("aes-192-gcm", newAesGCM, 24, 24),
	newAEADSpec("aes-128-gcm", newAesGCM, 16, 16),
}

func newAEADSpec(name string, newInstance func(key []byte) (cipher.AEAD, error), keySize, saltSize int) aeadSpec {
	dummyAead, err := newInstance(make([]byte, keySize))
	if err != nil {
		panic(fmt.Sprintf("Failed to initialize AEAD %v", name))
	}
	return aeadSpec{name, newInstance, keySize, saltSize, dummyAead.Overhead()}
}

func newAesGCM(key []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

func maxTagSize() int {
	max := 0
	for _, spec := range supportedAEADs {
		if spec.tagSize > max {
			max = spec.tagSize
		}
	}
	return max
}

type CipherConfig struct {
	IsSpec2022           bool
	UDPHasSeparateHeader bool
}

// Cipher encapsulates a Shadowsocks AEAD spec and a secret
type Cipher struct {
	aead   aeadSpec
	secret []byte

	// spec 2022
	config CipherConfig
	// Only used by 2022-blake3-aes-256-gcm for encrypting/decrypting the separate header.
	separateHeaderCipher cipher.Block
	// Only used by 2022-blake3-chacha20-poly1305, initialized with the main key.
	// Packets with separate header should instead use the AEAD cipher in session.
	udpAEAD cipher.AEAD
}

// SaltSize is the size of the salt for this Cipher
func (c *Cipher) SaltSize() int {
	return c.aead.saltSize
}

// TagSize is the size of the AEAD tag for this Cipher
func (c *Cipher) TagSize() int {
	return c.aead.tagSize
}

func (c *Cipher) Config() CipherConfig {
	return c.config
}

// NewAEAD creates the AEAD for this cipher
func (c *Cipher) NewAEAD(salt []byte) (cipher.AEAD, error) {
	sessionKey := make([]byte, c.aead.keySize)
	if c.config.IsSpec2022 {
		keyMaterial := make([]byte, len(c.secret)+len(salt))
		copy(keyMaterial, c.secret)
		copy(keyMaterial[len(c.secret):], salt)
		blake3.DeriveKey(sessionKey, "shadowsocks 2022 session subkey", keyMaterial)
	} else {
		r := hkdf.New(sha1.New, c.secret, salt, []byte("ss-subkey"))
		if _, err := io.ReadFull(r, sessionKey); err != nil {
			return nil, err
		}
	}
	return c.aead.newInstance(sessionKey)
}

// Function definition at https://www.openssl.org/docs/manmaster/man3/EVP_BytesToKey.html
func simpleEVPBytesToKey(data []byte, keyLen int) []byte {
	var derived, di []byte
	h := md5.New()
	for len(derived) < keyLen {
		h.Write(di)
		h.Write(data)
		derived = h.Sum(derived)
		di = derived[len(derived)-h.Size():]
		h.Reset()
	}
	return derived[:keyLen]
}

// NewCipher creates a Cipher given a cipher name and a secret
func NewCipher(cipherName string, secretText string) (*Cipher, error) {
	var c Cipher

	switch cipherName {
	case "aes-128-gcm", "AEAD_AES_128_GCM":
		c.aead = supportedAEADs[3]
	case "aes-192-gcm", "AEAD_AES_192_GCM":
		c.aead = supportedAEADs[2]
	case "2022-blake3-aes-256-gcm", "aes-256-gcm", "AEAD_AES_256_GCM":
		c.aead = supportedAEADs[1]
	case "2022-blake3-chacha20-poly1305", "chacha20-poly1305", "chacha20-ietf-poly1305":
		c.aead = supportedAEADs[0]
	default:
		return nil, fmt.Errorf("unknown method %s", cipherName)
	}

	switch cipherName {
	case "aes-128-gcm", "AEAD_AES_128_GCM", "aes-192-gcm", "AEAD_AES_192_GCM", "aes-256-gcm", "AEAD_AES_256_GCM", "chacha20-poly1305", "chacha20-ietf-poly1305":
		c.secret = simpleEVPBytesToKey([]byte(secretText), c.aead.keySize)
	case "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
		key, err := base64.StdEncoding.DecodeString(secretText)
		if err != nil {
			return nil, fmt.Errorf("invalid key %s", secretText)
		}
		if len(key) != c.aead.keySize {
			return nil, fmt.Errorf("bad key length %d", len(key))
		}
		c.secret = key
		c.config.IsSpec2022 = true
	}

	switch cipherName {
	case "2022-blake3-chacha20-poly1305":
		udpAEAD, err := chacha20poly1305.NewX(c.secret)
		if err != nil {
			return nil, fmt.Errorf("failed to create UDP AEAD: %w", err)
		}
		c.udpAEAD = udpAEAD
	case "2022-blake3-aes-256-gcm":
		c.config.UDPHasSeparateHeader = true
		cb, err := aes.NewCipher(c.secret)
		if err != nil {
			return nil, fmt.Errorf("failed to create block cipher for 2022 UDP header: %w", err)
		}
		c.separateHeaderCipher = cb
	}

	return &c, nil
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

func DecryptSeparateHeader(cipher *Cipher, dst, src []byte) error {
	if !cipher.config.IsSpec2022 || !cipher.config.UDPHasSeparateHeader {
		return nil
	}

	blockLen := cipher.separateHeaderCipher.BlockSize()

	if len(dst) < blockLen || len(src) < blockLen {
		return io.ErrShortBuffer
	}

	cipher.separateHeaderCipher.Decrypt(dst[:blockLen], src[:blockLen])
	return nil
}
