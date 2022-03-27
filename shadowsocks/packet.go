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
	"crypto/cipher"
	"errors"
	"io"
)

var ErrShortPacket = errors.New("short packet")

// Pack encrypts a Shadowsocks-UDP packet and returns a slice containing the encrypted packet.
// dst must be big enough to hold the encrypted packet.
// If plaintext and dst overlap but are not aligned for in-place encryption, this
// function will panic.
func Pack(dst, plaintext []byte, cipher *Cipher) ([]byte, error) {
	if !cipher.config.IsSpec2022 {
		saltSize := cipher.SaltSize()
		if len(dst) < saltSize {
			return nil, io.ErrShortBuffer
		}
		salt := dst[:saltSize]
		if err := RandomSaltGenerator.GetSalt(salt); err != nil {
			return nil, err
		}

		aead, err := cipher.NewAEAD(salt)
		if err != nil {
			return nil, err
		}

		if len(dst) < saltSize+len(plaintext)+aead.Overhead() {
			return nil, io.ErrShortBuffer
		}
		return aead.Seal(salt, zeroNonce[:aead.NonceSize()], plaintext, nil), nil
	}

	nonceSize := cipher.udpAEAD.NonceSize()

	if len(dst) < nonceSize+len(plaintext)+cipher.udpAEAD.Overhead() {
		return nil, io.ErrShortBuffer
	}

	// Random nonce
	if err := Blake3KeyedHashSaltGenerator.GetSalt(dst[:nonceSize]); err != nil {
		return nil, err
	}

	// Seal AEAD plaintext
	return cipher.udpAEAD.Seal(dst[:nonceSize], dst[:nonceSize], plaintext, nil), nil
}

// Pack function for 2022-blake3-aes-256-gcm.
// Do not encrypt header before calling this function.
// This function encrypts the separate header after sealing AEAD.
//
// plaintext should start with the separate header.
func PackAesWithSeparateHeader(dst, plaintext []byte, cipher *Cipher, sessionAEAD cipher.AEAD) ([]byte, error) {
	if len(dst) < 16+len(plaintext)+sessionAEAD.Overhead() {
		return nil, io.ErrShortBuffer
	}

	// Seal AEAD plaintext
	ciphertext := sessionAEAD.Seal(dst[:16], dst[4:16], plaintext[16:], nil)

	// Encrypt header
	cipher.separateHeaderCipher.Encrypt(ciphertext[:16], ciphertext[:16])

	return ciphertext, nil
}

// Unpack decrypts a Shadowsocks UDP packet and returns
// the plaintext offset in the original packet buffer,
// a slice containing the decrypted plaintext (header + payload) or an error.
//
// If dst is present, it is used to store the plaintext, and must have enough capacity.
// If dst is nil, decryption proceeds in-place.
func Unpack(dst, pkt []byte, cipher *Cipher) (plaintextStart int, plaintext []byte, err error) {
	switch {
	case cipher.config.IsSpec2022:
		plaintextStart = cipher.udpAEAD.NonceSize()
	default:
		plaintextStart = cipher.SaltSize()
	}

	if len(pkt) < plaintextStart {
		err = ErrShortPacket
		return
	}

	if dst == nil {
		dst = pkt[plaintextStart:]
	}

	// Open AEAD ciphertext
	switch {
	case cipher.config.IsSpec2022:
		plaintext, err = cipher.udpAEAD.Open(dst[:0], pkt[:plaintextStart], pkt[plaintextStart:], nil)
	default:
		plaintext, err = DecryptOnce(cipher, pkt[:plaintextStart], dst[:0], pkt[plaintextStart:])
	}

	return
}

// Unpack function for 2022-blake3-aes-256-gcm.
// If separateHeader is nil, DecryptSeparateheader MUST be called to decrypte the separate header in-place
// before passing the ciphertext.
// The returned buffer includes the separate header.
func UnpackAesWithSeparateHeader(dst, pkt, separateHeader []byte, unpackAEAD cipher.AEAD) ([]byte, error) {
	if len(pkt) <= 16+unpackAEAD.Overhead() {
		return nil, ErrShortPacket
	}

	if dst == nil {
		dst = pkt
	}

	if separateHeader == nil {
		separateHeader = pkt[:16]
	}

	copy(dst, separateHeader)

	// Open AEAD ciphertext
	buf, err := unpackAEAD.Open(dst[:16], separateHeader[4:], pkt[16:], nil)
	if err != nil {
		return nil, err
	}

	return buf, nil
}
