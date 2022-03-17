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
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"

	wgreplay "golang.zx2c4.com/wireguard/replay"
)

// ErrShortPacket is identical to shadowaead.ErrShortPacket
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

// Unpack decrypts a Shadowsocks-UDP packet and returns a slice containing the decrypted payload or an error.
// If dst is present, it is used to store the plaintext, and must have enough capacity.
// If dst is nil, decryption proceeds in-place.
// This function is needed because shadowaead.Unpack() embeds its own replay detection,
// which we do not always want, especially on memory-constrained clients.
func Unpack(dst, pkt []byte, cipher *Cipher) ([]byte, error) {
	if !cipher.config.IsSpec2022 {
		saltSize := cipher.SaltSize()
		if len(pkt) < saltSize {
			return nil, ErrShortPacket
		}
		salt := pkt[:saltSize]
		msg := pkt[saltSize:]
		if dst == nil {
			dst = msg
		}
		return DecryptOnce(cipher, salt, dst[:0], msg)
	}

	nonceSize := cipher.udpAEAD.NonceSize()

	if len(pkt) <= nonceSize+cipher.udpAEAD.Overhead() {
		return nil, ErrShortPacket
	}

	if dst == nil {
		dst = pkt[nonceSize:]
	}

	// Open AEAD ciphertext
	return cipher.udpAEAD.Open(dst[:0], pkt[:nonceSize], pkt[nonceSize:], nil)
}

// Unpack function for 2022-blake3-aes-256-gcm.
// If separateHeader is nil, DecryptHeaderInPlace MUST be called before passing the ciphertext.
// The returned buffer includes the separate header.
func UnpackAesWithSeparateHeader(dst, pkt, separateHeader []byte, cipher *Cipher, unpackAEAD cipher.AEAD) ([]byte, error) {
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

// UnpackAndValidatePacket unpacks an encrypted packet, validates the packet,
// and returns the payload (without header) and the address.
//
// This function is intended to be called by a client receiving from server.
func UnpackAndValidatePacket(c *Cipher, separateHeaderAEAD cipher.AEAD, filter *wgreplay.Filter, sid, dst, src []byte) ([]byte, string, error) {
	cipherConfig := c.Config()
	var buf []byte
	var err error

	switch {
	case cipherConfig.UDPHasSeparateHeader:
		if dst == nil {
			dst = src
		}

		// Decrypt separate header
		err = DecryptSeparateHeader(c, dst, src)
		if err != nil {
			return nil, "", err
		}

		// Check session id
		if !bytes.Equal(sid, dst[:8]) {
			return nil, "", ErrSessionIDMismatch
		}

		// Unpack
		buf, err = UnpackAesWithSeparateHeader(dst, src, nil, c, separateHeaderAEAD)
		if err != nil {
			return nil, "", err
		}

	case cipherConfig.IsSpec2022:
		buf, err = Unpack(dst, src, c)
		if err != nil {
			return nil, "", err
		}

		// Check session id
		if !bytes.Equal(sid, buf[:8]) {
			return nil, "", ErrSessionIDMismatch
		}

	default:
		buf, err = Unpack(dst, src, c)
		if err != nil {
			return nil, "", err
		}
	}

	addr, payload, err := ParseUDPHeader(buf, HeaderTypeServerPacket, cipherConfig)
	if err != nil {
		return nil, "", err
	}

	if cipherConfig.IsSpec2022 {
		pid := binary.BigEndian.Uint64(buf[8:])
		if !filter.ValidateCounter(pid, math.MaxUint64) {
			return nil, "", fmt.Errorf("detected replay packet id %d", pid)
		}
	}

	return payload, addr, nil
}
