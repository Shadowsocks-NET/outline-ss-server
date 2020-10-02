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
// limitations under the License.import "github.com/shadowsocks/go-shadowsocks2/shadowaead"

package shadowsocks

import (
	"io"

	"github.com/shadowsocks/go-shadowsocks2/shadowaead"
)

// This array must be at least service.maxNonceSize bytes.
var zeroNonce [12]byte

// Unpack decrypts a Shadowsocks-UDP packet and returns a slice containing the decrypted payload or an error.
// If dst is present, it is used to store the plaintext, and must have enough capacity.
// If dst is nil, decryption proceeds in-place.
// This function is needed because shadowaead.Unpack() embeds its own replay detection,
// which we do not always want, especially on memory-constrained clients.
func Unpack(dst, pkt []byte, cipher shadowaead.Cipher) ([]byte, error) {
	saltSize := cipher.SaltSize()
	if len(pkt) < saltSize {
		return nil, shadowaead.ErrShortPacket
	}
	salt := pkt[:saltSize]
	aead, err := cipher.Decrypter(salt)
	if err != nil {
		return nil, err
	}
	msg := pkt[saltSize:]
	if len(msg) < aead.Overhead() {
		return nil, shadowaead.ErrShortPacket
	}
	if dst == nil {
		dst = msg
	} else if len(dst)+aead.Overhead() < len(msg) {
		return nil, io.ErrShortBuffer
	}
	return aead.Open(dst[:0], zeroNonce[:aead.NonceSize()], msg, nil)
}
