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
	"crypto/cipher"
	"testing"

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
	smallSalt := &fakeCipher{saltsize: 8, decrypter: &fakeAEAD{overhead: 16, nonceSize: 12}}
	oddSalt := &fakeCipher{saltsize: 23, decrypter: &fakeAEAD{overhead: 16, nonceSize: 12}}
	bigSalt := &fakeCipher{saltsize: 64, decrypter: &fakeAEAD{overhead: 16, nonceSize: 12}}
	smallOverhead := &fakeCipher{saltsize: 8, decrypter: &fakeAEAD{overhead: 8, nonceSize: 12}}
	bigOverhead := &fakeCipher{saltsize: 8, decrypter: &fakeAEAD{overhead: 8, nonceSize: 12}}
	bigNonce := &fakeCipher{saltsize: 32, decrypter: &fakeAEAD{overhead: 16, nonceSize: 13}}

	ciphers := [...]shadowaead.Cipher{
		smallSalt, oddSalt, bigSalt,
		smallOverhead, bigOverhead,
		bigNonce,
	}
	for _, c := range ciphers {
		if err := CheckCipher(c); err == nil {
			t.Errorf("Expected error when checking cipher: %v", c)
		}
	}
}

func TestCompatibleCiphers(t *testing.T) {
	smallSalt := &fakeCipher{saltsize: 16, decrypter: &fakeAEAD{overhead: 16, nonceSize: 12}}
	bigSalt := &fakeCipher{saltsize: 32, decrypter: &fakeAEAD{overhead: 16, nonceSize: 12}}
	smallNonce := &fakeCipher{saltsize: 16, decrypter: &fakeAEAD{overhead: 16, nonceSize: 10}}

	ciphers := [...]shadowaead.Cipher{smallSalt, bigSalt, smallNonce}
	for _, c := range ciphers {
		if err := CheckCipher(c); err != nil {
			t.Error(err)
		}
	}
}

func TestRealCiphers(t *testing.T) {
	chacha, err := shadowaead.Chacha20Poly1305(make([]byte, 32))
	if err != nil {
		t.Error(err)
	}
	aes256, err := shadowaead.AESGCM(make([]byte, 32))
	if err != nil {
		t.Error(err)
	}
	aes192, err := shadowaead.AESGCM(make([]byte, 24))
	if err != nil {
		t.Error(err)
	}
	aes128, err := shadowaead.AESGCM(make([]byte, 16))
	if err != nil {
		t.Error(err)
	}

	ciphers := [...]shadowaead.Cipher{
		chacha, aes256, aes192, aes128,
	}
	for _, c := range ciphers {
		if err := CheckCipher(c); err != nil {
			t.Error(err)
		}
	}
}

func TestTCPHeader(t *testing.T) {
	for _, s := range supportedSizes {
		required := s.salt + 2 + s.overhead
		if required > tcpHeader {
			t.Error("Cipher requires too many bytes")
		}

		// Minimum length initial delivery is a complete zero-length chunk
		provided := required + s.overhead
		if provided < tcpHeader {
			t.Error("Cipher doesn't provide enough bytes")
		}
	}
}
