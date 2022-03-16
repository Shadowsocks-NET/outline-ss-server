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
	"crypto/rand"
	"io"

	"lukechampine.com/blake3"
)

// SaltGenerator generates unique salts to use in Shadowsocks connections.
type SaltGenerator interface {
	// Returns a new salt
	GetSalt(salt []byte) error
}

// randomSaltGenerator generates a new random salt.
type randomSaltGenerator struct{}

// GetSalt outputs a random salt.
func (randomSaltGenerator) GetSalt(salt []byte) error {
	_, err := rand.Read(salt)
	return err
}

type blake3KeyedHashSaltGenerator struct {
	r io.Reader
}

func NewBlake3KeyedHashReader(size int) SaltGenerator {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		panic(err)
	}

	h := blake3.New(size, key)
	return &blake3KeyedHashSaltGenerator{
		r: h.XOF(),
	}
}

func (g *blake3KeyedHashSaltGenerator) GetSalt(salt []byte) error {
	_, err := g.r.Read(salt)
	return err
}

var (
	// RandomSaltGenerator is a basic SaltGenerator.
	RandomSaltGenerator SaltGenerator = randomSaltGenerator{}

	// High performance random salt/nonce generator
	Blake3KeyedHashSaltGenerator = NewBlake3KeyedHashReader(24)
)
