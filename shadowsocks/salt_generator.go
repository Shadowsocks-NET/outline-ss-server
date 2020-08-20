package shadowsocks

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/shadowsocks/go-shadowsocks2/shadowaead"
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
	_, err := io.ReadFull(rand.Reader, salt)
	return err
}

// RandomSaltGenerator is a basic SaltGenerator.
var RandomSaltGenerator SaltGenerator = randomSaltGenerator{}

// ServerSaltGenerator generates unique salts that are secretly marked.
type ServerSaltGenerator struct {
	saltSize  int
	encrypter cipher.AEAD
}

// Number of bytes of salt to use as a marker.  Increasing this value reduces
// the false positive rate, but increases the likelihood of salt collisions.
// Must be less than or equal to the cipher overhead.
const markLen = 4

// Constant to identify this marking scheme.
var serverSaltLabel = []byte("outline-server-salt")

// NewServerSaltGenerator returns a SaltGenerator whose output is apparently
// random, but is secretly marked as being issued by the server.
// This is useful to prevent the server from accepting its own output in a
// reflection attack.
func NewServerSaltGenerator(cipher shadowaead.Cipher) (ServerSaltGenerator, error) {
	saltSize := cipher.SaltSize()
	zeroSalt := make([]byte, saltSize)
	encrypter, err := cipher.Encrypter(zeroSalt)
	if err != nil {
		return ServerSaltGenerator{}, err
	}
	return ServerSaltGenerator{saltSize, encrypter}, nil
}

func (sg ServerSaltGenerator) splitSalt(salt []byte) (prefix, mark []byte) {
	prefixLen := sg.saltSize - markLen
	prefix = salt[:prefixLen]
	mark = salt[prefixLen:]
	return
}

// getTag takes in a salt prefix and returns the tag.
// len(prefix) must be saltSize - markLen, which must be at least nonceSize.
// prefix must be random to avoid nonce reuse.
func (sg ServerSaltGenerator) getTag(prefix []byte) []byte {
	// Only the first nonceSize bytes are used to compute the tag. In the event
	// of a nonce collision (p=2^-33 after 2^32 messages for nonceSize==12),
	// the only effect will be to reveal a pattern in the handshakes, not
	// to reuse the same nonce on different inputs (which can cause more
	// serious problems: https://www.imperialviolet.org/2015/05/16/aeads.html).
	nonce := prefix[:sg.encrypter.NonceSize()]
	return sg.encrypter.Seal(nil, nonce, nil, serverSaltLabel)
}

// GetSalt returns an apparently random salt that can be identified
// as server-originated by anyone who knows the Shadowsocks key.
func (sg ServerSaltGenerator) GetSalt(salt []byte) error {
	if len(salt) != sg.saltSize {
		return fmt.Errorf("Wrong salt size: %d != %d", len(salt), sg.saltSize)
	}
	prefix, mark := sg.splitSalt(salt)
	_, err := io.ReadFull(rand.Reader, prefix)
	if err != nil {
		return err
	}
	tag := sg.getTag(prefix)
	copy(mark, tag)
	return nil
}

// IsServerSalt returns true if the salt is marked as server-originated.
func (sg ServerSaltGenerator) IsServerSalt(salt []byte) bool {
	prefix, mark := sg.splitSalt(salt)
	tag := sg.getTag(prefix)
	return bytes.Equal(tag[:markLen], mark)
}
