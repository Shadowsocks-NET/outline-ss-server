package shadowsocks

import (
	"bytes"
	"testing"

	"github.com/shadowsocks/go-shadowsocks2/core"
	"github.com/shadowsocks/go-shadowsocks2/shadowaead"
)

func TestRandomSaltGenerator(t *testing.T) {
	if err := RandomSaltGenerator.GetSalt(nil); err != nil {
		t.Error(err)
	}
	salt := make([]byte, 16)
	if err := RandomSaltGenerator.GetSalt(salt); err != nil {
		t.Error(err)
	}
	if bytes.Equal(salt, make([]byte, 16)) {
		t.Error("Salt is all zeros")
	}
}

type mockAEAD struct {
	fakeAEAD
	t      *testing.T
	sealed bool
	tag    []byte
}

func (a *mockAEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != a.NonceSize() {
		a.t.Errorf("Wrong nonce length: %d != %d", len(nonce), a.NonceSize())
	}
	if len(plaintext) != 0 {
		a.t.Errorf("Wrong plaintext length: %d != 0", len(plaintext))
	}
	if !bytes.Equal(additionalData, serverSaltLabel) {
		a.t.Errorf("Wrong additional data: %v", additionalData)
	}
	a.sealed = true
	dst = append(dst, a.tag...)
	return dst
}

// Test that ServerSaltGenerator works as expected using a fake cipher.
func TestServerSaltFake(t *testing.T) {
	tag := []byte("1234567890123456")
	mockCipher := &fakeCipher{
		saltSize: 32,
		aead: &mockAEAD{
			fakeAEAD: fakeAEAD{
				nonceSize: 12,
				overhead:  16,
			},
			t:   t,
			tag: tag,
		},
	}

	ssg, err := NewServerSaltGenerator(mockCipher)
	if err != nil {
		t.Fatal(err)
	}
	salt := make([]byte, mockCipher.saltSize)
	if err := ssg.GetSalt(salt); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(salt, make([]byte, len(salt))) {
		t.Error("Salt is zero")
	}
	if !bytes.Equal(salt[len(salt)-markLen:], tag[:markLen]) {
		t.Error("Tag mismatch")
	}
	if !ssg.IsServerSalt(salt) {
		t.Error("Tag was not recognized")
	}

	// Make another random salt with the same tag
	salt2 := make([]byte, mockCipher.saltSize)
	if err := ssg.GetSalt(salt2); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(salt, salt2) {
		t.Error("Salts should be different")
	}
	if !bytes.Equal(salt2[len(salt2)-markLen:], tag[:markLen]) {
		t.Error("Tag mismatch")
	}
	if !ssg.IsServerSalt(salt2) {
		t.Error("Tag was not recognized")
	}

	// Alter tag
	salt[len(salt)-1]++
	if ssg.IsServerSalt(salt) {
		t.Error("Altered tag was still recognized")
	}
}

// Test that ServerSaltGenerator recognizes its own salts
func TestServerSaltRecognized(t *testing.T) {
	cipher, err := core.PickCipher(testCipher, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	aead := cipher.(shadowaead.Cipher)
	ssg, err := NewServerSaltGenerator(aead)
	if err != nil {
		t.Fatal(err)
	}

	salt := make([]byte, aead.SaltSize())
	if err := ssg.GetSalt(salt); err != nil {
		t.Fatal(err)
	}
	if !ssg.IsServerSalt(salt) {
		t.Error("Server salt was not recognized")
	}
}

// Test that ServerSaltGenerator doesn't recognize random salts
func TestServerSaltUnrecognized(t *testing.T) {
	cipher, err := core.PickCipher(testCipher, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	aead := cipher.(shadowaead.Cipher)
	ssg, err := NewServerSaltGenerator(aead)
	if err != nil {
		t.Fatal(err)
	}

	salt := make([]byte, aead.SaltSize())
	if err := RandomSaltGenerator.GetSalt(salt); err != nil {
		t.Fatal(err)
	}
	if ssg.IsServerSalt(salt) {
		t.Error("Client salt was recognized as a server salt")
	}
}

// Test that ServerSaltGenerator produces different output on each call
func TestServerSaltDifferent(t *testing.T) {
	cipher, err := core.PickCipher(testCipher, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	aead := cipher.(shadowaead.Cipher)
	ssg, err := NewServerSaltGenerator(aead)
	if err != nil {
		t.Fatal(err)
	}

	salt1 := make([]byte, aead.SaltSize())
	if err := ssg.GetSalt(salt1); err != nil {
		t.Fatal(err)
	}
	salt2 := make([]byte, aead.SaltSize())
	if err := ssg.GetSalt(salt2); err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(salt1, salt2) {
		t.Error("salts should be random")
	}
}

// Test that two ServerSaltGenerators derived from the same cipher
// produce different outputs and recognize each other's output.
func TestServerSaltSameCipher(t *testing.T) {
	cipher, err := core.PickCipher(testCipher, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	aead := cipher.(shadowaead.Cipher)
	ssg1, err := NewServerSaltGenerator(aead)
	if err != nil {
		t.Fatal(err)
	}
	ssg2, err := NewServerSaltGenerator(aead)
	if err != nil {
		t.Fatal(err)
	}

	salt1 := make([]byte, aead.SaltSize())
	if err := ssg1.GetSalt(salt1); err != nil {
		t.Fatal(err)
	}
	salt2 := make([]byte, aead.SaltSize())
	if err := ssg2.GetSalt(salt2); err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(salt1, salt2) {
		t.Error("salts should be random")
	}

	if !ssg1.IsServerSalt(salt2) || !ssg2.IsServerSalt(salt1) {
		t.Error("Cross-recognition failed")
	}
}

// Test that two ServerSaltGenerators derived from the same secret
// produce different outputs and recognize each other's output.
func TestServerSaltSameSecret(t *testing.T) {
	cipher1, err := core.PickCipher(testCipher, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	aead1 := cipher1.(shadowaead.Cipher)
	cipher2, err := core.PickCipher(testCipher, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	aead2 := cipher2.(shadowaead.Cipher)
	ssg1, err := NewServerSaltGenerator(aead1)
	if err != nil {
		t.Fatal(err)
	}
	ssg2, err := NewServerSaltGenerator(aead2)
	if err != nil {
		t.Fatal(err)
	}

	salt1 := make([]byte, aead1.SaltSize())
	if err := ssg1.GetSalt(salt1); err != nil {
		t.Fatal(err)
	}
	salt2 := make([]byte, aead2.SaltSize())
	if err := ssg2.GetSalt(salt2); err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(salt1, salt2) {
		t.Error("salts should be random")
	}

	if !ssg1.IsServerSalt(salt2) || !ssg2.IsServerSalt(salt1) {
		t.Error("Cross-recognition failed")
	}
}

// Test that two ServerSaltGenerators derived from different secrets
// do not recognize each other's output.
func TestServerSaltDifferentCiphers(t *testing.T) {
	cipher1, err := core.PickCipher(testCipher, nil, "test1")
	if err != nil {
		t.Fatal(err)
	}
	aead1 := cipher1.(shadowaead.Cipher)
	cipher2, err := core.PickCipher(testCipher, nil, "test2")
	if err != nil {
		t.Fatal(err)
	}
	aead2 := cipher2.(shadowaead.Cipher)
	ssg1, err := NewServerSaltGenerator(aead1)
	if err != nil {
		t.Fatal(err)
	}
	ssg2, err := NewServerSaltGenerator(aead2)
	if err != nil {
		t.Fatal(err)
	}

	salt1 := make([]byte, aead1.SaltSize())
	if err := ssg1.GetSalt(salt1); err != nil {
		t.Fatal(err)
	}
	salt2 := make([]byte, aead2.SaltSize())
	if err := ssg2.GetSalt(salt2); err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(salt1, salt2) {
		t.Error("salts should be random")
	}

	if ssg1.IsServerSalt(salt2) || ssg2.IsServerSalt(salt1) {
		t.Error("Different ciphers should not recognize each other")
	}
}

func BenchmarkRandomSaltGenerator(b *testing.B) {
	salt := make([]byte, 32)
	for i := 0; i < b.N; i++ {
		if err := RandomSaltGenerator.GetSalt(salt); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkServerSaltGenerator(b *testing.B) {
	cipher, err := core.PickCipher(testCipher, nil, "test")
	if err != nil {
		b.Fatal(err)
	}
	aead := cipher.(shadowaead.Cipher)
	ssg, err := NewServerSaltGenerator(aead)
	if err != nil {
		b.Fatal(err)
	}
	salt := make([]byte, aead.SaltSize())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := ssg.GetSalt(salt); err != nil {
			b.Fatal(err)
		}
		if !ssg.IsServerSalt(salt) {
			b.Fatal("Failed to recognize salt")
		}
	}
}
