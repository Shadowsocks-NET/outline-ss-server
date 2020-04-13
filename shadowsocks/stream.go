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
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/shadowsocks/go-shadowsocks2/shadowaead"
)

// payloadSizeMask is the maximum size of payload in bytes.
const payloadSizeMask = 0x3FFF // 16*1024 - 1

// Writer is an io.Writer that also implements io.ReaderFrom to
// allow for piping the data without extra allocations and copies.
type Writer interface {
	io.Writer
	io.ReaderFrom
}

type shadowsocksWriter struct {
	writer   io.Writer
	ssCipher shadowaead.Cipher
	// These are lazily initialized:
	buf  []byte
	aead cipher.AEAD
	// Index of the next encrypted chunk to write.
	counter []byte
}

// NewShadowsocksWriter creates a Writer that encrypts the given Writer using
// the shadowsocks protocol with the given shadowsocks cipher.
func NewShadowsocksWriter(writer io.Writer, ssCipher shadowaead.Cipher) Writer {
	return &shadowsocksWriter{writer: writer, ssCipher: ssCipher}
}

// init generates a random salt, sets up the AEAD object and writes
// the salt to the inner Writer.
func (sw *shadowsocksWriter) init() (err error) {
	if sw.aead == nil {
		salt := make([]byte, sw.ssCipher.SaltSize())
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return fmt.Errorf("failed to generate salt: %v", err)
		}
		_, err := sw.writer.Write(salt)
		if err != nil {
			return fmt.Errorf("failed to write salt: %v", err)
		}
		sw.aead, err = sw.ssCipher.Encrypter(salt)
		if err != nil {
			return fmt.Errorf("failed to create AEAD: %v", err)
		}
		sw.counter = make([]byte, sw.aead.NonceSize())
		sw.buf = make([]byte, 2+sw.aead.Overhead()+payloadSizeMask+sw.aead.Overhead())
	}
	return nil
}

// WriteBlock encrypts and writes the input buffer as one signed block.
func (sw *shadowsocksWriter) encryptBlock(ciphertext []byte, plaintext []byte) ([]byte, error) {
	out := sw.aead.Seal(ciphertext, sw.counter, plaintext, nil)
	increment(sw.counter)
	return out, nil
}

func (sw *shadowsocksWriter) Write(p []byte) (int, error) {
	n, err := sw.ReadFrom(bytes.NewReader(p))
	return int(n), err
}

func (sw *shadowsocksWriter) ReadFrom(r io.Reader) (int64, error) {
	if err := sw.init(); err != nil {
		return 0, err
	}
	var written int64
	sizeBuf := sw.buf[:2+sw.aead.Overhead()]
	payloadBuf := sw.buf[len(sizeBuf):]
	for {
		plaintextSize, err := r.Read(payloadBuf[:payloadSizeMask])
		if plaintextSize > 0 {
			// big-endian payload size
			sizeBuf[0], sizeBuf[1] = byte(plaintextSize>>8), byte(plaintextSize)
			_, err = sw.encryptBlock(sizeBuf[:0], sizeBuf[:2])
			if err != nil {
				return written, fmt.Errorf("failed to encypt payload size: %v", err)
			}
			_, err := sw.encryptBlock(payloadBuf[:0], payloadBuf[:plaintextSize])
			if err != nil {
				return written, fmt.Errorf("failed to encrypt payload: %v", err)
			}
			payloadSize := plaintextSize + sw.aead.Overhead()
			_, err = sw.writer.Write(sw.buf[:len(sizeBuf)+payloadSize])
			written += int64(plaintextSize)
		}
		if err != nil {
			if err == io.EOF { // ignore EOF as per io.ReaderFrom contract
				return written, nil
			}
			return written, fmt.Errorf("Failed to read payload: %v", err)
		}
	}
}

type shadowsocksReader struct {
	reader   io.Reader
	ssCipher shadowaead.Cipher
	// These are lazily initialized:
	aead cipher.AEAD
	// Index of the next encrypted chunk to read.
	counter  []byte
	buf      []byte
	leftover []byte
}

// Reader is an io.Reader that also implements io.WriterTo to
// allow for piping the data without extra allocations and copies.
type Reader interface {
	io.Reader
	io.WriterTo
}

// NewShadowsocksReader creates a Reader that decrypts the given Reader using
// the shadowsocks protocol with the given shadowsocks cipher.
func NewShadowsocksReader(reader io.Reader, ssCipher shadowaead.Cipher) Reader {
	return &shadowsocksReader{reader: reader, ssCipher: ssCipher}
}

// init reads the salt from the inner Reader and sets up the AEAD object
func (sr *shadowsocksReader) init() (err error) {
	if sr.aead == nil {
		// For chacha20-poly1305, SaltSize is 32, NonceSize is 12 and Overhead is 16.
		salt := make([]byte, sr.ssCipher.SaltSize())
		if _, err := io.ReadFull(sr.reader, salt); err != nil {
			if err != io.EOF && err != io.ErrUnexpectedEOF {
				err = fmt.Errorf("failed to read salt: %v", err)
			}
			return err
		}
		sr.aead, err = sr.ssCipher.Decrypter(salt)
		if err != nil {
			return fmt.Errorf("failed to create AEAD: %v", err)
		}
		sr.counter = make([]byte, sr.aead.NonceSize())
		sr.buf = make([]byte, payloadSizeMask+sr.aead.Overhead())
	}
	return nil
}

// ReadBlock reads and decrypts a single signed block of ciphertext.
// The block will match the given decryptedBlockSize.
// The returned slice is only valid until the next Read call.
func (sr *shadowsocksReader) readBlock(decryptedBlockSize int) ([]byte, error) {
	if err := sr.init(); err != nil {
		return nil, err
	}
	cipherBlockSize := decryptedBlockSize + sr.aead.Overhead()
	if cipherBlockSize > cap(sr.buf) {
		return nil, io.ErrShortBuffer
	}
	buf := sr.buf[:cipherBlockSize]
	_, err := io.ReadFull(sr.reader, buf)
	if err != nil {
		return nil, err
	}
	buf, err = sr.aead.Open(buf[:0], sr.counter, buf, nil)
	increment(sr.counter)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %v", err)
	}
	return buf, nil
}

func (sr *shadowsocksReader) Read(b []byte) (int, error) {
	if err := sr.ensureLeftover(); err != nil {
		return 0, err
	}
	n := copy(b, sr.leftover)
	sr.leftover = sr.leftover[n:]
	return n, nil
}

func (sr *shadowsocksReader) WriteTo(w io.Writer) (written int64, err error) {
	for {
		if err = sr.ensureLeftover(); err != nil {
			if err == io.EOF {
				err = nil
			}
			return written, err
		}
		n, err := w.Write(sr.leftover)
		written += int64(n)
		sr.leftover = sr.leftover[n:]
		if err != nil {
			return written, err
		}
	}
}

// Ensures that sr.leftover is nonempty.  If leftover is empty, this method
// waits for incoming data and decrypts it.
// Returns an error only if sr.leftover could not be populated.
func (sr *shadowsocksReader) ensureLeftover() error {
	if len(sr.leftover) > 0 {
		return nil
	}
	buf, err := sr.readBlock(2)
	if err != nil {
		if err != io.EOF && err != io.ErrUnexpectedEOF {
			err = fmt.Errorf("failed to read payload size: %v", err)
		}
		return err
	}
	size := (int(buf[0])<<8 + int(buf[1])) & payloadSizeMask
	payload, err := sr.readBlock(size)
	if err != nil {
		return fmt.Errorf("failed to read payload: %v", err)
	}
	sr.leftover = payload
	return nil
}

// increment little-endian encoded unsigned integer b. Wrap around on overflow.
func increment(b []byte) {
	for i := range b {
		b[i]++
		if b[i] != 0 {
			return
		}
	}
}
