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
	"encoding/binary"
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
	// Wrapper for input that arrives as a slice.
	byteWrapper bytes.Reader
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
	sw.byteWrapper.Reset(p)
	n, err := sw.ReadFrom(&sw.byteWrapper)
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
			binary.BigEndian.PutUint16(sizeBuf, uint16(plaintextSize))
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

// ChunkReader is similar to io.Reader, except that it controls its own
// buffer granularity.
type ChunkReader interface {
	// ReadChunk reads the next chunk and returns its payload.  The caller must
	// complete its use of the returned buffer before the next call.
	// The buffer is nil iff there is an error.  io.EOF indicates a close.
	ReadChunk() ([]byte, error)
}

type chunkReader struct {
	reader   io.Reader
	ssCipher shadowaead.Cipher
	// These are lazily initialized:
	aead cipher.AEAD
	// Index of the next encrypted chunk to read.
	counter []byte
	buf     []byte
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
	return &readConverter{
		cr: &chunkReader{reader: reader, ssCipher: ssCipher},
	}
}

// init reads the salt from the inner Reader and sets up the AEAD object
func (cr *chunkReader) init() (err error) {
	if cr.aead == nil {
		// For chacha20-poly1305, SaltSize is 32, NonceSize is 12 and Overhead is 16.
		salt := make([]byte, cr.ssCipher.SaltSize())
		if _, err := io.ReadFull(cr.reader, salt); err != nil {
			if err != io.EOF && err != io.ErrUnexpectedEOF {
				err = fmt.Errorf("failed to read salt: %v", err)
			}
			return err
		}
		cr.aead, err = cr.ssCipher.Decrypter(salt)
		if err != nil {
			return fmt.Errorf("failed to create AEAD: %v", err)
		}
		cr.counter = make([]byte, cr.aead.NonceSize())
		cr.buf = make([]byte, payloadSizeMask+cr.aead.Overhead())
	}
	return nil
}

// readMessage reads, decrypts, and verifies a single AEAD ciphertext.
// The ciphertext and tag (i.e. "overhead") must exactly fill `buf`,
// and the decrypted message will be placed in buf[:len(buf)-overhead].
// Returns an error only if the block could not be read.
func (cr *chunkReader) readMessage(buf []byte) error {
	_, err := io.ReadFull(cr.reader, buf)
	if err != nil {
		return err
	}
	_, err = cr.aead.Open(buf[:0], cr.counter, buf, nil)
	increment(cr.counter)
	if err != nil {
		return fmt.Errorf("failed to decrypt: %v", err)
	}
	return nil
}

func (cr *chunkReader) ReadChunk() ([]byte, error) {
	if err := cr.init(); err != nil {
		return nil, err
	}
	// In Shadowsocks-AEAD, each chunk consists of two
	// encrypted messages.  The first message contains the payload length,
	// and the second message is the payload.
	sizeBuf := cr.buf[:2+cr.aead.Overhead()]
	if err := cr.readMessage(sizeBuf); err != nil {
		if err != io.EOF && err != io.ErrUnexpectedEOF {
			err = fmt.Errorf("failed to read payload size: %v", err)
		}
		return nil, err
	}
	size := int(binary.BigEndian.Uint16(sizeBuf) & payloadSizeMask)
	sizeWithTag := size + cr.aead.Overhead()
	if cap(cr.buf) < sizeWithTag {
		// This code is unreachable.
		return nil, io.ErrShortBuffer
	}
	payloadBuf := cr.buf[:sizeWithTag]
	if err := cr.readMessage(payloadBuf); err != nil {
		if err == io.EOF { // EOF is not expected mid-chunk.
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return payloadBuf[:size], nil
}

// readConverter adapts from ChunkReader, with source-controlled
// chunk sizes, to Go-style IO.
type readConverter struct {
	cr       ChunkReader
	leftover []byte
}

func (c *readConverter) Read(b []byte) (int, error) {
	if err := c.ensureLeftover(); err != nil {
		return 0, err
	}
	n := copy(b, c.leftover)
	c.leftover = c.leftover[n:]
	return n, nil
}

func (c *readConverter) WriteTo(w io.Writer) (written int64, err error) {
	for {
		if err = c.ensureLeftover(); err != nil {
			if err == io.EOF {
				err = nil
			}
			return written, err
		}
		n, err := w.Write(c.leftover)
		written += int64(n)
		c.leftover = c.leftover[n:]
		if err != nil {
			return written, err
		}
	}
}

// Ensures that c.leftover is nonempty.  If leftover is empty, this method
// waits for incoming data and decrypts it.
// Returns an error only if c.leftover could not be populated.
func (c *readConverter) ensureLeftover() error {
	if len(c.leftover) > 0 {
		return nil
	}
	payload, err := c.cr.ReadChunk()
	if err != nil {
		return err
	}
	c.leftover = payload
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
