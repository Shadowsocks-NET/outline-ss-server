package shadowsocks

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"github.com/Shadowsocks-NET/outline-ss-server/slicepool"
)

const (
	// Max payload size for Shadowsocks 2022.
	shadowsocks2022MaxPayloadSize = 0xFFFF // 64k - 1

	// legacyPayloadSizeMask is the maximum size of payload in bytes for legacy Shadowsocks AEAD.
	legacyPayloadSizeMask = 0x3FFF // 16*1024 - 1
)

// Buffer pool used for decrypting Shadowsocks streams.
// The largest buffer we could need is for decrypting a max-length payload.
var readBufPool = slicepool.MakePool(shadowsocks2022MaxPayloadSize + maxTagSize())

type DecryptionErr struct {
	Err error
}

func (e *DecryptionErr) Unwrap() error { return e.Err }
func (e *DecryptionErr) Error() string { return "failed to decrypt: " + e.Err.Error() }

// Writer is an io.Writer that also implements io.ReaderFrom to
// allow for piping the data without extra allocations and copies.
// The LazyWrite and Flush methods allow a header to be
// added but delayed until the first write, for concatenation.
// All methods except Flush must be called from a single thread.
type Writer struct {
	// This type is single-threaded except when lazyWriteBuf is not nil.
	// mu syncs the flushing goroutine with the main write goroutine.
	mu sync.Mutex

	// Controls whether to add a random padding and set the padding length
	// when Flush() (not flush()) is called.
	addPaddingOnFlush bool

	// lazyWriteBuf stores socks address + padding length or request salt.
	// Used when flushing to write header.
	// After flushing, set this to nil.
	lazyWriteBuf []byte

	writer   io.Writer
	ssCipher *Cipher
	// Wrapper for input that arrives as a slice.
	byteWrapper bytes.Reader
	// Number of plaintext bytes that are currently buffered.
	pending        int
	buf            []byte
	aead           cipher.AEAD
	counter        []byte
	maxPayloadSize int
}

// NewShadowsocksWriter creates a Writer that encrypts the given Writer using
// the shadowsocks protocol with the given shadowsocks cipher.
//
// addPaddingOnFlush: true, lazyWriteBuf != nil: Shadowsocks 2022 client writer
// addPaddingOnFlush: false, lazyWriteBuf != nil: Shadowsocks 2022 server writer, Legacy Shadowsocks client writer
// addPaddingOnFlush: false, lazyWriteBuf == nil: Legacy Shadowsocks server writer
func NewShadowsocksWriter(writer io.Writer, ssCipher *Cipher, saltGenerator SaltGenerator, lazyWriteBuf []byte, addPaddingOnFlush bool) (*Writer, error) {
	var maxPayloadSize int

	switch {
	case ssCipher.config.IsSpec2022:
		maxPayloadSize = shadowsocks2022MaxPayloadSize
	default:
		maxPayloadSize = legacyPayloadSizeMask
	}

	saltLen := ssCipher.aead.saltSize
	overhead := ssCipher.aead.tagSize
	buf := make([]byte, saltLen+2+overhead+maxPayloadSize+overhead)

	// Generate random salt
	if saltGenerator == nil {
		saltGenerator = RandomSaltGenerator
	}

	if err := saltGenerator.GetSalt(buf[:saltLen]); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Create AEAD
	aead, err := ssCipher.NewAEAD(buf[:saltLen])
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD: %w", err)
	}

	return &Writer{
		writer:            writer,
		ssCipher:          ssCipher,
		buf:               buf,
		aead:              aead,
		counter:           make([]byte, aead.NonceSize()),
		addPaddingOnFlush: addPaddingOnFlush,
		lazyWriteBuf:      lazyWriteBuf,
		maxPayloadSize:    maxPayloadSize,
	}, nil
}

func (sw *Writer) Salt() []byte {
	return sw.buf[:sw.ssCipher.aead.saltSize]
}

// encryptBlock encrypts `plaintext` in-place.  The slice must have enough capacity
// for the tag. Returns the total ciphertext length.
func (sw *Writer) encryptBlock(plaintext []byte) int {
	out := sw.aead.Seal(plaintext[:0], sw.counter, plaintext, nil)
	increment(sw.counter)
	return len(out)
}

func (sw *Writer) Write(p []byte) (int, error) {
	sw.byteWrapper.Reset(p)
	n, err := sw.ReadFrom(&sw.byteWrapper)
	return int(n), err
}

// Flush sends the pending header, if any. This method is thread-safe.
func (sw *Writer) Flush() error {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	if sw.lazyWriteBuf == nil {
		return nil
	}

	// Write header and random padding
	_, payloadBuf := sw.buffers()
	sw.pending = WriteTCPReqHeader(payloadBuf, sw.lazyWriteBuf, sw.addPaddingOnFlush, sw.ssCipher.config)
	sw.lazyWriteBuf = nil
	return sw.flush()
}

func isZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// Returns the slices of sw.buf in which to place plaintext for encryption.
func (sw *Writer) buffers() (sizeBuf, payloadBuf []byte) {
	// sw.buf starts with the salt.
	saltSize := sw.ssCipher.aead.saltSize
	overhead := sw.ssCipher.aead.tagSize

	// Each Shadowsocks-TCP message consists of a fixed-length size block,
	// followed by a variable-length payload block.
	sizeBuf = sw.buf[saltSize : saltSize+2]
	payloadStart := saltSize + 2 + overhead
	payloadBuf = sw.buf[payloadStart : payloadStart+sw.maxPayloadSize]
	return
}

// offsetInPayloadBuf is relative to payloadBuf, not sw.buf.
func (sw *Writer) buffersFromPayloadOffset(offsetInPayloadBuf int) (saltOffset, sizeOffset, payloadOffset int, saltBuf, sizeBuf, payloadBuf []byte) {
	saltSize := sw.ssCipher.aead.saltSize
	overhead := sw.ssCipher.aead.tagSize

	payloadOffset = saltSize + 2 + overhead + offsetInPayloadBuf
	payloadBuf = sw.buf[payloadOffset : len(sw.buf)-overhead]

	sizeOffset = payloadOffset - overhead - 2
	sizeBuf = sw.buf[sizeOffset : sizeOffset+2]

	saltOffset = sizeOffset - saltSize
	saltBuf = sw.buf[saltOffset:sizeOffset]

	return
}

// ReadFrom implements the io.ReaderFrom interface.
func (sw *Writer) ReadFrom(r io.Reader) (n int64, err error) {
	_, payloadBuf := sw.buffers()
	saltLen := sw.ssCipher.aead.saltSize

	sw.mu.Lock()
	if sw.lazyWriteBuf != nil {
		// Unlock so Flush() can successfully flush the header
		// should the timeout ran out and the read didn't return.
		sw.mu.Unlock()

		if sw.addPaddingOnFlush {
			// The protocol is Shadowsocks 2022 and might need padding.
			// Header length uncertain. Reserve max space for header.
			reservedLen := 1 + 8 + len(sw.lazyWriteBuf) + 2 + MaxPaddingLength
			var rn int
			rn, err = r.Read(payloadBuf[reservedLen:])
			n = int64(rn)

			sw.mu.Lock()
			sw.pending += rn

			if sw.lazyWriteBuf != nil {
				// Header not sent yet.
				// Calculate header start position, write header w/o padding.
				headerOffset := reservedLen - 1 - 8 - len(sw.lazyWriteBuf) - 2
				sw.pending += WriteTCPReqHeader(payloadBuf[headerOffset:], sw.lazyWriteBuf, false, sw.ssCipher.config)
				// Flush.
				if flushErr := sw.flushAt(headerOffset); flushErr != nil {
					err = flushErr
				}
				sw.lazyWriteBuf = nil
			} else {
				// Header already sent. Flush payload.
				if flushErr := sw.flushAt(reservedLen); flushErr != nil {
					err = flushErr
				}
			}
		} else {
			// Calculate header length.
			// It's either Shadowsocks 2022 response header, or legacy Shadowsocks socks address.
			var headerLen int
			switch {
			case sw.ssCipher.config.IsSpec2022:
				headerLen = 1 + 8 + saltLen
			default:
				headerLen = len(sw.lazyWriteBuf)
			}
			var rn int
			rn, err = r.Read(payloadBuf[headerLen:])
			n = int64(rn)

			sw.mu.Lock()
			sw.pending += rn

			if sw.lazyWriteBuf != nil {
				// Header not sent yet.
				// Write header.
				switch {
				case sw.ssCipher.config.IsSpec2022:
					sw.pending += WriteTCPRespHeader(payloadBuf, sw.lazyWriteBuf, sw.ssCipher.config)
				default:
					sw.pending += WriteTCPReqHeader(payloadBuf, sw.lazyWriteBuf, false, sw.ssCipher.config)
				}
				// Flush.
				if flushErr := sw.flush(); flushErr != nil {
					err = flushErr
				}
				sw.lazyWriteBuf = nil
			} else {
				// Header already sent. Flush payloadBuf[headerLen:headerLen+rn]
				if flushErr := sw.flushAt(headerLen); flushErr != nil {
					err = flushErr
				}
			}
		}
	}
	sw.mu.Unlock()

	// Main transfer loop
	for err == nil {
		sw.pending, err = r.Read(payloadBuf)
		n += int64(sw.pending)
		if flushErr := sw.flush(); flushErr != nil {
			err = flushErr
		}
	}

	if err == io.EOF { // ignore EOF as per io.ReaderFrom contract
		return n, nil
	}
	return n, fmt.Errorf("failed to read payload: %w", err)
}

// Encrypts all pending data and writes it to the output.
func (sw *Writer) flush() error {
	if sw.pending == 0 {
		return nil
	}
	// sw.buf starts with the salt.
	saltSize := sw.ssCipher.aead.saltSize
	// Normally we ignore the salt at the beginning of sw.buf.
	start := saltSize
	if isZero(sw.counter) {
		// For the first message, include the salt.  Compared to writing the salt
		// separately, this saves one packet during TCP slow-start and potentially
		// avoids having a distinctive size for the first packet.
		start = 0
	}

	sizeBuf, payloadBuf := sw.buffers()
	binary.BigEndian.PutUint16(sizeBuf, uint16(sw.pending))
	sizeBlockSize := sw.encryptBlock(sizeBuf)
	payloadSize := sw.encryptBlock(payloadBuf[:sw.pending])
	_, err := sw.writer.Write(sw.buf[start : saltSize+sizeBlockSize+payloadSize])
	sw.pending = 0
	return err
}

// flushAt flushes all pending bytes.
// When counter is zero, the salt will be skipped.
//
// offsetInPayloadBuf is relative to payloadBuf, not sw.buf.
func (sw *Writer) flushAt(offsetInPayloadBuf int) error {
	if sw.pending == 0 {
		return nil
	}

	saltOffset, sizeOffset, _, _, sizeBuf, payloadBuf := sw.buffersFromPayloadOffset(offsetInPayloadBuf)
	saltLen := sw.ssCipher.aead.saltSize
	start := sizeOffset
	if isZero(sw.counter) {
		// First flush. Include salt.
		start = saltOffset
		if saltOffset != 0 {
			// Copy salt to saltOffset
			// We don't have to worry about overlapped buffers,
			// because a large space should have been reserved before saltOffset.
			copy(sw.buf[saltOffset:], sw.buf[:saltLen])
		}
	}

	binary.BigEndian.PutUint16(sizeBuf, uint16(sw.pending))
	sizeBlockSize := sw.encryptBlock(sizeBuf)
	payloadSize := sw.encryptBlock(payloadBuf[:sw.pending])
	_, err := sw.writer.Write(sw.buf[start : sizeOffset+sizeBlockSize+payloadSize])
	sw.pending = 0
	return err
}

// ChunkReader is similar to io.Reader, except that it controls its own
// buffer granularity.
type ChunkReader interface {
	// ReadChunk reads the next chunk and returns its payload.  The caller must
	// complete its use of the returned buffer before the next call.
	// The buffer is nil iff there is an error.  io.EOF indicates a close.
	ReadChunk() ([]byte, error)

	Salt() []byte
}

type chunkReader struct {
	reader   io.Reader
	ssCipher *Cipher
	// These are lazily initialized:
	salt []byte
	aead cipher.AEAD
	// Index of the next encrypted chunk to read.
	counter []byte
	// Buffer for the uint16 size and its AEAD tag.  Made in init().
	payloadSizeBuf []byte
	// Holds a buffer for the payload and its AEAD tag, when needed.
	payload        slicepool.LazySlice
	maxPayloadSize int
}

// init reads the salt from the inner Reader and sets up the AEAD object
func (cr *chunkReader) init() (err error) {
	if cr.aead == nil {
		// For chacha20-poly1305, SaltSize is 32, NonceSize is 12 and Overhead is 16.
		cr.salt = make([]byte, cr.ssCipher.aead.saltSize)
		if _, err := io.ReadFull(cr.reader, cr.salt); err != nil {
			if err != io.EOF && err != io.ErrUnexpectedEOF {
				err = fmt.Errorf("failed to read salt: %w", err)
			}
			return err
		}
		cr.aead, err = cr.ssCipher.NewAEAD(cr.salt)
		if err != nil {
			return fmt.Errorf("failed to create AEAD: %w", err)
		}
		cr.counter = make([]byte, cr.aead.NonceSize())
		cr.payloadSizeBuf = make([]byte, 2+cr.aead.Overhead())
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
		return &DecryptionErr{Err: err}
	}
	return nil
}

// ReadChunk returns the next chunk from the stream.  Callers must fully
// consume and discard the previous chunk before calling ReadChunk again.
func (cr *chunkReader) ReadChunk() ([]byte, error) {
	if err := cr.init(); err != nil {
		return nil, err
	}

	// Release the previous payload buffer.
	cr.payload.Release()

	// In Shadowsocks-AEAD, each chunk consists of two
	// encrypted messages.  The first message contains the payload length,
	// and the second message is the payload.  Idle read threads will
	// block here until the next chunk.
	if err := cr.readMessage(cr.payloadSizeBuf); err != nil {
		if err != io.EOF && err != io.ErrUnexpectedEOF {
			err = fmt.Errorf("failed to read payload size: %w", err)
		}
		return nil, err
	}
	size := int(binary.BigEndian.Uint16(cr.payloadSizeBuf)) & cr.maxPayloadSize
	sizeWithTag := size + cr.aead.Overhead()
	payloadBuf := cr.payload.Acquire()
	if cap(payloadBuf) < sizeWithTag {
		// This code is unreachable if the constants are set correctly.
		return nil, io.ErrShortBuffer
	}
	if err := cr.readMessage(payloadBuf[:sizeWithTag]); err != nil {
		if err == io.EOF { // EOF is not expected mid-chunk.
			err = io.ErrUnexpectedEOF
		}
		cr.payload.Release()
		return nil, err
	}
	return payloadBuf[:size], nil
}

func (cr *chunkReader) Salt() []byte {
	return cr.salt
}

// Reader is an io.Reader that also implements io.WriterTo to
// allow for piping the data without extra allocations and copies.
type Reader interface {
	io.Reader
	io.WriterTo

	// Salt returns the salt used by this instance to derive the subkey.
	Salt() []byte

	// EnsureLeftover makes sure that the leftover slice is not nil.
	// If it's nil, a read is attempted and the result is returned.
	EnsureLeftover() error

	// LeftoverZeroCopy returns the leftover slice without copying.
	// The content of the returned slice won't change until next read.
	LeftoverZeroCopy() []byte
}

// readConverter adapts from ChunkReader, with source-controlled
// chunk sizes, to Go-style IO.
type readConverter struct {
	cr       ChunkReader
	leftover []byte
}

// NewShadowsocksReader creates a Reader that decrypts the given Reader using
// the shadowsocks protocol with the given shadowsocks cipher.
func NewShadowsocksReader(reader io.Reader, ssCipher *Cipher) Reader {
	var maxPayloadSize int

	switch {
	case ssCipher.config.IsSpec2022:
		maxPayloadSize = shadowsocks2022MaxPayloadSize
	default:
		maxPayloadSize = legacyPayloadSizeMask
	}

	return &readConverter{
		cr: &chunkReader{
			reader:         reader,
			ssCipher:       ssCipher,
			payload:        readBufPool.LazySlice(),
			maxPayloadSize: maxPayloadSize,
		},
	}
}

func (c *readConverter) Salt() []byte {
	return c.cr.Salt()
}

func (c *readConverter) LeftoverZeroCopy() (leftover []byte) {
	leftover = c.leftover
	c.leftover = nil
	return
}

func (c *readConverter) Read(b []byte) (int, error) {
	if err := c.EnsureLeftover(); err != nil {
		return 0, err
	}
	n := copy(b, c.leftover)
	c.leftover = c.leftover[n:]
	return n, nil
}

func (c *readConverter) WriteTo(w io.Writer) (written int64, err error) {
	for {
		if err = c.EnsureLeftover(); err != nil {
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
func (c *readConverter) EnsureLeftover() error {
	if len(c.leftover) > 0 {
		return nil
	}
	c.leftover = nil
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
