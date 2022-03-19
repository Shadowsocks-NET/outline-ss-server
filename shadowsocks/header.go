package shadowsocks

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"time"

	"github.com/Shadowsocks-NET/outline-ss-server/slicepool"
	"github.com/Shadowsocks-NET/outline-ss-server/socks"
)

const (
	HeaderTypeClientStream = 0
	HeaderTypeServerStream = 1

	HeaderTypeClientPacket = 0
	HeaderTypeServerPacket = 1

	MinPaddingLength = 0
	MaxPaddingLength = 900

	// type + 64-bit timestamp + socks address + padding length + padding
	TCPReqHeaderMaxLength = 1 + 8 + socks.MaxAddrLen + 2 + MaxPaddingLength

	// type + 64-bit timestamp + max salt length
	TCPRespHeaderMaxLength = 1 + 8 + 32

	SeparateHeaderMinClientPacketID = 0
	SeparateHeaderMinServerPacketID = 1 << 63
)

var (
	ErrBadTimestamp            = errors.New("time diff is over 30 seconds")
	ErrTypeMismatch            = errors.New("header type mismatch")
	ErrPaddingLengthOutOfRange = errors.New("padding length is less than 0 or greater than 900")
	ErrClientSaltMismatch      = errors.New("client salt in response header does not match request")
	ErrSessionIDMismatch       = errors.New("unexpected session ID")

	tcpReqHeaderPool = slicepool.MakePool(TCPReqHeaderMaxLength)
)

func ParseTCPReqHeader(r io.Reader, cipherConfig CipherConfig, htype byte) (string, error) {
	if !cipherConfig.IsSpec2022 {
		a, err := socks.AddrFromReader(r)
		if err != nil {
			return "", err
		}
		return a.String(), nil
	}

	lazySlice := tcpReqHeaderPool.LazySlice()
	b := lazySlice.Acquire()
	defer lazySlice.Release()

	// Read type & timestamp
	_, err := io.ReadFull(r, b[:1+8])
	if err != nil {
		return "", fmt.Errorf("failed to read type and timestamp: %w", err)
	}

	// Verify type
	if b[0] != htype {
		return "", ErrTypeMismatch
	}

	// Verify timestamp
	epoch := int64(binary.BigEndian.Uint64(b[1 : 1+8]))
	nowEpoch := time.Now().Unix()
	diff := epoch - nowEpoch
	if diff < -30 || diff > 30 {
		return "", ErrBadTimestamp
	}

	offset := 1 + 8

	// Read socks address
	n, err := socks.ReadAddr(b[offset:], r)
	if err != nil {
		return "", fmt.Errorf("failed to read socks address: %w", err)
	}
	socksaddr := socks.Addr(b[offset : offset+n])
	offset += n

	// Read padding length
	_, err = io.ReadFull(r, b[offset:offset+2])
	if err != nil {
		return "", fmt.Errorf("failed to read padding length: %w", err)
	}

	// Verify padding length
	paddingLen := int(binary.BigEndian.Uint16(b[offset : offset+2]))
	if paddingLen < MinPaddingLength || paddingLen > MaxPaddingLength {
		return "", ErrPaddingLengthOutOfRange
	}

	// Read padding
	if paddingLen > 0 {
		_, err := io.ReadFull(r, b[offset+2:offset+2+paddingLen])
		if err != nil {
			return "", fmt.Errorf("failed to read padding: %w", err)
		}
	}

	return socksaddr.String(), nil
}

func LazyWriteTCPReqHeader(address string, ssw *Writer) error {
	if !ssw.ssCipher.config.IsSpec2022 {
		tgtAddr, err := socks.ParseAddr(address)
		if err != nil {
			return fmt.Errorf("failed to write target address: %w", err)
		}
		_, err = ssw.LazyWrite(tgtAddr)
		return err
	}

	lazySlice := tcpReqHeaderPool.LazySlice()
	b := lazySlice.Acquire()
	defer lazySlice.Release()

	// Write type
	b[0] = HeaderTypeClientStream

	// Write timestamp
	nowEpoch := time.Now().Unix()
	binary.BigEndian.PutUint64(b[1:], uint64(nowEpoch))

	offset := 1 + 8

	// Write socks address
	n, _, _, err := socks.WriteAddr(b[offset:], address)
	if err != nil {
		return fmt.Errorf("failed to write socks address: %w", err)
	}
	offset += n

	// Ensure padding length is 0
	b[offset] = 0
	b[offset+1] = 0

	_, err = ssw.LazyWrite(b[:offset+2])
	if err != nil {
		return fmt.Errorf("failed to lazy-write: %w", err)
	}

	return nil
}

func ParseTCPRespHeader(r io.Reader, clientSalt []byte, cipherConfig CipherConfig) error {
	if !cipherConfig.IsSpec2022 {
		return nil
	}

	b := make([]byte, 1+8+len(clientSalt))

	// Read response header
	_, err := io.ReadFull(r, b)
	if err != nil {
		return fmt.Errorf("failed to read response header: %w", err)
	}

	// Verify type
	if b[0] != HeaderTypeServerStream {
		return ErrTypeMismatch
	}

	// Verify timestamp
	epoch := int64(binary.BigEndian.Uint64(b[1 : 1+8]))
	nowEpoch := time.Now().Unix()
	diff := epoch - nowEpoch
	if diff < -30 || diff > 30 {
		return ErrBadTimestamp
	}

	// Verify client salt
	n := bytes.Compare(clientSalt, b[1+8:])
	if n != 0 {
		return ErrClientSaltMismatch
	}

	return nil
}

func MakeTCPRespHeader(clientSalt []byte) []byte {
	b := make([]byte, 1+8+len(clientSalt))

	b[0] = HeaderTypeServerStream

	nowEpoch := time.Now().Unix()
	binary.BigEndian.PutUint64(b[1:1+8], uint64(nowEpoch))

	copy(b[1+8:], clientSalt)

	return b
}

func LazyWriteTCPRespHeader(clientSalt []byte, ssw *Writer) error {
	if !ssw.ssCipher.config.IsSpec2022 {
		return nil
	}

	rh := MakeTCPRespHeader(clientSalt)
	_, err := ssw.LazyWrite(rh)
	return err
}

// For spec 2022, this function only parses the decrypted AEAD header.
func ParseUDPHeader(plaintext []byte, htype byte, cipherConfig CipherConfig) (address string, payload []byte, err error) {
	var offset int

	if cipherConfig.IsSpec2022 {
		// Filter out short packets
		if len(plaintext) < 16+1+8+3 {
			err = fmt.Errorf("packet too short: %d", len(plaintext))
			return
		}

		// Session ID, packet ID
		offset += 16

		// Verify type
		if plaintext[offset] != htype {
			err = ErrTypeMismatch
			return
		}

		offset++

		// Verify timestamp
		epoch := int64(binary.BigEndian.Uint64(plaintext[offset : offset+8]))
		nowEpoch := time.Now().Unix()
		diff := epoch - nowEpoch
		if diff < -30 || diff > 30 {
			err = ErrBadTimestamp
			return
		}

		offset += 8
	}

	// Parse socks address
	tgtAddr, err := socks.SplitAddr(plaintext[offset:])
	if err != nil {
		err = fmt.Errorf("failed to parse target address: %w", err)
		return
	}

	offset += len(tgtAddr)

	if cipherConfig.IsSpec2022 {
		// Verify padding length
		if len(plaintext) < offset+2 {
			err = fmt.Errorf("packet too short to contain padding length field: %d", len(plaintext))
			return
		}

		paddingLen := int(binary.BigEndian.Uint16(plaintext[offset : offset+2]))
		if paddingLen < MinPaddingLength || paddingLen > MaxPaddingLength {
			err = ErrPaddingLengthOutOfRange
			return
		}

		offset += 2

		// Verify padding
		if len(plaintext) < offset+paddingLen {
			err = fmt.Errorf("packet too short (%d) to contain specified length (%d) of padding", len(plaintext), paddingLen)
			return
		}

		offset += paddingLen
	}

	return tgtAddr.String(), plaintext[offset:], nil
}

// WriteUDPAddrToSocksAddr converts a UDP address
// into socks address and writes to the buffer.
//
// No buffer length checks are performed.
// Make sure the buffer can hold the socks address.
func WriteUDPAddrToSocksAddr(b []byte, addr *net.UDPAddr) (n int) {
	n = 1

	if ip4 := addr.IP.To4(); ip4 != nil {
		b[0] = socks.AtypIPv4
		n += copy(b[n:], ip4)
	} else {
		b[0] = socks.AtypIPv6
		n += copy(b[n:], addr.IP)
	}

	binary.BigEndian.PutUint16(b[n:], uint16(addr.Port))
	n += 2
	return
}

func WriteRandomPadding(b []byte, targetPort int, max int) int {
	if len(b) > max || targetPort != 53 {
		b[0] = 0
		b[1] = 0
		return 2
	}

	paddingLen := rand.Intn(max)
	binary.BigEndian.PutUint16(b, uint16(paddingLen))
	return 2 + paddingLen
}

// WriteUDPHeader fills a UDP header into the buffer.
//
// No buffer length checks are performed.
// Make sure the buffer can hold the socks address.
func WriteUDPHeader(plaintext []byte, htype byte, sid []byte, pid uint64, targetAddr *net.UDPAddr, maxPacketSize int) (n int) {
	// Write session ID
	copy(plaintext[24:24+8], sid)

	// Write packet ID
	binary.BigEndian.PutUint64(plaintext[24+8:24+8+8], pid)

	// Write type
	plaintext[24+8+8] = htype

	// Write timestamp
	nowEpoch := time.Now().Unix()
	binary.BigEndian.PutUint64(plaintext[24+8+8+1:24+8+8+8+1], uint64(nowEpoch))

	// Write socks address
	n = 24 + 8 + 8 + 1 + 8
	n += WriteUDPAddrToSocksAddr(plaintext[n:], targetAddr)

	// Write padding length and optionally padding
	n += WriteRandomPadding(plaintext[n:], targetAddr.Port, maxPacketSize-n-2)

	return
}

// WriteUDPHeaderSeparated fills the separate header and the in-AEAD UDP header into the buffer.
//
// No buffer length checks are performed.
// Make sure the buffer can hold the socks address.
func WriteUDPHeaderSeparated(plaintext []byte, htype byte, sid []byte, pid uint64, targetAddr *net.UDPAddr, maxPacketSize int) (n int) {
	// Write session ID
	copy(plaintext[:8], sid)

	// Write packet ID
	binary.BigEndian.PutUint64(plaintext[8:8+8], pid)

	// Write type
	plaintext[16] = htype

	// Write timestamp
	nowEpoch := time.Now().Unix()
	binary.BigEndian.PutUint64(plaintext[16+1:16+1+8], uint64(nowEpoch))

	// Write socks address
	n = 16 + 1 + 8
	n += WriteUDPAddrToSocksAddr(plaintext[n:], targetAddr)

	// Write padding length and optionally padding
	n += WriteRandomPadding(plaintext[n:], targetAddr.Port, maxPacketSize-n-2)

	return
}

// WriteClientUDPHeaderPartial writes the first 8+8+1+8 bytes of header to the buffer.
func WriteClientUDPHeaderPartial(plaintext []byte, cipherConfig CipherConfig, sid []byte, pid uint64) (n int) {
	if cipherConfig.IsSpec2022 && !cipherConfig.UDPHasSeparateHeader {
		n = 24
	}

	switch {
	case cipherConfig.IsSpec2022:
		// Write session ID
		n += copy(plaintext[n:n+8], sid)

		// Write packet ID
		binary.BigEndian.PutUint64(plaintext[n:n+8], pid)
		n += 8

		// Write type
		plaintext[n] = HeaderTypeClientPacket
		n++

		// Write timestamp
		nowEpoch := time.Now().Unix()
		binary.BigEndian.PutUint64(plaintext[n:n+8], uint64(nowEpoch))
		n += 8
	}

	return
}

func WriteClientUDPHeader(plaintext []byte, cipherConfig CipherConfig, sid []byte, pid uint64, targetAddr net.Addr, maxPacketSize int) (n int, err error) {
	n += WriteClientUDPHeaderPartial(plaintext, cipherConfig, sid, pid)

	// Write socks address
	var port int

	if udpaddr, ok := targetAddr.(*net.UDPAddr); ok {
		port = udpaddr.Port
		n += WriteUDPAddrToSocksAddr(plaintext[n:], udpaddr)
	} else {
		var san int
		san, _, port, err = socks.WriteAddr(plaintext[n:], targetAddr.String())
		if err != nil {
			return
		}
		n += san
	}

	// Write padding length and optionally padding
	if cipherConfig.IsSpec2022 {
		n += WriteRandomPadding(plaintext[n:], port, maxPacketSize-n-2)
	}

	return
}
