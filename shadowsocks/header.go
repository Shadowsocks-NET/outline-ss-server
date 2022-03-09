package shadowsocks

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/Shadowsocks-NET/outline-ss-server/slicepool"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

const (
	HeaderTypeServerStream = 0
	HeaderTypeClientStream = 1

	MinPaddingLength = 0
	MaxPaddingLength = 900

	// type + 64-bit timestamp + socks address + padding length + padding
	TCPReqHeaderMaxLength = 1 + 8 + socks.MaxAddrLen + 2 + MaxPaddingLength

	// type + 64-bit timestamp + max salt length
	TCPRespHeaderMaxLength = 1 + 8 + 32
)

var (
	ErrBadTimestamp            = errors.New("time diff is over 30 seconds")
	ErrTypeMismatch            = errors.New("header type mismatch")
	ErrUnknownATYP             = errors.New("unknown ATYP in socks address")
	ErrPaddingLengthOutOfRange = errors.New("padding length is less than 0 or greater than 900")
	ErrClientSaltMismatch      = errors.New("client salt in response header does not match request")

	tcpReqHeaderPool = slicepool.MakePool(TCPReqHeaderMaxLength)
)

func ParseTCPReqHeader(r io.Reader, cipherConfig CipherConfig, htype byte) (string, error) {
	if !cipherConfig.IsSpec2022 {
		a, err := socks.ReadAddr(r)
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
		return "", fmt.Errorf("failed to read type and timestamp %w", err)
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

	// Read ATYP
	_, err = io.ReadFull(r, b[1+8:1+8+1])
	if err != nil {
		return "", fmt.Errorf("failed to read ATYP %w", err)
	}

	// Read addr
	var offset int
	var socksaddr socks.Addr
	switch b[1+8] {
	case socks.AtypDomainName:
		_, err := io.ReadFull(r, b[1+8+1:1+8+1+1])
		if err != nil {
			return "", fmt.Errorf("failed to read domain name length %w", err)
		}
		offset = 1 + 8 + 1 + 1 + int(b[1+8+1]) + 2
		_, err = io.ReadFull(r, b[1+8+1+1:offset])
		if err != nil {
			return "", fmt.Errorf("failed to read domain name %w", err)
		}
		socksaddr = b[1+8 : offset]
	case socks.AtypIPv4:
		offset = 1 + 8 + 1 + net.IPv4len + 2
		_, err := io.ReadFull(r, b[1+8+1:offset])
		if err != nil {
			return "", fmt.Errorf("failed to read IPv4 %w", err)
		}
		socksaddr = b[1+8 : offset]
	case socks.AtypIPv6:
		offset = 1 + 8 + 1 + net.IPv6len + 2
		_, err := io.ReadFull(r, b[1+8+1:offset])
		if err != nil {
			return "", fmt.Errorf("failed to read IPv6 %w", err)
		}
		socksaddr = b[1+8 : offset]
	default:
		return "", ErrUnknownATYP
	}

	// Read padding length
	_, err = io.ReadFull(r, b[offset:offset+2])
	if err != nil {
		return "", fmt.Errorf("failed to read padding length %w", err)
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
			return "", fmt.Errorf("failed to read padding %w", err)
		}
	}

	return socksaddr.String(), nil
}

func LazyWriteTCPReqHeader(address string, ssw *Writer) error {
	if !ssw.ssCipher.config.IsSpec2022 {
		tgtAddr := socks.ParseAddr(address)
		if tgtAddr == nil {
			return errors.New("failed to write target address")
		}
		_, err := ssw.LazyWrite(tgtAddr)
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

	// Write socks address
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("failed to split host:port %w", err)
	}

	var offset int

	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			b[1+8] = socks.AtypIPv4
			copy(b[1+8+1:], ip4)
			offset = 1 + 8 + 1 + net.IPv4len + 2
		} else {
			b[1+8] = socks.AtypIPv6
			copy(b[1+8+1:], ip)
			offset = 1 + 8 + 1 + net.IPv6len + 2
		}
	} else {
		if len(host) > 255 {
			return fmt.Errorf("host is too long: %d, must not be greater than 255", len(host))
		}
		b[1+8] = socks.AtypDomainName
		b[1+8+1] = byte(len(host))
		copy(b[1+8+1+1:], host)
		offset = 1 + 8 + 1 + 1 + len(host) + 2
	}

	portnum, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return fmt.Errorf("failed to parse port string: %s", port)
	}
	binary.BigEndian.PutUint16(b[offset-2:], uint16(portnum))

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
		return fmt.Errorf("failed to read response header %w", err)
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
