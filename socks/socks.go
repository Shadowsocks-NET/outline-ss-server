package socks

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strconv"

	onet "github.com/Shadowsocks-NET/outline-ss-server/net"
)

// SOCKS request commands as defined in RFC 1928 section 4.
const (
	CmdConnect      = 1
	CmdBind         = 2
	CmdUDPAssociate = 3
)

// SOCKS address types as defined in RFC 1928 section 5.
const (
	AtypIPv4       = 1
	AtypDomainName = 3
	AtypIPv6       = 4
)

// SOCKS errors as defined in RFC 1928 section 6.
const (
	Succeeded               = 0
	ErrGeneralFailure       = 1
	ErrConnectionNotAllowed = 2
	ErrNetworkUnreachable   = 3
	ErrHostUnreachable      = 4
	ErrConnectionRefused    = 5
	ErrTTLExpired           = 6
	ErrCommandNotSupported  = 7
	ErrAddressNotSupported  = 8
)

const (
	SocksAddressIPv4Length = 1 + net.IPv4len + 2
	SocksAddressIPv6Length = 1 + net.IPv6len + 2

	// MaxAddrLen is the maximum size of SOCKS address in bytes.
	MaxAddrLen = 1 + 1 + 255 + 2
)

// Addr represents a SOCKS address as defined in RFC 1928 section 5.
type Addr []byte

// String serializes SOCKS address a to string form.
func (a Addr) String() string {
	var host, port string

	switch a[0] { // address type
	case AtypDomainName:
		host = string(a[2 : 2+int(a[1])])
		port = strconv.Itoa((int(a[2+int(a[1])]) << 8) | int(a[2+int(a[1])+1]))
	case AtypIPv4:
		host = net.IP(a[1 : 1+net.IPv4len]).String()
		port = strconv.Itoa((int(a[1+net.IPv4len]) << 8) | int(a[1+net.IPv4len+1]))
	case AtypIPv6:
		host = net.IP(a[1 : 1+net.IPv6len]).String()
		port = strconv.Itoa((int(a[1+net.IPv6len]) << 8) | int(a[1+net.IPv6len+1]))
	}

	return net.JoinHostPort(host, port)
}

func (a Addr) Addr(network string) (net.Addr, error) {
	var ip net.IP
	var port int

	switch a[0] {
	case AtypDomainName:
		return onet.NewAddr(a.String(), network), nil
	case AtypIPv4:
		ip = net.IP(a[1 : 1+4])
		port = int(binary.BigEndian.Uint16(a[1+4 : 1+4+2]))
	case AtypIPv6:
		ip = net.IP(a[1 : 1+16])
		port = int(binary.BigEndian.Uint16(a[1+16 : 1+16+2]))
	default:
		return nil, fmt.Errorf("unknown atyp %v", a[0])
	}

	switch network {
	case "tcp", "tcp4", "tcp6":
		return &net.TCPAddr{
			IP:   ip,
			Port: port,
		}, nil
	case "udp", "udp4", "udp6":
		return &net.UDPAddr{
			IP:   ip,
			Port: port,
		}, nil
	default:
		return nil, fmt.Errorf("unknown network %s", network)
	}
}

func (a Addr) UDPAddr(preferIPv6 bool) (*net.UDPAddr, error) {
	switch a[0] {
	case AtypDomainName:
		return resolveUDPAddr(a.String(), preferIPv6)
	case AtypIPv4:
		return &net.UDPAddr{
			IP:   net.IP(a[1 : 1+4]),
			Port: int(binary.BigEndian.Uint16(a[1+4 : 1+4+2])),
		}, nil
	case AtypIPv6:
		return &net.UDPAddr{
			IP:   net.IP(a[1 : 1+16]),
			Port: int(binary.BigEndian.Uint16(a[1+16 : 1+16+2])),
		}, nil
	default:
		return nil, fmt.Errorf("unknown atyp %v", a[0])
	}
}

// resolveUDPAddr resolves an address in domain:port format into *net.UDPAddr.
// ip:port is not supported.
func resolveUDPAddr(address string, preferIPv6 bool) (*net.UDPAddr, error) {
	if !preferIPv6 {
		return net.ResolveUDPAddr("udp", address)
	}

	// Although !preferIPv6 was short-circuited to use net.ResolveUDPAddr(),
	// the following code is generic and takes preferIPv6 into account.

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	portNum, err := net.LookupPort("udp", port)
	if err != nil {
		return nil, err
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}

	// We can't actually do fallbacks here.
	// If preferIPv6 is true, v6 -> primaries, v4 -> fallbacks.
	// And vice versa.
	// Then we select a random IP from primaries, or fallbacks if primaries is empty.
	var primaries, fallbacks []net.IP

	for _, ipc := range ips {
		ip4 := ipc.To4()
		switch {
		case preferIPv6 && ip4 == nil || !preferIPv6 && ip4 != nil: // Prefer 6/4 and got 6/4
			primaries = append(primaries, ipc)
		case preferIPv6 && ip4 != nil || !preferIPv6 && ip4 == nil: // Prefer 6/4 and got 4/6
			fallbacks = append(fallbacks, ipc)
		}
	}

	var ip net.IP

	switch {
	case len(primaries) > 0:
		ip = primaries[rand.Intn(len(primaries))]
	case len(fallbacks) > 0:
		ip = fallbacks[rand.Intn(len(fallbacks))]
	default:
		return nil, errors.New("lookup returned no addresses and no error")
	}

	return &net.UDPAddr{
		IP:   ip,
		Port: portNum,
	}, nil
}

// WriteAddr parses an address string into a socks address
// and writes to the destination slice.
//
// The destination slice must be big enough to hold the socks address.
// Otherwise, this function might panic.
func WriteAddr(dst []byte, s string) (n int, host string, port int, err error) {
	host, portString, err := net.SplitHostPort(s)
	if err != nil {
		err = fmt.Errorf("failed to split host:port: %w", err)
		return
	}

	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			dst[n] = AtypIPv4
			n++
			n += copy(dst[n:], ip4)
		} else {
			dst[n] = AtypIPv6
			n++
			n += copy(dst[n:], ip)
		}
	} else {
		if len(host) > 255 {
			err = fmt.Errorf("host is too long: %d, must not be greater than 255", len(host))
			return
		}
		dst[n] = AtypDomainName
		n++
		dst[n] = byte(len(host))
		n++
		n += copy(dst[n:], host)
	}

	portnum, err := strconv.ParseUint(portString, 10, 16)
	if err != nil {
		err = fmt.Errorf("failed to parse port string: %w", err)
		return
	}
	binary.BigEndian.PutUint16(dst[n:], uint16(portnum))
	n += 2
	port = int(portnum)

	return
}

// WriteUDPAddrAsSocksAddr converts a UDP address
// into socks address and writes to the buffer.
//
// No buffer length checks are performed.
// Make sure the buffer can hold the socks address.
func WriteUDPAddrAsSocksAddr(b []byte, addr *net.UDPAddr) (n int) {
	n = 1

	if ip4 := addr.IP.To4(); ip4 != nil {
		b[0] = AtypIPv4
		n += copy(b[n:], ip4)
	} else {
		b[0] = AtypIPv6
		n += copy(b[n:], addr.IP)
	}

	binary.BigEndian.PutUint16(b[n:], uint16(addr.Port))
	n += 2
	return
}

// ParseAddr parses an address string into a socks address.
//
// To avoid allocation, use WriteAddr instead.
func ParseAddr(s string) (Addr, error) {
	dst := make([]byte, MaxAddrLen)
	n, _, _, err := WriteAddr(dst, s)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}

// ReadAddr reads just enough bytes from r to get a valid Addr.
//
// The destination slice must be big enough to hold the socks address.
// Otherwise, this function might panic.
func ReadAddr(dst []byte, r io.Reader) (n int, err error) {
	n, err = io.ReadFull(r, dst[:1]) // read 1st byte for address type
	if err != nil {
		return
	}

	switch dst[0] {
	case AtypDomainName:
		_, err = io.ReadFull(r, dst[1:2]) // read 2nd byte for domain length
		if err != nil {
			return
		}
		domainLen := int(dst[1])
		n += 1 + domainLen + 2
		_, err = io.ReadFull(r, dst[2:n])
		return
	case AtypIPv4:
		n += net.IPv4len + 2
		_, err = io.ReadFull(r, dst[1:n])
		return
	case AtypIPv6:
		n += net.IPv6len + 2
		_, err = io.ReadFull(r, dst[1:n])
		return
	}

	err = fmt.Errorf("unknown atyp %v", dst[0])
	return
}

// AddrFromReader allocates and reads a socks address from an io.Reader.
//
// To avoid allocation, use ReadAddr instead.
func AddrFromReader(r io.Reader) (Addr, error) {
	dst := make([]byte, MaxAddrLen)
	n, err := ReadAddr(dst, r)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}

// SplitAddr slices a SOCKS address from beginning of b. Returns nil if failed.
func SplitAddr(b []byte) (Addr, error) {
	addrLen := 1
	if len(b) < addrLen {
		return nil, io.ErrShortBuffer
	}

	switch b[0] {
	case AtypDomainName:
		if len(b) < 2 {
			return nil, io.ErrShortBuffer
		}
		addrLen = 1 + 1 + int(b[1]) + 2
	case AtypIPv4:
		addrLen = SocksAddressIPv4Length
	case AtypIPv6:
		addrLen = SocksAddressIPv6Length
	default:
		return nil, fmt.Errorf("unknown atyp %v", b[0])
	}

	if len(b) < addrLen {
		return nil, io.ErrShortBuffer
	}

	return b[:addrLen], nil
}
