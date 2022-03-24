//go:build !linux

package net

import "net"

// ListenUDP wraps Go's net.ListenConfig.ListenPacket and
// sets IP_PKTINFO, IPV6_RECVPKTINFO socket options on the returned socket.
func ListenUDP(network string, laddr *net.UDPAddr) (conn UDPPacketConn, err error, serr error) {
	conn, err = net.ListenUDP(network, laddr)
	return
}

// GetOobForCache filters out irrelevant OOB messages
// and returns only IP_PKTINFO or IPV6_PKTINFO socket control messages.
//
// Errors returned by this function can be safely ignored,
// or printed as debug logs.
func GetOobForCache(clientOob []byte) ([]byte, error) {
	return nil, nil
}
