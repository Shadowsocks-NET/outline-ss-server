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

package service

import (
	"context"
	"net"
	"syscall"
	"unsafe"

	onet "github.com/Shadowsocks-NET/outline-ss-server/net"
	"golang.org/x/sys/unix"
)

func ListenUDP(network string, laddr *net.UDPAddr) (onet.UDPPacketConn, error) {
	lc := &net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				// Always set IP_PKTINFO
				if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_PKTINFO, 1); err != nil {
					logger.Errorf("failed to set socket option IP_PKTINFO: %v", err)
					return
				}
				logger.Debugf("successfully set IP_PKTINFO on %s", network)

				if network == "udp6" {
					if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1); err != nil {
						logger.Errorf("failed to set socket option IPV6_RECVPKTINFO: %v", err)
						return
					}
					logger.Debugf("successfully set IPV6_RECVPKTINFO on %s", network)
				}
			})
		},
	}

	conn, err := lc.ListenPacket(context.Background(), network, laddr.String())
	if err != nil {
		return nil, err
	} else {
		return conn.(onet.UDPPacketConn), err
	}
}

func getOobForCache(clientOob []byte) []byte {
	switch len(clientOob) {
	case unix.SizeofCmsghdr + unix.SizeofInet4Pktinfo:
		return getOobForCache4(clientOob)
	case unix.SizeofCmsghdr + unix.SizeofInet6Pktinfo:
		return getOobForCache6(clientOob)
	case 0:
		logger.Debug("getOobForCache processed empty oob")
		return nil
	default:
		logger.Debugf("unknown oob length: %d", len(clientOob))
		return nil
	}
}

type oob4 struct {
	cmsghdr unix.Cmsghdr
	pktinfo unix.Inet4Pktinfo
}

func getOobForCache4(clientOob4 []byte) []byte {
	cmsg := (*oob4)(unsafe.Pointer(&clientOob4))
	if cmsg.cmsghdr.Level == unix.IPPROTO_IP && cmsg.cmsghdr.Type == unix.IP_PKTINFO {
		logger.Debug("successfully cached oob type IP_PKTINFO")
		return (*[unix.SizeofCmsghdr + unix.SizeofInet4Pktinfo]byte)(unsafe.Pointer(&oob4{
			cmsghdr: unix.Cmsghdr{
				Level: unix.IPPROTO_IP,
				Type:  unix.IP_PKTINFO,
				Len:   unix.SizeofCmsghdr + unix.SizeofInet4Pktinfo,
			},
			pktinfo: unix.Inet4Pktinfo{
				Ifindex:  cmsg.pktinfo.Ifindex,
				Spec_dst: cmsg.pktinfo.Spec_dst,
			},
		}))[:]
	} else {
		logger.Debugf("unknown client oob level %d type %d", cmsg.cmsghdr.Level, cmsg.cmsghdr.Type)
		return nil
	}
}

type oob6 struct {
	cmsghdr unix.Cmsghdr
	pktinfo unix.Inet6Pktinfo
}

func getOobForCache6(clientOob6 []byte) []byte {
	cmsg := (*oob6)(unsafe.Pointer(&clientOob6))
	if cmsg.cmsghdr.Level == unix.IPPROTO_IPV6 && cmsg.cmsghdr.Type == unix.IPV6_PKTINFO {
		logger.Debug("successfully cached oob type IPV6_PKTINFO")
		return (*[unix.SizeofCmsghdr + unix.SizeofInet6Pktinfo]byte)(unsafe.Pointer(&oob6{
			cmsghdr: unix.Cmsghdr{
				Level: unix.IPPROTO_IPV6,
				Type:  unix.IPV6_PKTINFO,
				Len:   unix.SizeofCmsghdr + unix.SizeofInet6Pktinfo,
			},
			pktinfo: unix.Inet6Pktinfo{
				Addr:    cmsg.pktinfo.Addr,
				Ifindex: cmsg.pktinfo.Ifindex,
			},
		}))[:]
	} else {
		logger.Debugf("unknown client oob level %d type %d", cmsg.cmsghdr.Level, cmsg.cmsghdr.Type)
		return nil
	}
}
