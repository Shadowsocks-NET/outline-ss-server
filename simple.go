package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/shadowsocks/go-shadowsocks2/core"
	sio "github.com/shadowsocks/go-shadowsocks2/io"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

var config struct {
	UDPTimeout time.Duration
}

// Listen on addr for incoming connections.
func tcpRemote(addr string, shadow func(net.Conn) net.Conn) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("failed to listen on %s: %v", addr, err)
		return
	}

	log.Printf("listening TCP on %s", addr)
	for {
		c, err := l.Accept()
		if err != nil {
			log.Printf("failed to accept: %v", err)
			return
		}

		go func() {
			defer log.Printf("done")
			defer c.Close()
			c.(*net.TCPConn).SetKeepAlive(true)
			c = shadow(c)

			tgt, err := socks.ReadAddr(c)
			if err != nil {
				log.Printf("failed to get target address: %v", err)
				return
			}

			rc, err := net.Dial("tcp", tgt.String())
			if err != nil {
				log.Printf("failed to connect to target: %v", err)
				return
			}
			defer rc.Close()
			rc.(*net.TCPConn).SetKeepAlive(true)

			log.Printf("proxy %s <-> %s", c.RemoteAddr(), tgt)
			_, _, err = sio.Relay(c, rc)
			if err != nil {
				log.Printf("relay error: %v", err)
			}
		}()
	}
}

func main() {

	var flags struct {
		Server   string
		Cipher   string
		Password string
	}

	flag.StringVar(&flags.Server, "s", "", "server listen address or url")
	flag.StringVar(&flags.Cipher, "cipher", "AEAD_CHACHA20_POLY1305", "available ciphers: "+strings.Join(core.ListCipher(), " "))
	flag.StringVar(&flags.Password, "password", "", "password")
	flag.DurationVar(&config.UDPTimeout, "udptimeout", 5*time.Minute, "UDP tunnel timeout")
	flag.Parse()

	if flags.Server == "" || flags.Cipher == "" || flags.Password == "" {
		flag.Usage()
		return
	}

	ciph, err := core.PickCipher(flags.Cipher, nil, flags.Password)
	if err != nil {
		log.Fatal(err)
	}

	// go udpRemote(addr, ciph.PacketConn)
	go tcpRemote(flags.Server, ciph.StreamConn)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}
