package main

import (
	"flag"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/Shadowsocks-NET/outline-ss-server/client"
	"github.com/database64128/tfo-go"
)

func main() {
	var address string
	var method string
	var password string

	var tunnelListenAddress string
	var tunnelRemoteAddress string
	var tunnelTCP bool
	var tunnelUDP bool

	var TCPFastOpen bool
	var listenerTFO bool
	var dialerTFO bool

	flag.StringVar(&address, "address", "", "shadowsocks server address host:port")
	flag.StringVar(&method, "method", "chacha20-ietf-poly1305", "shadowsocks server method")
	flag.StringVar(&password, "password", "", "shadowsocks server password")

	flag.StringVar(&tunnelListenAddress, "tunnelListenAddress", "", "shadowsocks tunnel local listen address")
	flag.StringVar(&tunnelRemoteAddress, "tunnelRemoteAddress", "", "shadowsocks tunnel remote address")
	flag.BoolVar(&tunnelTCP, "tunnelTCP", false, "Whether to tunnel TCP traffic")
	flag.BoolVar(&tunnelUDP, "tunnelUDP", false, "Whether to tunnel UDP traffic")

	flag.BoolVar(&TCPFastOpen, "tfo", false, "Enables TFO for both TCP listener and dialer")
	flag.BoolVar(&listenerTFO, "tfo_listener", false, "Enables TFO for TCP listener")
	flag.BoolVar(&dialerTFO, "tfo_dialer", false, "Enables TFO for TCP listener")

	flag.Parse()

	if TCPFastOpen {
		listenerTFO = true
		dialerTFO = true
	}

	c, err := client.NewClient(address, method, password)
	if err != nil {
		log.Fatal(err)
	}

	if tunnelTCP {
		lc := tfo.ListenConfig{
			DisableTFO: !listenerTFO,
		}
		l, err := lc.Listen(nil, "tcp", tunnelListenAddress)
		if err != nil {
			log.Fatal(err)
		}
		defer l.Close()

		go func() {
			for {
				clientconn, err := l.(*net.TCPListener).AcceptTCP()
				if err != nil {
					log.Print(err)
					continue
				}

				go func() {
					proxyconn, err := c.DialTCP(nil, tunnelRemoteAddress, dialerTFO)
					if err != nil {
						log.Print(err)
					}
					defer proxyconn.Close()

					ch := make(chan error, 1)

					go func() {
						_, err := io.Copy(clientconn, proxyconn)
						clientconn.CloseWrite()
						ch <- err
					}()

					_, err = io.Copy(proxyconn, clientconn)
					proxyconn.CloseWrite()

					innerErr := <-ch

					if err != nil {
						log.Print(err)
					}
					if innerErr != nil {
						log.Print(err)
					}
				}()
			}
		}()
	}

	if tunnelUDP {
		// l, err := net.Listen("udp", tunnelListenAddress)
		// if err != nil {
		// 	log.Fatal(err)
		// }
		// defer l.Close()

		// proxyconn, err := c.ListenUDP(nil)
		// if err != nil {
		// 	log.Fatal(err)
		// }
		// defer proxyconn.Close()

		// go func() {
		// 	for {
		// 		lazySlice := client.UDPPool.LazySlice()
		// 		b := lazySlice.Acquire()
		// 		defer lazySlice.Release()

		// 		n, oobn, flags, raddr, err := l.(*net.UDPConn).ReadMsgUDP(b, oob)
		// 	}
		// }()
		log.Println("not implemented")
		return
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}
