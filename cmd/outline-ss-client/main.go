package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Shadowsocks-NET/outline-ss-server/client"
	"github.com/Shadowsocks-NET/outline-ss-server/service"
)

func main() {
	var address string
	var method string
	var psk string

	var tunnelListenAddress string
	var tunnelRemoteAddress string
	var tunnelTCP bool
	var tunnelUDP bool

	var TCPFastOpen bool
	var listenerTFO bool
	var dialerTFO bool

	flag.StringVar(&address, "address", "", "shadowsocks server address host:port")
	flag.StringVar(&method, "method", "chacha20-ietf-poly1305", "shadowsocks server method")
	flag.StringVar(&psk, "psk", "", "shadowsocks server pre-shared key")

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

	saltPool := service.NewSaltPool()

	c, err := client.NewClient(address, method, psk, saltPool)
	if err != nil {
		log.Fatal(err)
	}

	var services []client.Service

	if tunnelTCP {
		s := client.NewTCPTunnelService(tunnelListenAddress, tunnelRemoteAddress, listenerTFO, dialerTFO, c)
		s.Start()
		services = append(services, s)
	}

	if tunnelUDP {
		s := client.NewUDPTunnelService(tunnelListenAddress, tunnelRemoteAddress, c)
		s.Start()
		services = append(services, s)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh

	log.Printf("Received %s, stopping...", sig.String())

	for _, s := range services {
		s.Stop()
		log.Printf("Stopped %s", s.Name())
	}
}
