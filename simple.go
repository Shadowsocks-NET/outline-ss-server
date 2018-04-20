package main

import (
	"flag"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/shadowsocks/go-shadowsocks2/core"
	sio "github.com/shadowsocks/go-shadowsocks2/io"
	"github.com/shadowsocks/go-shadowsocks2/shadowaead"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

var config struct {
	UDPTimeout time.Duration
}

type measuredReader struct {
	io.Reader
	count func(int)
}

func (r *measuredReader) Read(b []byte) (int, error) {
	n, err := r.Reader.Read(b)
	r.count(n)
	return n, err
}

func (r *measuredReader) WriteTo(w io.Writer) (int64, error) {
	n, err := io.Copy(w, r.Reader)
	r.count(int(n))
	return n, err
}

type measuredWriter struct {
	io.Writer
	count func(int)
}

func (w *measuredWriter) Write(b []byte) (int, error) {
	n, err := w.Writer.Write(b)
	w.count(n)
	return n, err
}

func (w *measuredWriter) ReadFrom(r io.Reader) (int64, error) {
	n, err := io.Copy(w.Writer, r)
	w.count(int(n))
	return n, err
}

// Listen on addr for incoming connections.
func tcpRemote(addr string, cipher shadowaead.Cipher) {
	receivedData := 0
	sentData := 0
	incrementReceivedData := func(n int) {
		receivedData += n
	}
	incrementSentData := func(n int) {
		sentData += n
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("failed to listen on %s: %v", addr, err)
		return
	}

	log.Printf("listening TCP on %s", addr)
	for {
		clientConn, err := l.(*net.TCPListener).AcceptTCP()
		if err != nil {
			log.Printf("failed to accept: %v", err)
			return
		}

		go func() {
			defer func() {
				log.Printf("Total bytes received: %v\n", receivedData)
				log.Printf("Total bytes send: %v\n", sentData)
			}()
			defer log.Printf("Done")
			defer clientConn.Close()
			clientConn.SetKeepAlive(true)
			shadowReader := shadowaead.NewShadowsocksReader(
				&measuredReader{clientConn, incrementReceivedData}, cipher)
			shadowWriter := shadowaead.NewShadowsocksWriter(
				&measuredWriter{clientConn, incrementSentData}, cipher)

			tgt, err := socks.ReadAddr(shadowReader)
			if err != nil {
				log.Printf("failed to get target address: %v", err)
				return
			}

			c, err := net.Dial("tcp", tgt.String())
			if err != nil {
				log.Printf("failed to connect to target: %v", err)
				return
			}
			tgtConn := c.(*net.TCPConn)
			defer tgtConn.Close()
			tgtConn.SetKeepAlive(true)
			tgtReader := &measuredReader{tgtConn, incrementReceivedData}
			tgtWriter := &measuredWriter{tgtConn, incrementSentData}

			log.Printf("proxy %s <-> %s", clientConn.RemoteAddr(), tgt)
			_, _, err = sio.Relay(
				shadowReader, clientConn.CloseRead,
				shadowWriter, clientConn.CloseWrite,
				tgtReader, tgtConn.CloseRead,
				tgtWriter, tgtConn.CloseWrite)
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
	aead, ok := ciph.(shadowaead.Cipher)
	if !ok {
		log.Fatal("Only AEAD ciphers are supported")
	}

	// go udpRemote(addr, ciph.PacketConn)
	go tcpRemote(flags.Server, aead)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}
