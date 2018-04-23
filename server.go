package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
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

func findCipher(clientReader shadowaead.ShadowsocksReader, cipherList []shadowaead.Cipher) (shadowaead.Cipher, io.Reader, error) {
	if len(cipherList) == 0 {
		return nil, nil, errors.New("Empty cipher list")
	} else if len(cipherList) == 1 {
		return cipherList[0], shadowaead.NewShadowsocksReader(clientReader, cipherList[0]), nil
	}
	// buffer saves the bytes read from shadowConn, in order to allow for replays.
	var buffer bytes.Buffer
	// Try each cipher until we find one that authenticates successfully.
	// This assumes that all ciphers are AEAD.
	for i, cipher := range cipherList {
		log.Printf("Trying cipher %v", i)
		// tmpReader reuses the bytes read so far, falling back to shadowConn if it needs more
		// bytes. All bytes read from shadowConn are saved in buffer.
		tmpReader := io.MultiReader(bytes.NewReader(buffer.Bytes()), io.TeeReader(clientReader, &buffer))
		// Override the Reader of shadowConn so we can reset it for each cipher test.
		cipherReader := shadowaead.NewShadowsocksReader(tmpReader, cipher)
		// Read should read just enough data to authenticate the payload size.
		_, err := cipherReader.Read(make([]byte, 0))
		if err != nil {
			log.Printf("Failed cipher %v", i)
			continue
		}
		log.Printf("Selected cipher %v", i)
		// We don't need to replay the bytes anymore, but we don't want to drop those
		// read so far.
		return cipher, shadowaead.NewShadowsocksReader(io.MultiReader(&buffer, clientReader), cipher), nil
	}
	return nil, nil, fmt.Errorf("could not find valid cipher")
}

// Listen on addr for incoming connections.
func tcpRemote(addr string, cipherList []shadowaead.Cipher) {
	receivedData := 0
	sentData := 0
	incReceivedData := func(n int) {
		receivedData += n
	}
	incSentData := func(n int) {
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
			cipher, shadowReader, err := findCipher(&measuredReader{clientConn, incReceivedData}, cipherList)
			if err != nil {
				log.Printf("Failed to find a valid cipher: %v", err)
			}
			shadowWriter := shadowaead.NewShadowsocksWriter(
				&measuredWriter{clientConn, incSentData}, cipher)

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
			tgtReader := &measuredReader{tgtConn, incReceivedData}
			tgtWriter := &measuredWriter{tgtConn, incSentData}

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

type cipherList []shadowaead.Cipher

func main() {

	var flags struct {
		Server  string
		Ciphers cipherList
	}

	flag.StringVar(&flags.Server, "s", "", "server listen address or url")
	flag.Var(&flags.Ciphers, "u", "available ciphers: "+strings.Join(core.ListCipher(), " "))
	flag.DurationVar(&config.UDPTimeout, "udptimeout", 5*time.Minute, "UDP tunnel timeout")
	flag.Parse()

	if flags.Server == "" || len(flags.Ciphers) == 0 {
		flag.Usage()
		return
	}

	// go udpRemote(addr, ciph.PacketConn)
	go tcpRemote(flags.Server, flags.Ciphers)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}

func (sl *cipherList) Set(flagValue string) error {
	e := strings.SplitN(flagValue, ":", 2)
	if len(e) != 2 {
		return fmt.Errorf("Missing colon")
	}
	cipher, err := core.PickCipher(e[0], nil, e[1])
	if err != nil {
		return err
	}
	aead, ok := cipher.(shadowaead.Cipher)
	if !ok {
		log.Fatal("Only AEAD ciphers are supported")
	}
	*sl = append(*sl, aead)
	return nil
}

func (sl *cipherList) String() string {
	return fmt.Sprint(*sl)
}
