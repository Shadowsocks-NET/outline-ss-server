package client

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	onet "github.com/Shadowsocks-NET/outline-ss-server/net"
	"github.com/Shadowsocks-NET/outline-ss-server/service"
	ss "github.com/Shadowsocks-NET/outline-ss-server/shadowsocks"
	"github.com/Shadowsocks-NET/outline-ss-server/socks"
)

const (
	testPassword   = "testPassword"
	testTargetAddr = "test.local:1111"
)

func TestShadowsocksClient_DialTCP(t *testing.T) {
	proxy, running := startShadowsocksTCPEchoProxy(testTargetAddr, t)
	d, err := NewClient(proxy.Addr().String(), ss.TestCipher, testPassword, nil)
	if err != nil {
		t.Fatalf("Failed to create ShadowsocksClient: %v", err)
	}
	conn, err := d.DialTCP(nil, testTargetAddr, false)
	if err != nil {
		t.Fatalf("ShadowsocksClient.DialTCP failed: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(time.Second * 5))
	expectEchoPayload(conn, ss.MakeTestPayload(1024), make([]byte, 1024), t)
	conn.Close()

	proxy.Close()
	running.Wait()
}

func TestShadowsocksClient_DialTCPNoPayload(t *testing.T) {
	proxy, running := startShadowsocksTCPEchoProxy(testTargetAddr, t)
	d, err := NewClient(proxy.Addr().String(), ss.TestCipher, testPassword, nil)
	if err != nil {
		t.Fatalf("Failed to create ShadowsocksClient: %v", err)
	}
	conn, err := d.DialTCP(nil, testTargetAddr, false)
	if err != nil {
		t.Fatalf("ShadowsocksClient.DialTCP failed: %v", err)
	}

	// Wait for more than 10 milliseconds to ensure that the target
	// address is sent.
	time.Sleep(20 * time.Millisecond)
	// Force the echo server to verify the target address.
	conn.Close()

	proxy.Close()
	running.Wait()
}

func TestShadowsocksClient_DialTCPFastClose(t *testing.T) {
	// Set up a listener that verifies no data is sent.
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenTCP failed: %v", err)
	}

	done := make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			t.Error(err)
		}
		buf := make([]byte, 64)
		n, err := conn.Read(buf)
		if n > 0 || err != io.EOF {
			t.Errorf("Expected EOF, got %v, %v", buf[:n], err)
		}
		listener.Close()
		close(done)
	}()

	d, err := NewClient(listener.Addr().String(), ss.TestCipher, testPassword, nil)
	if err != nil {
		t.Fatalf("Failed to create ShadowsocksClient: %v", err)
	}

	conn, err := d.DialTCP(nil, testTargetAddr, false)
	if err != nil {
		t.Fatalf("ShadowsocksClient.DialTCP failed: %v", err)
	}

	// Wait for less than 10 milliseconds to ensure that the target
	// address is not sent.
	time.Sleep(1 * time.Millisecond)
	// Close the connection before the target address is sent.
	conn.Close()
	// Wait for the listener to verify the close.
	<-done
}

func TestShadowsocksClient_ListenUDP(t *testing.T) {
	proxy, running := startShadowsocksUDPEchoServer(testTargetAddr, t)
	d, err := NewClient(proxy.LocalAddr().String(), ss.TestCipher, testPassword, nil)
	if err != nil {
		t.Fatalf("Failed to create ShadowsocksClient: %v", err)
	}
	conn, err := d.ListenUDP(nil)
	if err != nil {
		t.Fatalf("ShadowsocksClient.ListenUDP failed: %v", err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(time.Second * 5))
	pcrw := &packetConnReadWriter{PacketConn: conn, targetAddr: NewAddr(testTargetAddr, "udp")}
	expectEchoPayload(pcrw, ss.MakeTestPayload(1024), make([]byte, 1024), t)

	proxy.Close()
	running.Wait()
}

func BenchmarkShadowsocksClient_DialTCP(b *testing.B) {
	b.StopTimer()
	b.ResetTimer()

	proxy, running := startShadowsocksTCPEchoProxy(testTargetAddr, b)
	d, err := NewClient(proxy.Addr().String(), ss.TestCipher, testPassword, nil)
	if err != nil {
		b.Fatalf("Failed to create ShadowsocksClient: %v", err)
	}
	conn, err := d.DialTCP(nil, testTargetAddr, false)
	if err != nil {
		b.Fatalf("ShadowsocksClient.DialTCP failed: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(time.Second * 5))
	buf := make([]byte, 1024)
	for n := 0; n < b.N; n++ {
		payload := ss.MakeTestPayload(1024)
		b.StartTimer()
		expectEchoPayload(conn, payload, buf, b)
		b.StopTimer()
	}

	conn.Close()
	proxy.Close()
	running.Wait()
}

func BenchmarkShadowsocksClient_ListenUDP(b *testing.B) {
	b.StopTimer()
	b.ResetTimer()

	proxy, running := startShadowsocksUDPEchoServer(testTargetAddr, b)
	d, err := NewClient(proxy.LocalAddr().String(), ss.TestCipher, testPassword, nil)
	if err != nil {
		b.Fatalf("Failed to create ShadowsocksClient: %v", err)
	}
	conn, err := d.ListenUDP(nil)
	if err != nil {
		b.Fatalf("ShadowsocksClient.ListenUDP failed: %v", err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(time.Second * 5))
	buf := make([]byte, service.UDPPacketBufferSize)
	for n := 0; n < b.N; n++ {
		payload := ss.MakeTestPayload(1024)
		pcrw := &packetConnReadWriter{PacketConn: conn, targetAddr: NewAddr(testTargetAddr, "udp")}
		b.StartTimer()
		expectEchoPayload(pcrw, payload, buf, b)
		b.StopTimer()
	}

	proxy.Close()
	running.Wait()
}

func startShadowsocksTCPEchoProxy(expectedTgtAddr string, t testing.TB) (net.Listener, *sync.WaitGroup) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenTCP failed: %v", err)
	}
	t.Logf("Starting SS TCP echo proxy at %v\n", listener.Addr())
	cipher, err := ss.NewCipher(ss.TestCipher, testPassword)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}
	var running sync.WaitGroup
	running.Add(1)
	go func() {
		defer running.Done()
		defer listener.Close()
		for {
			clientConn, err := listener.AcceptTCP()
			if err != nil {
				t.Logf("AcceptTCP failed: %v", err)
				return
			}
			running.Add(1)
			go func() {
				defer running.Done()
				defer clientConn.Close()
				ssr := ss.NewShadowsocksReader(clientConn, cipher)
				ssw := ss.NewShadowsocksWriter(clientConn, cipher, cipher.Config().IsSpec2022)
				ssClientConn := onet.WrapDuplexConn(clientConn, ssr, ssw)

				tgtAddr, err := socks.AddrFromReader(ssClientConn)
				if err != nil {
					t.Fatalf("Failed to read target address: %v", err)
				}
				if tgtAddr.String() != expectedTgtAddr {
					t.Fatalf("Expected target address '%v'. Got '%v'", expectedTgtAddr, tgtAddr)
				}
				io.Copy(ssw, ssr)
			}()
		}
	}()
	return listener, &running
}

func startShadowsocksUDPEchoServer(expectedTgtAddr string, t testing.TB) (net.Conn, *sync.WaitGroup) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("Proxy ListenUDP failed: %v", err)
	}
	t.Logf("Starting SS UDP echo proxy at %v\n", conn.LocalAddr())
	cipherBuf := make([]byte, service.UDPPacketBufferSize)
	clientBuf := make([]byte, service.UDPPacketBufferSize)
	cipher, err := ss.NewCipher(ss.TestCipher, testPassword)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}
	var running sync.WaitGroup
	running.Add(1)
	go func() {
		defer running.Done()
		defer conn.Close()
		for {
			n, clientAddr, err := conn.ReadFromUDP(cipherBuf)
			if err != nil {
				t.Logf("Failed to read from UDP conn: %v", err)
				return
			}
			buf, err := ss.Unpack(clientBuf, cipherBuf[:n], cipher)
			if err != nil {
				t.Fatalf("Failed to decrypt: %v", err)
			}
			tgtAddr, err := socks.SplitAddr(buf)
			if err != nil {
				t.Fatalf("Failed to read target address: %v", err)
			}
			if tgtAddr.String() != expectedTgtAddr {
				t.Fatalf("Expected target address '%v'. Got '%v'", expectedTgtAddr, tgtAddr)
			}
			// Echo both the payload and SOCKS address.
			buf, err = ss.Pack(cipherBuf, buf, cipher)
			if err != nil {
				t.Fatalf("Failed to encrypt: %v", err)
			}
			conn.WriteTo(buf, clientAddr)
			if err != nil {
				t.Fatalf("Failed to write: %v", err)
			}
		}
	}()
	return conn, &running
}

// io.ReadWriter adapter for net.PacketConn. Used to share code between UDP and TCP tests.
type packetConnReadWriter struct {
	net.PacketConn
	io.ReadWriter
	targetAddr net.Addr
}

func (pc *packetConnReadWriter) Read(b []byte) (n int, err error) {
	n, _, err = pc.PacketConn.ReadFrom(b)
	return
}

func (pc *packetConnReadWriter) Write(b []byte) (int, error) {
	return pc.PacketConn.WriteTo(b, pc.targetAddr)
}

// Writes `payload` to `conn` and reads it into `buf`, which we take as a parameter to avoid
// reallocations in benchmarks and memory profiles. Fails the test if the read payload does not match.
func expectEchoPayload(conn io.ReadWriter, payload, buf []byte, t testing.TB) {
	_, err := conn.Write(payload)
	if err != nil {
		t.Fatalf("Failed to write payload: %v", err)
	}
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read payload: %v", err)
	}
	if !bytes.Equal(payload, buf[:n]) {
		t.Fatalf("Expected output '%v'. Got '%v'", payload, buf[:n])
	}
}

// Sends UDP packets into a black hole as fast as possible, in order to
// benchmark the CPU and memory cost of encrypting and sending UDP packes.
func BenchmarkShadowsocksClient_UDPWrite(b *testing.B) {
	d, err := NewClient("192.0.2.1:1", ss.TestCipher, testPassword, nil)
	if err != nil {
		b.Fatalf("Failed to create ShadowsocksClient: %v", err)
	}
	conn, err := d.ListenUDP(nil)
	if err != nil {
		b.Fatalf("ShadowsocksClient.ListenUDP failed: %v", err)
	}
	defer conn.Close()
	payload := ss.MakeTestPayload(1024)
	destAddr := &net.UDPAddr{
		IP:   net.ParseIP("192.0.2.2"),
		Port: 1,
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		conn.WriteTo(payload, destAddr)
	}
}
