// Copyright 2020 Jigsaw Operations LLC
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

package shadowsocks

import (
	"bytes"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	onet "github.com/Jigsaw-Code/outline-ss-server/net"
	logging "github.com/op/go-logging"
)

func testIPPolicy(ip net.IP) *onet.ConnectionError {
	return nil
}

func startTCPEchoServer(t testing.TB) *net.TCPListener {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenTCP failed: %v", err)
	}
	go func() {
		for {
			clientConn, err := listener.AcceptTCP()
			if err != nil {
				t.Logf("AcceptTCP failed: %v", err)
				return
			}
			go io.Copy(clientConn, clientConn)
		}
	}()
	return listener
}

func startUDPEchoServer(t testing.TB) *net.UDPConn {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("Proxy ListenUDP failed: %v", err)
	}
	go func() {
		defer conn.Close()
		buf := make([]byte, udpBufSize)
		for {
			n, clientAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				t.Logf("Failed to read from UDP conn: %v", err)
				return
			}
			conn.WriteTo(buf[:n], clientAddr)
			if err != nil {
				t.Fatalf("Failed to write: %v", err)
			}
		}
	}()
	return conn
}

func TestTCPEcho(t *testing.T) {
	echoListener := startTCPEchoServer(t)

	proxyListener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenTCP failed: %v", err)
	}
	cipherList, secrets, err := MakeTestCiphers(1)
	if err != nil {
		t.Fatal(err)
	}
	replayCache := NewReplayCache(5)
	testMetrics := &probeTestMetrics{}
	const testTimeout = 200 * time.Millisecond
	proxy := NewTCPService(proxyListener, cipherList, &replayCache, testMetrics, testTimeout)
	proxy.(*tcpService).ipPolicy = testIPPolicy
	go proxy.Start()

	proxyHost, proxyPort, err := net.SplitHostPort(proxyListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	portNum, err := strconv.Atoi(proxyPort)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(proxyHost, portNum, secrets[0], testCipher)
	if err != nil {
		t.Fatalf("Failed to create ShadowsocksClient: %v", err)
	}
	conn, err := client.DialTCP(nil, echoListener.Addr().String())
	if err != nil {
		t.Fatalf("ShadowsocksClient.DialTCP failed: %v", err)
	}

	const N = 1000
	up := make([]byte, N)
	for i := 0; i < N; i++ {
		up[i] = byte(i)
	}
	n, err := conn.Write(up)
	if err != nil {
		t.Fatal(err)
	}
	if n != N {
		t.Fatalf("Tried to upload %d bytes, but only sent %d", N, n)
	}

	down := make([]byte, N)
	n, err = conn.Read(down)
	if err != nil {
		t.Fatal(err)
	}
	if n != N {
		t.Fatalf("Tried to download %d bytes, but only sent %d", N, n)
	}

	if !bytes.Equal(up, down) {
		t.Fatal("Echo mismatch")
	}

	conn.Close()
	proxy.Stop()
	echoListener.Close()
}

func TestUDPEcho(t *testing.T) {
	echoConn := startUDPEchoServer(t)

	proxyConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenTCP failed: %v", err)
	}
	cipherList, secrets, err := MakeTestCiphers(1)
	if err != nil {
		t.Fatal(err)
	}
	testMetrics := &probeTestMetrics{}
	proxy := NewUDPService(proxyConn, time.Hour, cipherList, testMetrics)
	proxy.(*udpService).ipPolicy = testIPPolicy
	go proxy.Start()

	proxyHost, proxyPort, err := net.SplitHostPort(proxyConn.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	portNum, err := strconv.Atoi(proxyPort)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(proxyHost, portNum, secrets[0], testCipher)
	if err != nil {
		t.Fatalf("Failed to create ShadowsocksClient: %v", err)
	}
	conn, err := client.ListenUDP(nil)
	if err != nil {
		t.Fatalf("ShadowsocksClient.ListenUDP failed: %v", err)
	}

	const N = 1000
	up := MakeTestPayload(N)
	n, err := conn.WriteTo(up, echoConn.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	if n != N {
		t.Fatalf("Tried to upload %d bytes, but only sent %d", N, n)
	}

	down := make([]byte, N)
	n, addr, err := conn.ReadFrom(down)
	if err != nil {
		t.Fatal(err)
	}
	if n != N {
		t.Errorf("Tried to download %d bytes, but only sent %d", N, n)
	}
	if addr.String() != echoConn.LocalAddr().String() {
		t.Errorf("Reported address mismatch: %s != %s", addr.String(), echoConn.LocalAddr().String())
	}

	if !bytes.Equal(up, down) {
		t.Fatal("Echo mismatch")
	}

	conn.Close()
	proxy.Stop()
	echoConn.Close()
}

func BenchmarkTCPThroughput(b *testing.B) {
	echoListener := startTCPEchoServer(b)

	proxyListener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		b.Fatalf("ListenTCP failed: %v", err)
	}
	cipherList, secrets, err := MakeTestCiphers(1)
	if err != nil {
		b.Fatal(err)
	}
	replayCache := NewReplayCache(5)
	testMetrics := &probeTestMetrics{}
	const testTimeout = 200 * time.Millisecond
	proxy := NewTCPService(proxyListener, cipherList, &replayCache, testMetrics, testTimeout)
	proxy.(*tcpService).ipPolicy = testIPPolicy
	go proxy.Start()

	proxyHost, proxyPort, err := net.SplitHostPort(proxyListener.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	portNum, err := strconv.Atoi(proxyPort)
	if err != nil {
		b.Fatal(err)
	}
	client, err := NewClient(proxyHost, portNum, secrets[0], testCipher)
	if err != nil {
		b.Fatalf("Failed to create ShadowsocksClient: %v", err)
	}
	conn, err := client.DialTCP(nil, echoListener.Addr().String())
	if err != nil {
		b.Fatalf("ShadowsocksClient.DialTCP failed: %v", err)
	}

	const N = 1000
	up := MakeTestPayload(N)
	down := make([]byte, N)

	start := time.Now()
	b.ResetTimer()
	go func() {
		for i := 0; i < b.N; i++ {
			conn.Write(up)
		}
	}()

	for i := 0; i < b.N; i++ {
		conn.Read(down)
	}
	b.StopTimer()
	elapsed := time.Now().Sub(start)

	megabits := float64(8*1000*b.N) / 1e6
	b.ReportMetric(megabits/elapsed.Seconds(), "mbps")

	conn.Close()
	proxy.Stop()
	echoListener.Close()
}

func BenchmarkTCPMultiplexing(b *testing.B) {
	logging.SetLevel(logging.CRITICAL, "")

	echoListener := startTCPEchoServer(b)

	proxyListener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		b.Fatalf("ListenTCP failed: %v", err)
	}
	const numKeys = 100
	cipherList, secrets, err := MakeTestCiphers(numKeys)
	if err != nil {
		b.Fatal(err)
	}
	replayCache := NewReplayCache(MaxCapacity)
	testMetrics := &probeTestMetrics{}
	const testTimeout = 200 * time.Millisecond
	proxy := NewTCPService(proxyListener, cipherList, &replayCache, testMetrics, testTimeout)
	proxy.(*tcpService).ipPolicy = testIPPolicy
	go proxy.Start()

	proxyHost, proxyPort, err := net.SplitHostPort(proxyListener.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	portNum, err := strconv.Atoi(proxyPort)
	if err != nil {
		b.Fatal(err)
	}

	var clients [numKeys]Client
	for i := 0; i < numKeys; i++ {
		clients[i], err = NewClient(proxyHost, portNum, secrets[i], testCipher)
		if err != nil {
			b.Fatalf("Failed to create ShadowsocksClient: %v", err)
		}
	}

	b.ResetTimer()
	var wg sync.WaitGroup
	for i := 0; i < numKeys; i++ {
		k := b.N / numKeys
		if i < b.N%numKeys {
			k++
		}
		client := clients[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < k; i++ {
				conn, err := client.DialTCP(nil, echoListener.Addr().String())
				if err != nil {
					b.Fatalf("ShadowsocksClient.DialTCP failed: %v", err)
				}

				const N = 1000
				buf := make([]byte, N)
				n, err := conn.Write(buf)
				if n != N {
					b.Fatalf("Tried to upload %d bytes, but only sent %d", N, n)
				}
				n, err = conn.Read(buf)
				if n != N {
					b.Fatalf("Tried to download %d bytes, but only received %d", N, n)
				}
				conn.Close()
			}
		}()
	}
	wg.Wait()

	proxy.Stop()
	echoListener.Close()
}

func BenchmarkUDPEcho(b *testing.B) {
	logging.SetLevel(logging.CRITICAL, "")
	echoConn := startUDPEchoServer(b)

	proxyConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		b.Fatalf("ListenTCP failed: %v", err)
	}
	cipherList, secrets, err := MakeTestCiphers(1)
	if err != nil {
		b.Fatal(err)
	}
	testMetrics := &probeTestMetrics{}
	proxy := NewUDPService(proxyConn, time.Hour, cipherList, testMetrics)
	proxy.(*udpService).ipPolicy = testIPPolicy
	go proxy.Start()

	proxyHost, proxyPort, err := net.SplitHostPort(proxyConn.LocalAddr().String())
	if err != nil {
		b.Fatal(err)
	}
	portNum, err := strconv.Atoi(proxyPort)
	if err != nil {
		b.Fatal(err)
	}
	client, err := NewClient(proxyHost, portNum, secrets[0], testCipher)
	if err != nil {
		b.Fatalf("Failed to create ShadowsocksClient: %v", err)
	}
	conn, err := client.ListenUDP(nil)
	if err != nil {
		b.Fatalf("ShadowsocksClient.ListenUDP failed: %v", err)
	}

	const N = 1000
	buf := make([]byte, N)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn.WriteTo(buf, echoConn.LocalAddr())
		conn.ReadFrom(buf)
	}
	b.StopTimer()

	conn.Close()
	proxy.Stop()
	echoConn.Close()
}

func BenchmarkUDPManyKeys(b *testing.B) {
	logging.SetLevel(logging.CRITICAL, "")
	echoConn := startUDPEchoServer(b)

	proxyConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		b.Fatalf("ListenTCP failed: %v", err)
	}
	const numKeys = 100
	cipherList, secrets, err := MakeTestCiphers(numKeys)
	if err != nil {
		b.Fatal(err)
	}
	testMetrics := &probeTestMetrics{}
	proxy := NewUDPService(proxyConn, time.Hour, cipherList, testMetrics)
	proxy.(*udpService).ipPolicy = testIPPolicy
	go proxy.Start()

	proxyHost, proxyPort, err := net.SplitHostPort(proxyConn.LocalAddr().String())
	if err != nil {
		b.Fatal(err)
	}
	portNum, err := strconv.Atoi(proxyPort)
	if err != nil {
		b.Fatal(err)
	}
	var clients [numKeys]Client
	for i := 0; i < numKeys; i++ {
		clients[i], err = NewClient(proxyHost, portNum, secrets[i], testCipher)
		if err != nil {
			b.Fatalf("Failed to create ShadowsocksClient: %v", err)
		}
	}

	const N = 1000
	buf := make([]byte, N)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, _ := clients[i%numKeys].ListenUDP(nil)
		conn.WriteTo(buf, echoConn.LocalAddr())
		conn.ReadFrom(buf)
		conn.Close()
	}
	b.StopTimer()
	proxy.Stop()
	echoConn.Close()
}
