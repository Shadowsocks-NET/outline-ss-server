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

package metrics

import (
	"errors"
	"io"
	"net"
	"time"

	onet "github.com/Jigsaw-Code/outline-ss-server/net"
	"github.com/oschwald/geoip2-golang"
	"github.com/prometheus/client_golang/prometheus"
)

// ShadowsocksMetrics registers metrics for the Shadowsocks service.
type ShadowsocksMetrics interface {
	GetLocation(net.Addr) (string, error)

	SetNumAccessKeys(numKeys int, numPorts int)
	AddUDPPacketFromClient(clientLocation, accessKey, status string, clientProxyBytes, proxyTargetBytes int)
	AddUDPPacketFromTarget(clientLocation, accessKey, status string, targetProxyBytes, proxyClientBytes int)
	AddOpenTCPConnection(clientLocation string)
	AddClosedTCPConnection(clientLocation, accessKey, status string, data ProxyMetrics, duration time.Duration)

	AddUdpNatEntry()
	RemoveUdpNatEntry()
}

type shadowsocksMetrics struct {
	ipCountryDB *geoip2.Reader

	accessKeys prometheus.Gauge
	ports      prometheus.Gauge
	dataBytes  *prometheus.CounterVec
	// TODO: Add time to first byte.

	tcpOpenConnections   *prometheus.CounterVec
	tcpClosedConnections *prometheus.CounterVec
	// TODO: Define a time window for the duration summary (e.g. 1 hour)
	tcpConnectionDurationMs *prometheus.SummaryVec

	udpAddedNatEntries   prometheus.Counter
	udpRemovedNatEntries prometheus.Counter
}

func NewShadowsocksMetrics(ipCountryDB *geoip2.Reader) ShadowsocksMetrics {
	m := &shadowsocksMetrics{
		ipCountryDB: ipCountryDB,
		accessKeys: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "shadowsocks",
			Name:      "keys",
			Help:      "Count of access keys",
		}),
		ports: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "shadowsocks",
			Name:      "ports",
			Help:      "Count of open Shadowsocks ports",
		}),
		tcpOpenConnections: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "shadowsocks",
			Subsystem: "tcp",
			Name:      "connections_opened",
			Help:      "Count of open TCP connections",
		}, []string{"location"}),
		tcpClosedConnections: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "shadowsocks",
			Subsystem: "tcp",
			Name:      "connections_closed",
			Help:      "Count of closed TCP connections",
		}, []string{"location", "status", "access_key"}),
		tcpConnectionDurationMs: prometheus.NewSummaryVec(
			prometheus.SummaryOpts{
				Namespace:  "shadowsocks",
				Subsystem:  "tcp",
				Name:       "connection_duration_ms",
				Help:       "TCP connection duration distributions.",
				Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
			}, []string{"location", "status", "access_key"}),
		dataBytes: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "shadowsocks",
				Name:      "data_bytes",
				Help:      "Bytes tranferred by the proxy",
			}, []string{"dir", "proto", "location", "status", "access_key"}),
		udpAddedNatEntries: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: "shadowsocks",
				Subsystem: "udp",
				Name:      "nat_entries_added",
				Help:      "Entries added to the UDP NAT table",
			}),
		udpRemovedNatEntries: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: "shadowsocks",
				Subsystem: "udp",
				Name:      "nat_entries_removed",
				Help:      "Entries removed from the UDP NAT table",
			}),
	}
	// TODO: Is it possible to pass where to register the collectors?
	prometheus.MustRegister(m.accessKeys, m.ports, m.tcpOpenConnections, m.tcpClosedConnections, m.tcpConnectionDurationMs,
		m.dataBytes, m.udpAddedNatEntries, m.udpRemovedNatEntries)
	return m
}

func (m *shadowsocksMetrics) GetLocation(addr net.Addr) (string, error) {
	if m.ipCountryDB == nil {
		return "", nil
	}
	hostname, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return "", errors.New("Failed to split hostname and port")
	}
	ip := net.ParseIP(hostname)
	if ip == nil {
		return "", errors.New("Failed to parse address as IP")
	}
	if ip.IsLoopback() {
		return "", errors.New("IP is localhost")
	}
	if !ip.IsGlobalUnicast() {
		return "", errors.New("IP is not global unicast")
	}
	record, err := m.ipCountryDB.Country(ip)
	if err != nil {
		return "", errors.New("IP lookup failed")
	}
	if record == nil {
		return "", errors.New("IP lookup returned nil")
	}
	if record.Country.IsoCode == "" {
		return "", errors.New("Ip Lookup has empty ISO code")
	}
	return record.Country.IsoCode, nil
}

func (m *shadowsocksMetrics) SetNumAccessKeys(numKeys int, ports int) {
	m.accessKeys.Set(float64(numKeys))
	m.ports.Set(float64(ports))
}

func (m *shadowsocksMetrics) AddOpenTCPConnection(clientLocation string) {
	m.tcpOpenConnections.WithLabelValues(clientLocation).Inc()
}

func (m *shadowsocksMetrics) AddClosedTCPConnection(clientLocation, accessKey, status string, data ProxyMetrics, duration time.Duration) {
	m.tcpClosedConnections.WithLabelValues(clientLocation, status, accessKey).Inc()
	m.tcpConnectionDurationMs.WithLabelValues(clientLocation, status, accessKey).Observe(duration.Seconds() * 1000)
	m.dataBytes.WithLabelValues("c>p", "tcp", clientLocation, status, accessKey).Add(float64(data.ClientProxy))
	m.dataBytes.WithLabelValues("p>t", "tcp", clientLocation, status, accessKey).Add(float64(data.ProxyTarget))
	m.dataBytes.WithLabelValues("p<t", "tcp", clientLocation, status, accessKey).Add(float64(data.TargetProxy))
	m.dataBytes.WithLabelValues("c<p", "tcp", clientLocation, status, accessKey).Add(float64(data.ProxyClient))
}

func (m *shadowsocksMetrics) AddUDPPacketFromClient(clientLocation, accessKey, status string, clientProxyBytes, proxyTargetBytes int) {
	m.dataBytes.WithLabelValues("c>p", "udp", clientLocation, status, accessKey).Add(float64(clientProxyBytes))
	m.dataBytes.WithLabelValues("p>t", "udp", clientLocation, status, accessKey).Add(float64(proxyTargetBytes))
}

func (m *shadowsocksMetrics) AddUDPPacketFromTarget(clientLocation, accessKey, status string, targetProxyBytes, proxyClientBytes int) {
	m.dataBytes.WithLabelValues("p<t", "udp", clientLocation, status, accessKey).Add(float64(targetProxyBytes))
	m.dataBytes.WithLabelValues("c<p", "udp", clientLocation, status, accessKey).Add(float64(proxyClientBytes))
}

func (m *shadowsocksMetrics) AddUdpNatEntry() {
	m.udpAddedNatEntries.Inc()
}

func (m *shadowsocksMetrics) RemoveUdpNatEntry() {
	m.udpRemovedNatEntries.Inc()
}

type ProxyMetrics struct {
	ClientProxy int64
	ProxyTarget int64
	TargetProxy int64
	ProxyClient int64
}

func (m *ProxyMetrics) add(other ProxyMetrics) {
	m.ClientProxy += other.ClientProxy
	m.ProxyTarget += other.ProxyTarget
	m.TargetProxy += other.TargetProxy
	m.ProxyClient += other.ProxyClient
}

type measuredConn struct {
	onet.DuplexConn
	io.WriterTo
	readCount *int64
	io.ReaderFrom
	writeCount *int64
}

func (c *measuredConn) Read(b []byte) (int, error) {
	n, err := c.DuplexConn.Read(b)
	*c.readCount += int64(n)
	return n, err
}

func (c *measuredConn) WriteTo(w io.Writer) (int64, error) {
	n, err := io.Copy(w, c.DuplexConn)
	*c.readCount += n
	return n, err
}

func (c *measuredConn) Write(b []byte) (int, error) {
	n, err := c.DuplexConn.Write(b)
	*c.writeCount += int64(n)
	return n, err
}

func (c *measuredConn) ReadFrom(r io.Reader) (int64, error) {
	n, err := io.Copy(c.DuplexConn, r)
	*c.writeCount += n
	return n, err
}

func MeasureConn(conn onet.DuplexConn, bytesSent, bytesRceived *int64) onet.DuplexConn {
	return &measuredConn{DuplexConn: conn, writeCount: bytesSent, readCount: bytesRceived}
}
