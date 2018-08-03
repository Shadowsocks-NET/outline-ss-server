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
	"io"
	"time"

	onet "github.com/Jigsaw-Code/outline-ss-server/net"
	"github.com/prometheus/client_golang/prometheus"
)

// ShadowsocksMetrics registers metrics for the Shadowsocks service.
type ShadowsocksMetrics interface {
	SetNumAccessKeys(numKeys int, numPorts int)
	AddClientUDPPacket(accessKey, status string, clientProxyBytes, proxyTargetBytes int)
	AddTargetUDPPacket(accessKey, status string, targetProxyBytes, proxyClientBytes int)
	AddOpenTCPConnection()
	AddClosedTCPConnection(accessKey, status string, data ProxyMetrics, duration time.Duration)
}

type shadowsocksMetrics struct {
	accessKeys           prometheus.Gauge
	ports                prometheus.Gauge
	tcpOpenConnections   prometheus.Counter
	tcpClosedConnections *prometheus.CounterVec

	// TODO: Add per network/location metrics.
	// TODO: Add time to first byte.
	tcpDataClientProxyBytes *prometheus.CounterVec
	tcpDataProxyTargetBytes *prometheus.CounterVec
	tcpDataTargetProxyBytes *prometheus.CounterVec
	tcpDataProxyClientBytes *prometheus.CounterVec
	// TODO: Define a time window for the duration summary (e.g. 1 hour)
	tcpConnectionDurationMs *prometheus.SummaryVec

	udpDataClientProxyBytes *prometheus.CounterVec
	udpDataProxyTargetBytes *prometheus.CounterVec
	udpDataTargetProxyBytes *prometheus.CounterVec
	udpDataProxyClientBytes *prometheus.CounterVec
}

func NewShadowsocksMetrics() ShadowsocksMetrics {
	m := &shadowsocksMetrics{
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
		tcpOpenConnections: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "shadowsocks",
			Subsystem: "tcp",
			Name:      "open_connections",
			Help:      "Count of open TCP connections",
		}),
		tcpClosedConnections: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "shadowsocks",
			Subsystem: "tcp",
			Name:      "closed_connections",
			Help:      "Count of closed TCP connections",
		}, []string{"access_key", "status"}),
		tcpDataClientProxyBytes: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "shadowsocks",
				Subsystem: "tcp",
				Name:      "data_client_proxy_bytes",
				Help:      "Bytes tranferred from client to proxy.",
			}, []string{"access_key", "status"}),
		tcpDataProxyTargetBytes: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "shadowsocks",
				Subsystem: "tcp",
				Name:      "data_proxy_target_bytes",
				Help:      "Bytes tranferred from proxy to target.",
			}, []string{"access_key", "status"}),
		tcpDataTargetProxyBytes: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "shadowsocks",
				Subsystem: "tcp",
				Name:      "data_target_proxy_bytes",
				Help:      "Bytes tranferred from target to proxy.",
			}, []string{"access_key", "status"}),
		tcpDataProxyClientBytes: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "shadowsocks",
				Subsystem: "tcp",
				Name:      "data_proxy_client_bytes",
				Help:      "Bytes tranferred from proxy to client.",
			}, []string{"access_key", "status"}),
		tcpConnectionDurationMs: prometheus.NewSummaryVec(
			prometheus.SummaryOpts{
				Namespace:  "shadowsocks",
				Subsystem:  "tcp",
				Name:       "connection_duration_ms",
				Help:       "TCP connection duration distributions.",
				Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
			}, []string{"access_key", "status"}),
		udpDataClientProxyBytes: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "shadowsocks",
				Subsystem: "udp",
				Name:      "data_client_proxy_bytes",
				Help:      "Bytes tranferred from client to proxy.",
			}, []string{"access_key", "status"}),
		udpDataProxyTargetBytes: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "shadowsocks",
				Subsystem: "udp",
				Name:      "data_proxy_target_bytes",
				Help:      "Bytes tranferred from proxy to target.",
			}, []string{"access_key", "status"}),
		udpDataTargetProxyBytes: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "shadowsocks",
				Subsystem: "udp",
				Name:      "data_target_proxy_bytes",
				Help:      "Bytes tranferred from target to proxy.",
			}, []string{"access_key", "status"}),
		udpDataProxyClientBytes: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "shadowsocks",
				Subsystem: "udp",
				Name:      "data_proxy_client_bytes",
				Help:      "Bytes tranferred from proxy to client.",
			}, []string{"access_key", "status"}),
	}
	// TODO: Is it possible to pass where to register the collectors?
	prometheus.MustRegister(m.accessKeys, m.ports, m.tcpOpenConnections, m.tcpClosedConnections, m.tcpDataClientProxyBytes,
		m.tcpDataProxyTargetBytes, m.tcpDataTargetProxyBytes, m.tcpDataProxyClientBytes, m.tcpConnectionDurationMs,
		m.udpDataClientProxyBytes, m.udpDataProxyTargetBytes, m.udpDataTargetProxyBytes, m.udpDataProxyClientBytes)
	return m
}

func (m *shadowsocksMetrics) SetNumAccessKeys(numKeys int, ports int) {
	m.accessKeys.Set(float64(numKeys))
	m.ports.Set(float64(ports))
}

func (m *shadowsocksMetrics) AddOpenTCPConnection() {
	m.tcpOpenConnections.Inc()
}

func (m *shadowsocksMetrics) AddClosedTCPConnection(accessKey, status string, data ProxyMetrics, duration time.Duration) {
	m.tcpClosedConnections.WithLabelValues(accessKey, status).Inc()
	m.tcpDataClientProxyBytes.WithLabelValues(accessKey, status).Add(float64(data.ClientProxy))
	m.tcpDataProxyTargetBytes.WithLabelValues(accessKey, status).Add(float64(data.ProxyTarget))
	m.tcpDataTargetProxyBytes.WithLabelValues(accessKey, status).Add(float64(data.TargetProxy))
	m.tcpDataProxyClientBytes.WithLabelValues(accessKey, status).Add(float64(data.ProxyClient))
	m.tcpConnectionDurationMs.WithLabelValues(accessKey, status).Observe(duration.Seconds() * 1000)
}

func (m *shadowsocksMetrics) AddClientUDPPacket(accessKey, status string, clientProxyBytes, proxyTargetBytes int) {
	m.udpDataClientProxyBytes.WithLabelValues(accessKey, status).Add(float64(clientProxyBytes))
	m.udpDataProxyTargetBytes.WithLabelValues(accessKey, status).Add(float64(proxyTargetBytes))
}

func (m *shadowsocksMetrics) AddTargetUDPPacket(accessKey, status string, targetProxyBytes, proxyClientBytes int) {
	m.udpDataTargetProxyBytes.WithLabelValues(accessKey, status).Add(float64(targetProxyBytes))
	m.udpDataProxyClientBytes.WithLabelValues(accessKey, status).Add(float64(proxyClientBytes))
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
