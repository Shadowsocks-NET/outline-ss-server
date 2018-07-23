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
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	ssnet "github.com/shadowsocks/go-shadowsocks2/net"
)

// TCPMetrics registers metrics for TCP connections.
type TCPMetrics interface {
	AddOpenTCPConnection()
	AddClosedTCPConnection(accessKey, status string, data ProxyMetrics, duration time.Duration)
}

type prometheusTCPMetrics struct {
	tcpOpenConnections   prometheus.Counter
	tcpClosedConnections *prometheus.CounterVec

	tcpDataClientProxyBytes *prometheus.CounterVec
	tcpDataProxyTargetBytes *prometheus.CounterVec
	tcpDataTargetProxyBytes *prometheus.CounterVec
	tcpDataProxyClientBytes *prometheus.CounterVec

	tcpConnectionDurationMs *prometheus.SummaryVec
}

func NewPrometheusTCPMetrics() TCPMetrics {
	m := &prometheusTCPMetrics{
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
	}
	// TODO: Is it possible to pass where to register the collectors?
	prometheus.MustRegister(m.tcpOpenConnections, m.tcpClosedConnections, m.tcpDataClientProxyBytes,
		m.tcpDataProxyTargetBytes, m.tcpDataTargetProxyBytes, m.tcpDataProxyClientBytes, m.tcpConnectionDurationMs)
	return m
}

func (m *prometheusTCPMetrics) AddOpenTCPConnection() {
	m.tcpOpenConnections.Inc()
}
func (m *prometheusTCPMetrics) AddClosedTCPConnection(accessKey, status string, data ProxyMetrics, duration time.Duration) {
	m.tcpClosedConnections.WithLabelValues(accessKey, status).Inc()
	m.tcpDataClientProxyBytes.WithLabelValues(accessKey, status).Add(float64(data.ClientProxy))
	m.tcpDataProxyTargetBytes.WithLabelValues(accessKey, status).Add(float64(data.ProxyTarget))
	m.tcpDataTargetProxyBytes.WithLabelValues(accessKey, status).Add(float64(data.TargetProxy))
	m.tcpDataProxyClientBytes.WithLabelValues(accessKey, status).Add(float64(data.ProxyClient))
	m.tcpConnectionDurationMs.WithLabelValues(accessKey, status).Observe(duration.Seconds() * 1000)
}

type measuredReader struct {
	io.Reader
	io.WriterTo
	count *int64
}

func MeasureReader(reader io.Reader, count *int64) io.Reader {
	return &measuredReader{Reader: reader, count: count}
}

func (r *measuredReader) Read(b []byte) (int, error) {
	n, err := r.Reader.Read(b)
	*r.count += int64(n)
	return n, err
}

func (r *measuredReader) WriteTo(w io.Writer) (int64, error) {
	n, err := io.Copy(w, r.Reader)
	*r.count += n
	return n, err
}

type measuredWriter struct {
	io.Writer
	io.ReaderFrom
	count *int64
}

func MeasureWriter(writer io.Writer, count *int64) io.Writer {
	return &measuredWriter{Writer: writer, count: count}
}

func (w *measuredWriter) Write(b []byte) (int, error) {
	n, err := w.Writer.Write(b)
	*w.count += int64(n)
	return n, err
}

func (w *measuredWriter) ReadFrom(r io.Reader) (int64, error) {
	n, err := io.Copy(w.Writer, r)
	*w.count += n
	return n, err
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

type MetricsMap struct {
	mutex sync.RWMutex
	m     map[string]*ProxyMetrics
}

func (this *MetricsMap) Add(key string, toAdd ProxyMetrics) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	p, ok := this.m[key]
	if !ok {
		p = &ProxyMetrics{}
		this.m[key] = p
	}
	p.add(toAdd)
}

func (this *MetricsMap) Get(key string) ProxyMetrics {
	this.mutex.RLock()
	defer this.mutex.RUnlock()
	if p, ok := this.m[key]; ok {
		return *p
	}
	return ProxyMetrics{}
}

func NewMetricsMap() *MetricsMap {
	return &MetricsMap{m: make(map[string]*ProxyMetrics)}
}

func MeasureConn(conn ssnet.DuplexConn, bytesSent, bytesRceived *int64) ssnet.DuplexConn {
	r := MeasureReader(conn, bytesRceived)
	w := MeasureWriter(conn, bytesSent)
	return ssnet.WrapDuplexConn(conn, r, w)
}

func SPrintMetrics(m ProxyMetrics) string {
	return fmt.Sprintf("C->P: %v, P->T: %v, T->P: %v, P->C: %v",
		m.ClientProxy, m.ProxyTarget, m.TargetProxy, m.ProxyClient)
}
