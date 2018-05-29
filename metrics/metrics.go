package metrics

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	ssnet "github.com/shadowsocks/go-shadowsocks2/net"
)

type TCPMetrics interface {
	AddTCPConnection()
	RemoveTCPConnection(accessKey, status string, duration time.Duration)
}

type prometheusTCPMetrics struct {
	tcpOpenConnections      prometheus.Counter
	tcpClosedConnections    *prometheus.CounterVec
	tcpConnectionDurationMs *prometheus.SummaryVec
}

func (m *prometheusTCPMetrics) AddTCPConnection() {
	m.tcpOpenConnections.Inc()
}
func (m *prometheusTCPMetrics) RemoveTCPConnection(accessKey, status string, duration time.Duration) {
	m.tcpClosedConnections.WithLabelValues(accessKey, status).Inc()
	m.tcpConnectionDurationMs.WithLabelValues(accessKey, status).Observe(duration.Seconds() * 1000)
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
	prometheus.MustRegister(m.tcpOpenConnections, m.tcpClosedConnections, m.tcpConnectionDurationMs)
	return m
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
