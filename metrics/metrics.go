package metrics

import (
	"io"
	"sync"
)

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
