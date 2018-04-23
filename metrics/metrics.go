package metrics

import "io"

type measuredReader struct {
	io.Reader
	io.WriterTo
	count func(int)
}

func MeasureReader(reader io.Reader, count func(int)) io.Reader {
	return &measuredReader{Reader: reader, count: count}
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
	io.ReaderFrom
	count func(int)
}

func MeasureWriter(writer io.Writer, count func(int)) io.Writer {
	return &measuredWriter{Writer: writer, count: count}
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
