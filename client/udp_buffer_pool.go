package client

import (
	"sync"
)

// clientUDPBufferSize is the maximum UDP packet size in bytes.
const clientUDPBufferSize = 16 * 1024

var pool = sync.Pool{
	New: func() interface{} {
		return make([]byte, clientUDPBufferSize)
	},
}

// newBuffer retrieves a UDP buffer from the pool.
func newUDPBuffer() []byte {
	return pool.Get().([]byte)
}

// freeBuffer returns a UDP buffer to the pool.
func freeUDPBuffer(b []byte) {
	pool.Put(b)
}
