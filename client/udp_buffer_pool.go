package client

import (
	"sync"

	"github.com/Jigsaw-Code/outline-ss-server/shadowsocks"
)

var pool = sync.Pool{
	New: func() interface{} {
		return make([]byte, shadowsocks.MaxUDPPacketSize)
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
