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

package slicepool

import (
	"sync"
)

// Pool wraps a sync.Pool of *[]byte.  To encourage correct usage,
// all public methods are on slicepool.Slice.
//
// All copies of a Pool refer to the same underlying pool.
//
// "*[]byte" is used to avoid an allocation due to casting
// []byte to interface{} when calling sync.Pool.Put.
type Pool struct {
	pool *sync.Pool
	len  int
}

// MakePool returns a Pool of slices with the specified length.
func MakePool(sliceLen int) Pool {
	return Pool{
		pool: &sync.Pool{
			New: func() interface{} {
				slice := make([]byte, sliceLen)
				return &slice
			},
		},
		len: sliceLen,
	}
}

func (p *Pool) get() *[]byte {
	return p.pool.Get().(*[]byte)
}

func (p *Pool) put(b *[]byte) {
	if len(*b) != p.len || cap(*b) != p.len {
		panic("Buffer length mismatch")
	}
	p.pool.Put(b)
}

// Slice returns an empty Slice tied to this Pool.
func (p *Pool) Slice() Slice {
	return Slice{pool: p}
}

// Slice holds 0 or 1 buffers from a particular Pool.
type Slice struct {
	buf  *[]byte
	pool *Pool
}

// Acquire this slice from the pool and return it.
// This slice must not already be acquired.
func (b *Slice) Acquire() []byte {
	if b.buf != nil {
		panic("buffer already acquired")
	}
	b.buf = b.pool.get()
	return *b.buf
}

// Release the buffer back to the pool, unless the box is empty.
// The caller must discard any references to the buffer.
func (b *Slice) Release() {
	if b.buf != nil {
		b.pool.put(b.buf)
		b.buf = nil
	}
}
