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
	"math/rand"
	"testing"
)

func MakeVecs(n int) [][32]byte {
	vecs := make([][32]byte, n)
	for i := 0; i < n; i++ {
		rand.Read(vecs[i][:])
	}
	return vecs
}

func TestIVCache_Active(t *testing.T) {
	vecs := MakeVecs(2)
	cache := NewIVCache(10)
	if !cache.Add(vecs[0][:]) {
		t.Error("First addition to a clean cache should succeed")
	}
	if cache.Add(vecs[0][:]) {
		t.Error("Duplicate add should fail")
	}
	if !cache.Add(vecs[1][:]) {
		t.Error("Addition of a new vector should succeed")
	}
	if cache.Add(vecs[1][:]) {
		t.Error("Second duplicate add should fail")
	}
}

func TestIVCache_Archive(t *testing.T) {
	vecs0 := MakeVecs(10)
	vecs1 := MakeVecs(10)
	cache := NewIVCache(10)
	// Add vectors to the active set until it hits the limit
	// and spills into the archive.
	for _, v := range vecs0 {
		if !cache.Add(v[:]) {
			t.Error("Addition of a new vector should succeed")
		}
	}

	for _, v := range vecs0 {
		if cache.Add(v[:]) {
			t.Error("Duplicate add should fail")
		}
	}

	// Repopulate the active set.
	for _, v := range vecs1 {
		if !cache.Add(v[:]) {
			t.Error("Addition of a new vector should succeed")
		}
	}

	// Both active and archive are full.  Adding another vector
	// should wipe the archive.
	lastStraw := MakeVecs(1)[0]
	if !cache.Add(lastStraw[:]) {
		t.Error("Addition of a new vector should succeed")
	}
	for _, v := range vecs0 {
		if !cache.Add(v[:]) {
			t.Error("First 10 vectors should have been forgotten")
		}
	}
}

func BenchmarkIVCache_Max(b *testing.B) {
	vecs := MakeVecs(b.N)
	// All vectors will fit in the active set.
	cache := NewIVCache(maxCapacity)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Add(vecs[i][:])
	}
}

func BenchmarkIVCache_Min(b *testing.B) {
	vecs := MakeVecs(b.N)
	// Every addition will archive the active set.
	cache := NewIVCache(1)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Add(vecs[i][:])
	}
}

func BenchmarkIVCache_Parallel(b *testing.B) {
	c := make(chan []byte, b.N)
	for _, v := range MakeVecs(b.N) {
		c <- v[:]
	}
	close(c)
	// Exercise both expansion and archiving.
	cache := NewIVCache(100)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			cache.Add(<-c)
		}
	})
}
