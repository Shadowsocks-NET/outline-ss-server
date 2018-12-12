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

package shadowsocks

import (
	"testing"

	sstest "github.com/Jigsaw-Code/outline-ss-server/shadowsocks/testing"
	logging "github.com/op/go-logging"
)

func BenchmarkUDPUnpack(b *testing.B) {
	b.StopTimer()
	b.ResetTimer()

	logging.SetLevel(logging.INFO, "")

	cipherList, err := sstest.MakeTestCiphers(100)
	if err != nil {
		b.Fatal(err)
	}
	testPayload := sstest.MakeTestPayload(60)
	textBuf := make([]byte, udpBufSize)
	for n := 0; n < b.N; n++ {
		b.StartTimer()
		unpack(textBuf, testPayload, cipherList)
		b.StopTimer()
	}
}
