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
	"container/list"
	"time"
)

type CipherCache struct {
	ipCiphers map[string]*list.List
}

type CachedItem struct {
	itemsList *list.List
	element   *list.Element
}

func (c *CipherCache) GetCiphers(ip string) []*CachedItem {
	cipherList, ok := c.ipCiphers[ip]
	if !ok {
		return []*CachedItem{}
	}
	items := make([]*CachedItem, cipherList.Len())
	pos := 0
	for el := cipherList.Front(); el != nil; el = el.Next() {
		items[pos] = &CachedItem{cipherList, el}
	}
	return items
}

type cipherTime struct {
	CipherID  string
	Timestamp time.Time
}

// WARNING
// TODO: All of this needs a MUTEX!!!!!!!
// WARNING
func (cc *CipherCache) AddCipher(ip string, cipherId string) {
	cipherList, ok := cc.ipCiphers[ip]
	if !ok {
		cipherList = list.New()
		cc.ipCiphers[ip] = cipherList
	}
	cipherList.PushFront(cipherTime{CipherID: cipherId, Timestamp: time.Now()})
}

func (cc *CipherCache) ExpireOlderThan(oldestTime time.Time) {
	for key, itemList := range cc.ipCiphers {
		// Remove expired items
		for item := itemList.Back(); item != nil && item.Value.(*cipherTime).Timestamp.Sub(oldestTime) < 0; item = itemList.Back() {
			itemList.Remove(item)
		}
		if itemList.Len() == 0 {
			// TODO: Make this not break the loop
			delete(cc.ipCiphers, key)
		}
	}
}

func (ci *CachedItem) Refresh() {
	ci.element.Value.(*cipherTime).Timestamp = time.Now()
	ci.itemsList.MoveToFront(ci.element)
}

func (ci *CachedItem) CipherId() string {
	return ci.element.Value.(*cipherTime).CipherID
}
