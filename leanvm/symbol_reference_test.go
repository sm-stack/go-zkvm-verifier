package leanvm

import (
	"bytes"
	"encoding/binary"
	"math/rand/v2"
	"testing"
)

// Sequential lookup decodes ELF records directly, independently of elfReader's
// accessors and the production interval cache. It preserves section/symbol order.
func symbolUncached(data []byte, name string) (uint64, bool, bool) {
	span := func(offset, size uint64) ([]byte, bool) {
		if offset > uint64(len(data)) || size > uint64(len(data))-offset {
			return nil, false
		}
		return data[offset : offset+size], true
	}
	if len(data) < 62 || binary.LittleEndian.Uint16(data[58:]) != 64 {
		return 0, false, false
	}
	count := uint64(binary.LittleEndian.Uint16(data[60:]))
	headers, ok := span(binary.LittleEndian.Uint64(data[40:]), count*64)
	if !ok {
		return 0, false, false
	}
	want := append([]byte(name), 0)
	for i := uint64(0); i < count; i++ {
		h := headers[i*64:][:64]
		if binary.LittleEndian.Uint32(h[4:]) != 2 {
			continue
		}
		size := binary.LittleEndian.Uint64(h[32:])
		link := uint64(binary.LittleEndian.Uint32(h[40:]))
		if binary.LittleEndian.Uint64(h[56:]) != 24 || size%24 != 0 || link >= count {
			return 0, false, false
		}
		symbols, ok := span(binary.LittleEndian.Uint64(h[24:]), size)
		if !ok {
			return 0, false, false
		}
		stringsHeader := headers[link*64:][:64]
		if binary.LittleEndian.Uint32(stringsHeader[4:]) != 3 {
			return 0, false, false
		}
		strings, ok := span(binary.LittleEndian.Uint64(stringsHeader[24:]), binary.LittleEndian.Uint64(stringsHeader[32:]))
		if !ok {
			return 0, false, false
		}
		for len(symbols) != 0 {
			start := uint64(binary.LittleEndian.Uint32(symbols))
			if start <= uint64(len(strings)) && bytes.HasPrefix(strings[start:], want) {
				return binary.LittleEndian.Uint64(symbols[8:]), true, true
			}
			symbols = symbols[24:]
		}
	}
	return 0, false, true
}

func TestSymbolIntervalsAgainstSequential(t *testing.T) {
	r := rand.New(rand.NewPCG(701, 18))
	for trial := 0; trial < 2000; trial++ {
		b := symbolELF(16, false)
		sym := 64 + 16*64
		str := sym + 24*16
		copy(b[str:], "__stack_top\x00")
		for i := 0; i < 16; i++ {
			binary.LittleEndian.PutUint32(b[sym+24*i:], uint32(r.IntN(64)))
			binary.LittleEndian.PutUint64(b[sym+24*i+8:], r.Uint64())
		}
		for i := 0; i < 15; i++ {
			start := r.IntN(16)
			n := r.IntN(17 - start)
			binary.LittleEndian.PutUint64(b[64+64*i+24:], uint64(sym+24*start+r.IntN(2)))
			binary.LittleEndian.PutUint64(b[64+64*i+32:], uint64(24*n))
		}
		if trial%3 == 0 {
			b[r.IntN(len(b))] ^= byte(r.Uint32())
		}
		v, f, ok := symbol(elfReader(b), "__stack_top")
		want, wf, wo := symbolUncached(elfReader(b), "__stack_top")
		if v != want || f != wf || ok != wo {
			t.Fatalf("trial %d: (%d,%v,%v) != (%d,%v,%v)", trial, v, f, ok, want, wf, wo)
		}
	}
}
