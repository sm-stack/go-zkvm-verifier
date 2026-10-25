package leanvm

import (
	"encoding/binary"
	"github.com/stretchr/testify/require"
	"testing"
)

func symbolELF(headers int, duplicate bool) []byte {
	const base = 64
	sym := base + 64*headers
	b := make([]byte, sym+24*headers+64)
	binary.LittleEndian.PutUint64(b[40:], base)
	binary.LittleEndian.PutUint16(b[58:], 64)
	binary.LittleEndian.PutUint16(b[60:], uint16(headers))
	for i := 0; i < headers-1; i++ {
		sh := b[base+64*i:]
		binary.LittleEndian.PutUint32(sh[4:], shtSymtab)
		off := sym
		if !duplicate {
			off += 24 * i
		}
		binary.LittleEndian.PutUint64(sh[24:], uint64(off))
		binary.LittleEndian.PutUint64(sh[32:], uint64(24*(headers-i)))
		if duplicate {
			binary.LittleEndian.PutUint64(sh[32:], uint64(24*headers))
		}
		binary.LittleEndian.PutUint32(sh[40:], uint32(headers-1))
		binary.LittleEndian.PutUint64(sh[56:], 24)
	}
	sh := b[base+64*(headers-1):]
	binary.LittleEndian.PutUint32(sh[4:], shtStrtab)
	binary.LittleEndian.PutUint64(sh[24:], uint64(sym+24*headers))
	binary.LittleEndian.PutUint64(sh[32:], 64)
	return b
}

func TestSymbolLookupWork(t *testing.T) {
	b := symbolELF(8192, true)
	_, found, ok := symbol(elfReader(b), "__stack_top")
	require.True(t, ok)
	require.False(t, found)
	// Distinct overlapping tables reuse scanned ranges without budget rejection.
	b = symbolELF(8192, false)
	_, found, ok = symbol(elfReader(b), "__stack_top")
	require.True(t, ok)
	require.False(t, found)
}

func TestSymbolLaterTableAndValidationOrder(t *testing.T) {
	b := symbolELF(4, false)
	// First table empty; the second table holds the first matching value.
	binary.LittleEndian.PutUint64(b[64+32:], 0)
	sym := 64 + 4*64 + 24
	str := 64 + 4*64 + 24*4
	copy(b[str:], "__stack_top\x00")
	binary.LittleEndian.PutUint64(b[sym+8:], ramBase+1024)
	// Invalid table after the match must not invalidate it.
	binary.LittleEndian.PutUint64(b[64+2*64+56:], 1)
	v, found, ok := symbol(elfReader(b), "__stack_top")
	require.True(t, ok)
	require.True(t, found)
	require.Equal(t, uint64(ramBase+1024), v)
	binary.LittleEndian.PutUint64(b[64+56:], 1)
	_, _, ok = symbol(elfReader(b), "__stack_top")
	require.False(t, ok)
}

func overlappingELF(t testing.TB, n int) []byte {
	f := loadFixture(t, "fibonacci.elf", "fibonacci-1000")
	b := append([]byte(nil), f.elf...)
	original := int(binary.LittleEndian.Uint64(b[32:]))
	originalN := int(binary.LittleEndian.Uint16(b[56:]))
	var text []byte
	for i := 0; i < originalN; i++ {
		p := b[original+56*i : original+56*(i+1)]
		if binary.LittleEndian.Uint32(p) == ptLoad && binary.LittleEndian.Uint32(p[4:])&pfX != 0 {
			text = append([]byte(nil), p...)
			break
		}
	}
	require.Len(t, text, 56)
	off := len(b)
	b = append(b, make([]byte, 56*(n+1))...)
	binary.LittleEndian.PutUint64(b[32:], uint64(off))
	binary.LittleEndian.PutUint16(b[56:], uint16(n+1))
	copy(b[off:], text)
	for i := 1; i <= n; i++ {
		p := b[off+56*i:]
		binary.LittleEndian.PutUint32(p, ptLoad)
		binary.LittleEndian.PutUint64(p[16:], ramBase)
		binary.LittleEndian.PutUint64(p[32:], uint64(len(b)))
		binary.LittleEndian.PutUint64(p[40:], uint64(len(b)))
		binary.LittleEndian.PutUint64(p[48:], 1)
	}
	return b
}

func TestRejectOverlappingSegmentsBeforeCopy(t *testing.T) {
	b := overlappingELF(t, 2048)
	_, err := ProgramDigest(b)
	require.Error(t, err)
}

func BenchmarkELFSymbolAmplification(b *testing.B) {
	elf := symbolELF(32768, true)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_, found, ok := symbol(elfReader(elf), "__stack_top")
		if !ok || found {
			b.Fatal("unexpected lookup")
		}
	}
}
func BenchmarkELFOverlappingSegments(b *testing.B) {
	elf := overlappingELF(b, 2048)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := ProgramDigest(elf); err == nil {
			b.Fatal("accepted overlaps")
		}
	}
}

func TestCircuitCommittedSlotsUnique(t *testing.T) {
	// Streaming bilinear evaluation requires exactly one assignment per row.
	for _, c := range classCircuits() {
		seen := make(map[int]bool)
		for _, g := range c.gates {
			if g.kind == gateXor {
				continue
			}
			slot := g.slot
			if g.kind == gateFree {
				slot = g.x
			}
			require.False(t, seen[slot], "duplicate committed slot %d", slot)
			seen[slot] = true
		}
	}
}

func TestSymbolCacheSeparatesStrings(t *testing.T) {
	b := symbolELF(4, true)
	sym := 64 + 4*64
	// Two tables share symbol bytes but resolve names through different strings.
	for _, i := range []int{0, 1} {
		binary.LittleEndian.PutUint64(b[64+i*64+32:], 24)
	}
	str := len(b)
	b = append(b, []byte("__stack_top\x00")...)
	sh := b[64+2*64:]
	binary.LittleEndian.PutUint32(sh[4:], shtStrtab)
	binary.LittleEndian.PutUint64(sh[24:], uint64(str))
	binary.LittleEndian.PutUint64(sh[32:], 12)
	binary.LittleEndian.PutUint32(b[64+64+40:], 2)
	binary.LittleEndian.PutUint64(b[sym+8:], ramBase+1024)
	v, found, ok := symbol(elfReader(b), "__stack_top")
	require.True(t, ok)
	require.True(t, found)
	require.Equal(t, uint64(ramBase+1024), v)
	// Invalid strings for an empty table must still be refused.
	binary.LittleEndian.PutUint64(b[64+32:], 0)
	binary.LittleEndian.PutUint64(b[64+3*64+24:], uint64(len(b)+1))
	_, _, ok = symbol(elfReader(b), "__stack_top")
	require.False(t, ok)
}

func TestSymbolCacheSeparatesStringLengths(t *testing.T) {
	b := symbolELF(4, true)
	sym, str := 64+4*64, 64+4*64+24*4
	copy(b[str:], "__stack_top\x00")
	for _, i := range []int{0, 1} {
		binary.LittleEndian.PutUint64(b[64+i*64+32:], 24)
	}
	// Same string address, but only the second table permits the whole name.
	binary.LittleEndian.PutUint64(b[64+3*64+32:], 8)
	sh := b[64+2*64:]
	binary.LittleEndian.PutUint32(sh[4:], shtStrtab)
	binary.LittleEndian.PutUint64(sh[24:], uint64(str))
	binary.LittleEndian.PutUint64(sh[32:], 12)
	binary.LittleEndian.PutUint32(b[64+64+40:], 2)
	binary.LittleEndian.PutUint64(b[sym+8:], ramBase+2048)
	v, f, ok := symbol(elfReader(b), "__stack_top")
	require.True(t, ok)
	require.True(t, f)
	require.Equal(t, uint64(ramBase+2048), v)
}
