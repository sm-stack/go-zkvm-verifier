package leanvm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"golang.org/x/crypto/blake2s"
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"
)

func (p *program) bytecodeTableReference(text []uint32) ([]uint64, error) {
	n := p.entryCount
	table := make([]uint64, n<<busBits)
	b2u := func(b bool) uint64 {
		if b {
			return 1
		}
		return 0
	}
	for i := range n {
		e := illegalEntry
		if i < len(text) {
			e = decode(text[i], textBase+4*uint64(i))
		}
		if !e.wellFormed() {
			return nil, errNotProgram
		}
		pc := textBase + 4*uint64(i)
		set := func(slot int, v uint64) { table[slot*n+i] = v }
		if e.class != classIllegal {
			set(slotTag, gpow(uint64(e.class)))
		}
		set(slotFlags, e.flags)
		set(slotA1, uint64(e.a1))
		set(slotA2, uint64(e.a2))
		set(slotAD, uint64(e.ad))
		set(slotImm, e.imm)
		set(slotPC4, pc+4)
		switch e.target {
		case targetAbs:
			set(slotDT, e.targetPC^(pc+4))
		case targetHalt:
			set(slotDT, p.haltPC()^(pc+4))
		}
		set(slotLink, b2u(e.link))
		set(slotJalr, b2u(e.jalr))
		set(exitSlot, b2u(e.target == targetHalt))
	}
	return table, nil
}

// Compare streaming slots and evaluations with a materialized slot-major table.
func TestStreamingBytecode(t *testing.T) {
	r := rand.New(rand.NewPCG(41, 92))
	for _, n := range []int{1, 2, 255, 256, 257, 511, 1024, 4097} {
		text := make([]uint32, n)
		for i := range text {
			text[i] = r.Uint32()
		}
		p := &program{entryCount: int(nextPow2(uint64(n) + 2)), text: text}
		table, err := p.bytecodeTableReference(text)
		if err != nil {
			t.Fatal(err)
		}
		for slot := 0; slot < 16; slot++ {
			for i := 0; i < p.entryCount; i++ {
				if got := p.bytecodeWord(slot, i); got != table[slot*p.entryCount+i] {
					t.Fatalf("n=%d slot=%d i=%d", n, slot, i)
				}
			}
		}
		for trial := 0; trial < 3; trial++ {
			point := make([]ext, p.logBytecode()+busBits)
			for i := range point {
				if trial == 0 {
					point[i] = ext{r.Uint64(), r.Uint64(), r.Uint64()}
				} else if trial == 2 {
					point[i] = extOne
				}
			}
			want := multilinearEvalK(table, point)
			if got := p.bytecodeMLE(point[:p.logBytecode()], point[p.logBytecode():]); got != want {
				t.Fatalf("evaluation n=%d trial=%d", n, trial)
			}
		}
	}
}

func TestStreamingProgramDigest(t *testing.T) {
	for _, name := range []string{"fibonacci.elf", "preimage.elf"} {
		elf, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		g, err := loadGuest(elf)
		if err != nil {
			t.Fatal(err)
		}
		p, err := newProgram(g)
		if err != nil {
			t.Fatal(err)
		}
		table, err := p.bytecodeTableReference(p.text)
		if err != nil {
			t.Fatal(err)
		}
		h, _ := blake2s.New256(nil)
		h.Write([]byte("leanvm-rv64im-2"))
		word := func(w uint64) { var b [8]byte; binary.LittleEndian.PutUint64(b[:], w); h.Write(b[:]) }
		word(uint64(len(table)))
		for _, w := range table {
			word(w)
		}
		for _, w := range []uint64{p.entryPC, p.haltPC(), uint64(p.logRAM), uint64(p.logAdvice), uint64(len(p.image))} {
			word(w)
		}
		for _, w := range p.image {
			word(w)
		}
		if !bytes.Equal(h.Sum(nil), p.digest[:]) {
			t.Fatal("digest differs", name)
		}
	}
}

// Inputs are preallocated so this reports program construction's additional memory.
func BenchmarkLargeProgram(b *testing.B) {
	for _, size := range []int{1 << 20, 16 << 20} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			g := &guest{text: make([]uint32, size/4), entryPC: textBase, logRAM: 1, logAdvice: 1}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if _, err := newProgram(g); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkLargeBytecodeEvaluation(b *testing.B) {
	for _, size := range []int{1 << 20, 16 << 20} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			p := &program{text: make([]uint32, size/4), entryCount: int(nextPow2(uint64(size/4) + 2))}
			point := make([]ext, p.logBytecode())
			for i := range point {
				point[i] = ext{uint64(i + 2), 3, 7}
			}
			slots := []ext{{2, 3, 4}, {5, 6, 7}, {8, 9, 10}, {11, 12, 13}}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				bytecodeEvaluationSink = p.bytecodeMLE(point, slots)
			}
		})
	}
}

var bytecodeEvaluationSink ext
