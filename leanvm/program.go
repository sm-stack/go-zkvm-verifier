package leanvm

import (
	"encoding/binary"
	"errors"
	"sync"

	"golang.org/x/crypto/blake2s"
)

// An instruction class: one table, one circuit. The order is leanvm_core::tables::CLASSES, so a
// class is also its table's index.
const (
	classALU = iota
	classLoad
	classStore
	classShift
	classMul
	classMulh
	classDiv
	classHash
	numTables
	classIllegal = -1
)

// The ALU class's flag bits (leanvm_core::rv::alu).
const (
	aluSub      = 1 << 0
	aluWord     = 1 << 1
	aluSelLT    = 1 << 2
	aluSelLTU   = 1 << 3
	aluSelAnd   = 1 << 4
	aluSelOr    = 1 << 5
	aluSelXor   = 1 << 6
	aluClearBit = 1 << 7
	aluBrEq     = 1 << 8
	aluBrNe     = 1 << 9
	aluBrLT     = 1 << 10
	aluBrGE     = 1 << 11
	aluBrLTU    = 1 << 12
	aluBrGEU    = 1 << 13
	aluAlways   = 1 << 14
	aluBranches = aluBrEq | aluBrNe | aluBrLT | aluBrGE | aluBrLTU | aluBrGEU
)

const (
	shiftRight  = 1 << 0
	shiftArith  = 1 << 1
	shiftWord   = 1 << 2
	loadSigned  = 1 << 2
	mulWord     = 1 << 0
	mulhSigned1 = 1 << 0
	mulhSigned2 = 1 << 1
	divSigned   = 1 << 0
	divRem      = 1 << 1
	divWord     = 1 << 2
	hashOpcode  = 0x0b
	hashFinal   = 0xFFFF_FFFF
)

// sink is the register cell an instruction with no destination writes.
const sink = 32

// legalFlags are the flag words each class defines (leanvm_core::rv::legal_flags).
var legalFlags = [numTables][]uint64{
	classALU: {0, aluSub, aluWord, aluSub | aluWord, aluSub | aluSelLT, aluSub | aluSelLTU, aluSelAnd, aluSelOr,
		aluSelXor, aluClearBit, aluSub | aluBrEq, aluSub | aluBrNe, aluSub | aluBrLT, aluSub | aluBrGE,
		aluSub | aluBrLTU, aluSub | aluBrGEU, aluAlways},
	classLoad:  {loadSigned, loadSigned | 1, loadSigned | 2, 3, 0, 1, 2},
	classStore: {0, 1, 2, 3},
	classShift: {0, shiftRight, shiftRight | shiftArith, shiftWord, shiftWord | shiftRight, shiftWord | shiftRight | shiftArith},
	classMul:   {0, mulWord},
	classMulh:  {mulhSigned1 | mulhSigned2, mulhSigned1, 0},
	classDiv:   {0, 1, 2, 3, 4, 5, 6, 7},
	classHash:  {0, hashFinal},
}

// Where control goes after an instruction.
const (
	targetNext = iota
	targetAbs
	targetHalt
)

// entry is one decoded instruction (leanvm_core::rv::Entry).
type entry struct {
	class      int
	flags      uint64
	a1, a2, ad uint8
	imm        uint64
	target     int
	targetPC   uint64
	link, jalr bool
}

var illegalEntry = entry{class: classIllegal, ad: sink}

// sext sign-extends the low bits of x.
func sext(x uint32, bits uint) uint64 {
	return uint64(int64(uint64(x)<<(64-bits)) >> (64 - bits))
}

func mkEntry(class int, flags uint64, a1, a2, rd uint32, imm uint64) entry {
	ad := uint8(rd)
	if rd == 0 {
		ad = sink
	}
	return entry{class: class, flags: flags, a1: uint8(a1), a2: uint8(a2), ad: ad, imm: imm}
}

// funct is an instruction's funct7 and funct3 fields.
type funct struct{ f7, f3 uint32 }

// decode decodes the instruction word at pc, as leanvm_core::rv::decode does: anything rv64im does
// not define is illegal.
func decode(word uint32, pc uint64) entry {
	opcode, rd, f3 := word&0x7f, (word>>7)&31, (word>>12)&7
	rs1, rs2, f7 := (word>>15)&31, (word>>20)&31, word>>25
	immI := sext(word>>20, 12)
	immS := sext((f7<<5)|rd, 12)
	immB := sext(((word>>31)<<12)|(((word>>7)&1)<<11)|(((word>>25)&0x3f)<<5)|(((word>>8)&0xf)<<1), 13)
	immU := sext(word&0xffff_f000, 32)
	immJ := sext(((word>>31)<<20)|(((word>>12)&0xff)<<12)|(((word>>20)&1)<<11)|(((word>>21)&0x3ff)<<1), 21)
	reg := func(class int, flags uint64) entry { return mkEntry(class, flags, rs1, rs2, rd, 0) }
	imm := func(class int, flags uint64, imm uint64) entry { return mkEntry(class, flags, rs1, 0, rd, imm) }

	switch opcode {
	case 0x37:
		return mkEntry(classALU, 0, 0, 0, rd, immU)
	case 0x17:
		return mkEntry(classALU, 0, 0, 0, rd, pc+immU)
	case 0x6f:
		e := mkEntry(classALU, aluAlways, 0, 0, rd, 0)
		e.target, e.targetPC, e.link = targetAbs, pc+immJ, true
		return e
	case 0x67:
		if f3 != 0 {
			return illegalEntry
		}
		e := imm(classALU, aluClearBit, immI)
		e.link, e.jalr = true, true
		return e
	case 0x63:
		var when uint64
		switch f3 {
		case 0:
			when = aluBrEq
		case 1:
			when = aluBrNe
		case 4:
			when = aluBrLT
		case 5:
			when = aluBrGE
		case 6:
			when = aluBrLTU
		case 7:
			when = aluBrGEU
		default:
			return illegalEntry
		}
		e := mkEntry(classALU, aluSub|when, rs1, rs2, 0, 0)
		e.target, e.targetPC = targetAbs, pc+immB
		return e
	case 0x03:
		var flags uint64
		switch {
		case f3 <= 2:
			flags = loadSigned | uint64(f3)
		case f3 == 3:
			flags = 3
		case f3 <= 6:
			flags = uint64(f3 - 4)
		default:
			return illegalEntry
		}
		return imm(classLoad, flags, immI)
	case 0x23:
		if f3 > 3 {
			return illegalEntry
		}
		return mkEntry(classStore, uint64(f3)&3, rs1, rs2, 0, immS)
	case 0x13:
		switch {
		case f3 == 0:
			return imm(classALU, 0, immI)
		case f3 == 2:
			return imm(classALU, aluSub|aluSelLT, immI)
		case f3 == 3:
			return imm(classALU, aluSub|aluSelLTU, immI)
		case f3 == 4:
			return imm(classALU, aluSelXor, immI)
		case f3 == 6:
			return imm(classALU, aluSelOr, immI)
		case f3 == 7:
			return imm(classALU, aluSelAnd, immI)
		case f3 == 1 && word>>26 == 0:
			return imm(classShift, 0, uint64(word>>20&63))
		case f3 == 5 && word>>26 == 0:
			return imm(classShift, shiftRight, uint64(word>>20&63))
		case f3 == 5 && word>>26 == 0x10:
			return imm(classShift, shiftRight|shiftArith, uint64(word>>20&63))
		}
		return illegalEntry
	case 0x1b:
		switch {
		case f3 == 0:
			return imm(classALU, aluWord, immI)
		case f3 == 1 && f7 == 0:
			return imm(classShift, shiftWord, uint64(rs2))
		case f3 == 5 && f7 == 0:
			return imm(classShift, shiftWord|shiftRight, uint64(rs2))
		case f3 == 5 && f7 == 0x20:
			return imm(classShift, shiftWord|shiftRight|shiftArith, uint64(rs2))
		}
		return illegalEntry
	case 0x33:
		switch (funct{f7, f3}) {
		case funct{0, 0}:
			return reg(classALU, 0)
		case funct{0x20, 0}:
			return reg(classALU, aluSub)
		case funct{0, 1}:
			return reg(classShift, 0)
		case funct{0, 2}:
			return reg(classALU, aluSub|aluSelLT)
		case funct{0, 3}:
			return reg(classALU, aluSub|aluSelLTU)
		case funct{0, 4}:
			return reg(classALU, aluSelXor)
		case funct{0, 5}:
			return reg(classShift, shiftRight)
		case funct{0x20, 5}:
			return reg(classShift, shiftRight|shiftArith)
		case funct{0, 6}:
			return reg(classALU, aluSelOr)
		case funct{0, 7}:
			return reg(classALU, aluSelAnd)
		case funct{1, 0}:
			return reg(classMul, 0)
		case funct{1, 1}:
			return reg(classMulh, mulhSigned1|mulhSigned2)
		case funct{1, 2}:
			return reg(classMulh, mulhSigned1)
		case funct{1, 3}:
			return reg(classMulh, 0)
		case funct{1, 4}:
			return reg(classDiv, divSigned)
		case funct{1, 5}:
			return reg(classDiv, 0)
		case funct{1, 6}:
			return reg(classDiv, divSigned|divRem)
		case funct{1, 7}:
			return reg(classDiv, divRem)
		}
		return illegalEntry
	case 0x3b:
		switch (funct{f7, f3}) {
		case funct{0, 0}:
			return reg(classALU, aluWord)
		case funct{0x20, 0}:
			return reg(classALU, aluSub|aluWord)
		case funct{0, 1}:
			return reg(classShift, shiftWord)
		case funct{0, 5}:
			return reg(classShift, shiftWord|shiftRight)
		case funct{0x20, 5}:
			return reg(classShift, shiftWord|shiftRight|shiftArith)
		case funct{1, 0}:
			return reg(classMul, mulWord)
		case funct{1, 4}:
			return reg(classDiv, divWord|divSigned)
		case funct{1, 5}:
			return reg(classDiv, divWord)
		case funct{1, 6}:
			return reg(classDiv, divWord|divSigned|divRem)
		case funct{1, 7}:
			return reg(classDiv, divWord|divRem)
		}
		return illegalEntry
	case 0x0f:
		if f3 != 0 {
			return illegalEntry
		}
		return mkEntry(classALU, 0, 0, 0, 0, 0)
	case hashOpcode:
		if f7 != 0 || rd != 0 || f3 > 1 {
			return illegalEntry
		}
		flags := uint64(0)
		if f3 == 1 {
			flags = hashFinal
		}
		return mkEntry(classHash, flags, rs1, rs2, 0, 0)
	case 0x73:
		if word != 0x73 {
			return illegalEntry
		}
		e := mkEntry(classALU, aluAlways, 0, 0, 0, 0)
		e.target = targetHalt
		return e
	}
	return illegalEntry
}

// wellFormed is Entry::is_well_formed: the x0 and sink rules, legal flags, and control flow of its
// class's shape.
func (e entry) wellFormed() bool {
	if e.class == classIllegal {
		return e == illegalEntry
	}
	if e.target == targetHalt {
		return e == decode(0x73, 0)
	}
	var control bool
	switch {
	case e.class != classALU:
		control = e.target == targetNext && !e.link && !e.jalr
	case e.flags == aluClearBit:
		control = e.jalr && e.link && e.target == targetNext
	case e.flags == aluAlways:
		control = !e.jalr && e.link && e.target == targetAbs
	case e.flags&aluBranches != 0:
		control = !e.jalr && !e.link && e.target == targetAbs
	default:
		control = !e.jalr && !e.link && e.target == targetNext
	}
	legal := false
	for _, f := range legalFlags[e.class] {
		legal = legal || f == e.flags
	}
	hash := e.class == classHash
	return e.a1 < 32 && e.a2 < 32 && e.ad >= 1 && e.ad <= sink && legal && control &&
		(!hash || (e.ad == sink && e.imm == 0))
}

// fillSizes are the fill blocks' sizes (leanvm_core::cpu::filler::SIZES); the last, a lone jump,
// is the ALU's only.
var fillSizes = []int{128, 64, 32, 16, 8, 4, 2, 1, 0}

// fillNops are each class's no-op, every register x0 (filler::nop).
var fillNops = [numTables]uint32{
	classALU:   0x13,
	classLoad:  0x03,
	classStore: 0x23,
	classShift: 0x13 | 1<<12,
	classMul:   0x33 | 1<<25,
	classMulh:  0x33 | 3<<12 | 1<<25,
	classDiv:   0x33 | 5<<12 | 1<<25,
	classHash:  hashOpcode,
}

// jType encodes `jal x0, offset`.
func jType(offset int32) uint32 {
	o := uint32(offset)
	return 0x6f | ((o >> 12 & 0xff) << 12) | ((o >> 11 & 1) << 20) | ((o >> 1 & 0x3ff) << 21) | ((o >> 20 & 1) << 31)
}

// fillBlocks is the words every program's fill blocks add: per table and size, that many no-ops
// of the table's class, then a jump back to the block's first instruction.
var fillBlocks = sync.OnceValue(func() []uint32 {
	var out []uint32
	for t := range numTables {
		for _, size := range fillSizes {
			if size == 0 && t != classALU {
				continue
			}
			for range size {
				out = append(out, fillNops[t])
			}
			out = append(out, jType(int32(-4*size)))
		}
	}
	return out
})

// program is a decoded program (leanvm_core::cpu::Program): its entries, a power of two whose last
// is the halt slot, and what its digest commits to.
type program struct {
	entryCount int
	entryPC    uint64
	image      []uint64
	logRAM     int
	logAdvice  int
	// text includes the illegal word and filler; padded entries are generated on demand.
	text   []uint32
	digest [32]byte
}

func (p *program) logBytecode() int {
	return bitLen(uint64(p.entryCount)) - 1
}

func (p *program) haltPC() uint64 {
	return textBase + 4*uint64(p.entryCount-1)
}

var errNotProgram = errors.New("leanvm: the guest's text and RAM form no program")

// validateProgram is rv::Program::validate.
func validateProgram(words int, entryPC uint64, imageWords int, logRAM, logAdvice int) bool {
	if words > 1<<maxLogText-2 {
		return false
	}
	if entryPC < textBase {
		return false
	}
	offset := entryPC - textBase
	if offset%4 != 0 || offset/4 >= uint64(words) {
		return false
	}
	return logRAM <= maxLogRAM && uint64(imageWords) <= uint64(1)<<logRAM && logAdvice <= maxLogAdvice
}

// nextPow2 returns the least power of two at least x (x >= 1).
func nextPow2(x uint64) uint64 {
	return uint64(1) << log2Ceil(x)
}

// newProgram builds a program from a guest as cpu::Program::new does: it appends the illegal word
// and the fill blocks, decodes the text, pads it to a power of two with illegal entries, and
// digests the bytecode table, the entry and halt pcs, the region sizes and the RAM image.
func newProgram(g *guest) (*program, error) {
	if !validateProgram(len(g.text), g.entryPC, len(g.image), g.logRAM, g.logAdvice) {
		return nil, errNotProgram
	}
	blocks := fillBlocks()
	// filler::text_fits bounds the extended text including its two padding entries.
	// Appending preserves the already-validated entry PC and memory dimensions.
	if nextPow2(uint64(len(g.text))+uint64(len(blocks))+3) > 1<<maxLogText {
		return nil, errNotProgram
	}
	text := make([]uint32, 0, len(g.text)+1+len(blocks))
	text = append(text, g.text...)
	text = append(text, 0)
	text = append(text, blocks...)

	p := &program{
		entryCount: int(nextPow2(uint64(len(text)) + 2)),
		entryPC:    g.entryPC,
		image:      g.image,
		logRAM:     g.logRAM,
		logAdvice:  g.logAdvice,
	}
	p.text = text
	for i, w := range text {
		if !decode(w, textBase+4*uint64(i)).wellFormed() {
			return nil, errNotProgram
		}
	}

	h, _ := blake2s.New256(nil)
	word := func(w uint64) {
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], w)
		h.Write(b[:])
	}
	h.Write([]byte("leanvm-rv64im-2"))
	word(uint64(p.entryCount) << busBits)
	// Stream canonical little-endian words without duplicating whole tables.
	writeWords := func(words []uint64) {
		var buf [4096]byte
		for len(words) > 0 {
			n := min(len(words), len(buf)/8)
			for i, w := range words[:n] {
				binary.LittleEndian.PutUint64(buf[8*i:], w)
			}
			h.Write(buf[:8*n])
			words = words[n:]
		}
	}
	// Preserve the upstream slot-major encoding, using constant scratch space.
	var buf [4096]byte
	for slot := range 1 << busBits {
		for start := 0; start < p.entryCount; start += len(buf) / 8 {
			n := min(p.entryCount-start, len(buf)/8)
			for i := range n {
				binary.LittleEndian.PutUint64(buf[8*i:], p.bytecodeWord(slot, start+i))
			}
			h.Write(buf[:8*n])
		}
	}
	for _, w := range []uint64{p.entryPC, p.haltPC(), uint64(p.logRAM), uint64(p.logAdvice), uint64(len(p.image))} {
		word(w)
	}
	writeWords(p.image)
	copy(p.digest[:], h.Sum(nil))
	return p, nil
}

// Bytecode slots: the public columns of an entry sit at their bus tuple coordinates.
const (
	busBits   = 4
	slotTag   = 3
	slotFlags = 4
	slotA1    = 5
	slotA2    = 6
	slotAD    = 7
	slotImm   = 8
	slotPC4   = 9
	slotDT    = 10
	slotLink  = 11
	slotJalr  = 12
	badSlot   = 13
	exitSlot  = 14
)

// bytecodeEntry decodes an instruction or returns the canonical padding entry.
func (p *program) bytecodeEntry(i int) entry {
	if i < len(p.text) {
		return decode(p.text[i], textBase+4*uint64(i))
	}
	return illegalEntry
}

func (p *program) entryWord(e entry, slot, i int) uint64 {
	pc4 := textBase + 4*uint64(i) + 4
	switch slot {
	case slotTag:
		if e.class != classIllegal {
			return gpow(uint64(e.class))
		}
	case slotFlags:
		return e.flags
	case slotA1:
		return uint64(e.a1)
	case slotA2:
		return uint64(e.a2)
	case slotAD:
		return uint64(e.ad)
	case slotImm:
		return e.imm
	case slotPC4:
		return pc4
	case slotDT:
		if e.target == targetAbs {
			return e.targetPC ^ pc4
		}
		if e.target == targetHalt {
			return p.haltPC() ^ pc4
		}
	case slotLink:
		if e.link {
			return 1
		}
	case slotJalr:
		if e.jalr {
			return 1
		}
	case exitSlot:
		if e.target == targetHalt {
			return 1
		}
	}
	return 0
}

func (p *program) bytecodeWord(slot, i int) uint64 {
	if slot < slotTag || slot == badSlot || slot > exitSlot {
		return 0
	}
	if slot == slotPC4 {
		return textBase + 4*uint64(i) + 4
	}
	return p.entryWord(p.bytecodeEntry(i), slot, i)
}

// bytecodeMLE evaluates the same slot-major table as cpu::layout::bytecode_table.
// Fold the 16 slots first, then instruction coordinates in bounded blocks. Field
// multilinearity permits this reordering; transcript and digest order are unchanged.
// Higher coordinates are folded recursively, requiring only O(log(entryCount))
// stack space and one shared 256-entry scratch buffer.
func (p *program) bytecodeMLE(point, slotPoint []ext) ext {
	weights := eqKernel(slotPoint)
	var scratch [256]ext
	var eval func(int, int) ext
	eval = func(start, logN int) ext {
		if logN > 8 {
			a := eval(start, logN-1)
			b := eval(start+(1<<(logN-1)), logN-1)
			return a.add(point[logN-1].mul(a.add(b)))
		}
		n := 1 << logN
		for i := range n {
			e := p.bytecodeEntry(start + i)
			v := extZero
			for slot := slotTag; slot <= exitSlot; slot++ {
				v = v.add(weights[slot].mulK(p.entryWord(e, slot, start+i)))
			}
			scratch[i] = v
		}
		return foldMultilinear(scratch[:n], point[:logN])
	}
	return eval(0, len(point))
}
