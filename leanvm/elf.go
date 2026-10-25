package leanvm

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"errors"
	"slices"
	"sort"
)

// The machine's memory map (leanvm_core::rv).
const (
	textBase     = 0x1000_0000
	ramBase      = 0x4000_0000
	adviceBase   = 0x2000_0000
	maxLogText   = 26
	maxLogRAM    = 27
	maxLogAdvice = 26
)

const (
	etExec    = 2
	emRiscV   = 243
	ptLoad    = 1
	ptDynamic = 2
	ptInterp  = 3
	ptTLS     = 7
	pfX       = 1
	pfW       = 2
	shtSymtab = 2
	shtStrtab = 3
)

var errNotGuest = errors.New("leanvm: not a leanVM guest")

// guest is what a program is made from (leanvm_core::rv::Guest).
type guest struct {
	text      []uint32
	entryPC   uint64
	image     []uint64
	logRAM    int
	logAdvice int
}

// elfReader reads little-endian fields of an ELF file, every read checked.
type elfReader []byte

func (r elfReader) bytes(at, n uint64) ([]byte, bool) {
	end := at + n
	if end < at || end > uint64(len(r)) {
		return nil, false
	}
	return r[at:end], true
}

func (r elfReader) u16(at uint64) (uint64, bool) {
	b, ok := r.bytes(at, 2)
	if !ok {
		return 0, false
	}
	return uint64(binary.LittleEndian.Uint16(b)), true
}

func (r elfReader) u32(at uint64) (uint64, bool) {
	b, ok := r.bytes(at, 4)
	if !ok {
		return 0, false
	}
	return uint64(binary.LittleEndian.Uint32(b)), true
}

func (r elfReader) u64(at uint64) (uint64, bool) {
	b, ok := r.bytes(at, 8)
	if !ok {
		return 0, false
	}
	return binary.LittleEndian.Uint64(b), true
}

// at is base + offset, refusing a wrap.
func at(base, offset uint64) (uint64, bool) {
	sum := base + offset
	return sum, sum >= base
}

// loadGuest loads a static RV64 executable linked with the guests' linker script, as
// leanvm_core::rv::Guest::from_elf does: its executable segments are the text, every other loaded
// segment is RAM's image, RAM ends at __stack_top and the advice region at __advice_top.
func loadGuest(elf []byte) (*guest, error) {
	g, ok := loadGuestOK(elf)
	if !ok {
		return nil, errNotGuest
	}
	return g, nil
}

func loadGuestOK(elf []byte) (*guest, bool) {
	r := elfReader(elf)
	if _, ok := r.bytes(0, 64); !ok {
		return nil, false
	}
	if !bytes.Equal(elf[:7], []byte{0x7f, 'E', 'L', 'F', 2, 1, 1}) {
		return nil, false
	}
	typ, _ := r.u16(16)
	machine, _ := r.u16(18)
	version, _ := r.u32(20)
	ehsize, _ := r.u16(52)
	// Only the base integer ABI is supported; reject every e_flags bit.
	flags, _ := r.u32(48)
	entryPC, _ := r.u64(24)
	if typ != etExec || machine != emRiscV || version != 1 || ehsize != 64 || flags != 0 || entryPC%4 != 0 {
		return nil, false
	}

	var text, image []byte
	phoff, _ := r.u64(32)
	phentsize, _ := r.u16(54)
	phnum, _ := r.u16(56)
	if phentsize != 56 {
		return nil, false
	}
	if _, ok := r.bytes(phoff, phnum*phentsize); !ok {
		return nil, false
	}
	type segment struct{ start, end uint64 }
	segments := make([]segment, 0, phnum)
	type placement struct {
		offset     uint64
		data       []byte
		executable bool
	}
	placements := make([]placement, 0, phnum)
	entryLoaded := false
	dataEnd := uint64(ramBase)
	fileLen := uint64(len(elf))
	for i := range phnum {
		ph, ok := at(phoff, i*phentsize)
		if !ok {
			return nil, false
		}
		kind, ok1 := r.u32(ph)
		pflagsAt, ok2 := at(ph, 4)
		if !ok1 || !ok2 {
			return nil, false
		}
		pflags, ok := r.u32(pflagsAt)
		if !ok {
			return nil, false
		}
		if kind == ptDynamic || kind == ptInterp || kind == ptTLS {
			return nil, false
		}
		if kind != ptLoad {
			continue
		}
		var fields [5]uint64
		for j, off := range []uint64{8, 16, 32, 40, 48} {
			a, ok := at(ph, off)
			if !ok {
				return nil, false
			}
			if fields[j], ok = r.u64(a); !ok {
				return nil, false
			}
		}
		offset, vaddr, filesz, memsz, align := fields[0], fields[1], fields[2], fields[3], fields[4]
		if filesz > memsz {
			return nil, false
		}
		if align > 1 && (align&(align-1) != 0 || vaddr%align != offset%align) {
			return nil, false
		}
		end, ok := at(vaddr, memsz)
		if !ok {
			return nil, false
		}
		b, ok := r.bytes(offset, filesz)
		if !ok {
			return nil, false
		}
		if memsz != 0 {
			segments = append(segments, segment{vaddr, end})
		}
		if pflags&pfX != 0 {
			if pflags&pfW != 0 {
				return nil, false
			}
			if vaddr < textBase || vaddr%4 != 0 || end > textBase+(4<<maxLogText) {
				return nil, false
			}
			if vaddr-textBase+uint64(len(b)) > fileLen {
				return nil, false
			}
			entryLoaded = entryLoaded || (entryPC >= vaddr && entryPC+4 >= entryPC && entryPC+4 <= vaddr+filesz)
			placements = append(placements, placement{vaddr - textBase, b, true})
		} else {
			if vaddr < ramBase || end > ramBase+(8<<maxLogRAM) {
				return nil, false
			}
			dataEnd = max(dataEnd, end)
			if len(b) != 0 {
				if vaddr-ramBase+uint64(len(b)) > fileLen {
					return nil, false
				}
				placements = append(placements, placement{vaddr - ramBase, b, false})
			}
		}
	}
	slices.SortFunc(segments, func(a, b segment) int {
		return cmp.Or(cmp.Compare(a.start, b.start), cmp.Compare(a.end, b.end))
	})
	for i := 1; i < len(segments); i++ {
		if segments[i-1].end > segments[i].start {
			return nil, false
		}
	}
	if !entryLoaded {
		return nil, false
	}

	ramEnd, found, ok := symbol(r, "__stack_top")
	if !ok || !found {
		return nil, false
	}
	ramBytes := ramEnd - ramBase
	if ramEnd <= ramBase || ramBytes&(ramBytes-1) != 0 || ramBytes < 8 || dataEnd > ramEnd {
		return nil, false
	}
	logRAM := bitLen(ramBytes/8) - 1
	adviceEnd, found, ok := symbol(r, "__advice_top")
	if !ok || !found {
		return nil, false
	}
	adviceBytes := adviceEnd - adviceBase
	if adviceEnd <= adviceBase || adviceBytes&(adviceBytes-1) != 0 || adviceBytes < 8 {
		return nil, false
	}
	logAdvice := bitLen(adviceBytes/8) - 1
	if logAdvice > maxLogAdvice {
		return nil, false
	}
	// All segment and symbol checks precede allocation and copying. Allocate each
	// image once; disjoint segments bound total copying by the mapped image size.
	var textSize, imageSize uint64
	for _, p := range placements {
		end := p.offset + uint64(len(p.data))
		if p.executable {
			textSize = max(textSize, (end+3)/4*4)
		} else {
			imageSize = max(imageSize, (end+7)/8*8)
		}
	}
	if logRAM > maxLogRAM || imageSize/8 > uint64(1)<<logRAM {
		return nil, false
	}
	text, image = make([]byte, textSize), make([]byte, imageSize)
	for _, p := range placements {
		if p.executable {
			copy(text[p.offset:], p.data)
		} else {
			copy(image[p.offset:], p.data)
		}
	}
	g := &guest{
		text:      make([]uint32, len(text)/4),
		entryPC:   entryPC,
		image:     make([]uint64, len(image)/8),
		logRAM:    logRAM,
		logAdvice: logAdvice,
	}
	for i := range g.text {
		g.text[i] = binary.LittleEndian.Uint32(text[4*i:])
	}
	for i := range g.image {
		g.image[i] = binary.LittleEndian.Uint64(image[8*i:])
	}
	if logRAM > maxLogRAM || uint64(len(g.image)) > uint64(1)<<logRAM {
		return nil, false
	}
	return g, true
}

// symbol returns the value of the symbol name from the file's symbol table, whether it was found,
// and false in the last result if the section headers or a symbol table are malformed.
func symbol(r elfReader, name string) (value uint64, found bool, ok bool) {
	shoff, ok1 := r.u64(40)
	shentsize, ok2 := r.u16(58)
	shnum, ok3 := r.u16(60)
	if !ok1 || !ok2 || !ok3 || shentsize != 64 {
		return 0, false, false
	}
	if _, ok := r.bytes(shoff, shnum*shentsize); !ok {
		return 0, false, false
	}
	want := append([]byte(name), 0)
	// Cache only fully scanned, unmatched ranges. Records can be shared only
	// with the same string table and 24-byte alignment. No work-budget rejection:
	// preserve upstream first-match and malformed-table order for every table.
	type tableKey struct{ strings, stringSize, alignment uint64 }
	seen := make(map[tableKey][]symbolSpan)
	for i := range shnum {
		sh, ok := at(shoff, i*shentsize)
		if !ok {
			return 0, false, false
		}
		var f [5]uint64
		for j, field := range []struct {
			off  uint64
			size int
		}{{4, 4}, {24, 8}, {32, 8}, {40, 4}, {56, 8}} {
			a, ok := at(sh, field.off)
			if !ok {
				return 0, false, false
			}
			if field.size == 4 {
				f[j], ok = r.u32(a)
			} else {
				f[j], ok = r.u64(a)
			}
			if !ok {
				return 0, false, false
			}
			if j == 0 && f[0] != shtSymtab {
				break
			}
		}
		if f[0] != shtSymtab {
			continue
		}
		offset, size, link, entsize := f[1], f[2], f[3], f[4]
		if entsize != 24 || size%entsize != 0 || link >= shnum {
			return 0, false, false
		}
		if _, ok := r.bytes(offset, size); !ok {
			return 0, false, false
		}
		stringHeader, ok := at(shoff, link*shentsize)
		if !ok {
			return 0, false, false
		}
		var s [3]uint64
		for j, off := range []uint64{4, 24, 32} {
			a, ok := at(stringHeader, off)
			if !ok {
				return 0, false, false
			}
			if j == 0 {
				s[j], ok = r.u32(a)
			} else {
				s[j], ok = r.u64(a)
			}
			if !ok {
				return 0, false, false
			}
			if j == 0 && s[0] != shtStrtab {
				return 0, false, false
			}
		}
		strOffset, strSize := s[1], s[2]
		if _, ok := r.bytes(strOffset, strSize); !ok {
			return 0, false, false
		}
		count := size / entsize
		if count == 0 {
			continue
		}
		key := tableKey{strOffset, strSize, offset % entsize}
		ranges := seen[key]
		j := sort.Search(len(ranges), func(i int) bool { return ranges[i].end > offset })
		for k := uint64(0); k < count; k++ {
			pos := offset + k*entsize
			for j < len(ranges) && ranges[j].end <= pos {
				j++
			}
			if j < len(ranges) && ranges[j].start <= pos {
				k += min(ranges[j].end-pos, size-k*entsize)/entsize - 1
				continue
			}

			sym, ok := at(offset, k*entsize)
			if !ok {
				return 0, false, false
			}
			nameAt, ok := r.u32(sym)
			if !ok {
				return 0, false, false
			}
			if nameAt+uint64(len(name)) < strSize {
				a, ok := at(strOffset, nameAt)
				if !ok {
					return 0, false, false
				}
				b, ok := r.bytes(a, uint64(len(want)))
				if !ok {
					return 0, false, false
				}
				if bytes.Equal(b, want) {
					va, ok := at(sym, 8)
					if !ok {
						return 0, false, false
					}
					v, ok := r.u64(va)
					return v, ok, ok
				}
			}
		}
		seen[key] = addSymbolSpan(ranges, symbolSpan{offset, offset + size})
	}
	return 0, false, true
}

// Nonoverlapping sorted ranges of records already scanned without a match.
type symbolSpan struct{ start, end uint64 }

func addSymbolSpan(ranges []symbolSpan, span symbolSpan) []symbolSpan {
	i := sort.Search(len(ranges), func(i int) bool { return ranges[i].end >= span.start })
	j := i
	for j < len(ranges) && ranges[j].start <= span.end {
		span.start = min(span.start, ranges[j].start)
		span.end = max(span.end, ranges[j].end)
		j++
	}
	if i == j {
		return slices.Insert(ranges, i, span)
	}
	ranges[i] = span
	copy(ranges[i+1:], ranges[j:])
	return ranges[:len(ranges)-(j-i)+1]
}
