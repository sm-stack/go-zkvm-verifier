// Derived from rec/tree/{proof,multiset}.rs at da5c964831c993b011464e4fd4a573b7172d5295.
// Upstream MIT attribution is retained in NOTICE.
package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/blake"
	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/transcript"
	"slices"
)

var ErrEncoding = errors.New("leanvmclaims: malformed root or claims encoding")

type Element [3]uint64
type Root struct {
	Rate    uint8
	Circuit uint64
	Words   []Element
	Proof   transcript.Proof
}

func DecodeRoot(data []byte) (Root, error) {
	if len(data) < 11 || string(data[:4]) != "LVMT" {
		return Root{}, ErrEncoding
	}
	if version := binary.LittleEndian.Uint16(data[4:6]); version != 20 {
		return Root{}, fmt.Errorf("leanvmclaims: root version %d, expected 20", version)
	}
	rate := data[6]
	if rate < 1 || rate > 4 {
		return Root{}, ErrEncoding
	}
	n := uint64(binary.LittleEndian.Uint32(data[7:11]))
	data = data[11:]
	if n == 0 || n > uint64(len(data))/24 {
		return Root{}, ErrEncoding
	}
	// Validate the rest before allocating the statement words.
	p, e := transcript.Decode(data[int(n)*24:])
	if e != nil {
		return Root{}, e
	}
	circuit := binary.LittleEndian.Uint64(data[:8])
	if binary.LittleEndian.Uint64(data[8:16]) != 0 || binary.LittleEndian.Uint64(data[16:24]) != 0 {
		return Root{}, ErrEncoding
	}
	words := make([]Element, int(n))
	for i := range words {
		for j := range words[i] {
			words[i][j] = binary.LittleEndian.Uint64(data[i*24+j*8:])
		}
	}
	return Root{rate, circuit, words, p}, nil
}

// Instance is LengthPrefixed(root.limbs().as_flattened()): four u64 limbs
// per field element, including a zero high limb; the prefix counts u64s.
func (r Root) Instance() []byte {
	out := make([]byte, 8+32*len(r.Words))
	binary.LittleEndian.PutUint64(out, uint64(len(r.Words))*4)
	for i, w := range r.Words {
		for j, x := range w {
			binary.LittleEndian.PutUint64(out[8+i*32+j*8:], x)
		}
	}
	return out
}

type Group struct {
	Label   [6]uint64
	Members [][4]uint64
}
type Claims []Group

func DecodeClaims(data []byte) (Claims, error) {
	if len(data) < 4 {
		return nil, ErrEncoding
	}
	ng := uint64(binary.LittleEndian.Uint32(data))
	data = data[4:]
	if ng > uint64(len(data))/52 {
		return nil, ErrEncoding
	}
	// Each allocation is bounded by bytes actually present, never the encoded count alone.
	groups := make(Claims, 0, int(ng))
	for i := uint64(0); i < ng; i++ {
		if len(data) < 52 {
			return nil, ErrEncoding
		}
		var g Group
		for j := range g.Label {
			g.Label[j] = binary.LittleEndian.Uint64(data[j*8:])
		}
		nm := uint64(binary.LittleEndian.Uint32(data[48:52]))
		data = data[52:]
		if nm > uint64(len(data))/32 {
			return nil, ErrEncoding
		}
		g.Members = make([][4]uint64, int(nm))
		for j := range g.Members {
			for k := range g.Members[j] {
				g.Members[j][k] = binary.LittleEndian.Uint64(data[j*32+k*8:])
			}
		}
		data = data[int(nm)*32:]
		groups = append(groups, g)
	}
	if len(data) != 0 {
		return nil, ErrEncoding
	}
	return groups, nil
}
func (c Claims) Check(claimBound, groupBound uint64) error {
	var total uint64
	for i, g := range c {
		if i > 0 && slices.Compare(c[i-1].Label[:], g.Label[:]) >= 0 {
			return errors.New("leanvmclaims: unordered claim groups")
		}
		if len(g.Members) == 0 {
			return errors.New("leanvmclaims: empty claim group")
		}
		for j := 1; j < len(g.Members); j++ {
			if slices.Compare(g.Members[j-1][:], g.Members[j][:]) >= 0 {
				return errors.New("leanvmclaims: unordered claim members")
			}
		}
		total += uint64(len(g.Members))
	}
	if total >= claimBound || uint64(len(c)) > groupBound {
		return errors.New("leanvmclaims: claim capacity exceeded")
	}
	return nil
}
func (c Claims) Digest() [32]byte {
	cv := blake.ParameterIV()
	first := true
	compress := func(words [8]uint64, code uint64, last bool) {
		var b [64]byte
		for i, w := range words {
			binary.LittleEndian.PutUint64(b[i*8:], w)
		}
		if first {
			code |= 1
			first = false
		}
		cv = blake.Compress(cv, b, code, last)
	}
	for _, g := range c {
		var header [8]uint64
		copy(header[:], g.Label[:])
		compress(header, 0, false)
		for i := 0; i < len(g.Members); i += 2 {
			var pair [8]uint64
			copy(pair[:4], g.Members[i][:])
			code := uint64(2)
			if i+1 < len(g.Members) {
				copy(pair[4:], g.Members[i+1][:])
				code |= 8
			}
			compress(pair, code, false)
		}
	}
	var end [8]uint64
	end[0] = binary.LittleEndian.Uint64([]byte("claimset"))
	compress(end, 4, true)
	var out [32]byte
	for i, w := range cv {
		binary.LittleEndian.PutUint32(out[i*4:], w)
	}
	return out
}
