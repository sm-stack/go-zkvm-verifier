package sp1

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"slices"
	"strings"
	"unicode/utf8"
)

// The decoder reads SP1's legacy bincode encoding (little endian, fixed-width integers, u64 lengths)
// and accepts exactly what SP1's serde types accept: field elements are any u32 and are reduced,
// maps keep the last value of a repeated key and iterate in key order, and tensors must have at
// most three dimensions whose product matches their storage.

// MaxProofBytes is the library's transport limit (16 MiB), matching our Rust adapter.
// SP1's upstream raw API itself does not enforce this limit.
const MaxProofBytes = 16 * 1024 * 1024
const maxProofBytes = MaxProofBytes

var errTruncated = errors.New("unexpected end of input")

type decoder struct {
	buf []byte
	err error
}

func (d *decoder) fail(err error) {
	if d.err == nil {
		d.err = err
	}
}

func (d *decoder) take(n int) []byte {
	if d.err != nil {
		return nil
	}
	if n > len(d.buf) {
		d.fail(errTruncated)
		d.buf = nil
		return nil
	}
	out := d.buf[:n]
	d.buf = d.buf[n:]
	return out
}

func (d *decoder) u8() byte {
	b := d.take(1)
	if b == nil {
		return 0
	}
	return b[0]
}

func (d *decoder) u32() uint32 {
	b := d.take(4)
	if b == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(b)
}

func (d *decoder) u64() uint64 {
	b := d.take(8)
	if b == nil {
		return 0
	}
	return binary.LittleEndian.Uint64(b)
}

// length reads a sequence length and checks that the remaining input can hold that many elements
// of at least minSize bytes each, which bounds allocations by the input size.
func (d *decoder) length(minSize int) int {
	n := d.u64()
	if d.err != nil {
		return 0
	}
	if n > uint64(len(d.buf)/minSize) {
		d.fail(errTruncated)
		return 0
	}
	return int(n)
}

func (d *decoder) felt() felt {
	return feltFromU32(d.u32())
}

func (d *decoder) ext() ext {
	return ext{d.felt(), d.felt(), d.felt(), d.felt()}
}

func (d *decoder) digest() digest {
	var out digest
	for i := range out {
		out[i] = d.felt()
	}
	return out
}

func (d *decoder) felts() []felt {
	out := make([]felt, d.length(4))
	for i := range out {
		out[i] = d.felt()
	}
	return out
}

func (d *decoder) exts() []ext {
	out := make([]ext, d.length(16))
	for i := range out {
		out[i] = d.ext()
	}
	return out
}

func (d *decoder) digests() []digest {
	out := make([]digest, d.length(4*digestSize))
	for i := range out {
		out[i] = d.digest()
	}
	return out
}

func (d *decoder) str() string {
	b := d.take(d.length(1))
	if d.err != nil {
		return ""
	}
	if !utf8.Valid(b) {
		d.fail(errors.New("invalid utf-8 string"))
		return ""
	}
	return string(b)
}

func (d *decoder) option() bool {
	switch d.u8() {
	case 0:
		return false
	case 1:
		return true
	default:
		d.fail(errors.New("invalid option tag"))
		return false
	}
}

// tensor is a row-major tensor of at most three dimensions.
type tensor[T any] struct {
	data []T
	dims []uint64
}

// rows splits the tensor along its first dimension. It must have exactly two dimensions.
func (t *tensor[T]) rows() [][]T {
	n, width := t.dims[0], t.dims[1]
	out := make([][]T, n)
	for i := range out {
		out[i] = t.data[uint64(i)*width : uint64(i+1)*width]
	}
	return out
}

// isShape reports whether the tensor's dimensions are exactly dims.
func (t *tensor[T]) isShape(dims ...uint64) bool {
	if len(t.dims) != len(dims) {
		return false
	}
	for i := range dims {
		if t.dims[i] != dims[i] {
			return false
		}
	}
	return true
}

func decodeTensor[T any](d *decoder, elems func(*decoder) []T) tensor[T] {
	data := elems(d)
	numDims := d.length(8)
	if numDims > 3 {
		d.fail(errors.New("tensor has more than three dimensions"))
		return tensor[T]{}
	}
	dims := make([]uint64, numDims)
	for i := range dims {
		dims[i] = d.u64()
	}
	if d.err != nil {
		return tensor[T]{}
	}
	// The product must not overflow in either direction of accumulation.
	total, ok := uint64(1), true
	for _, n := range dims {
		var hi uint64
		hi, total = bits.Mul64(total, n)
		if hi != 0 {
			ok = false
			break
		}
	}
	reverse := uint64(1)
	for i := len(dims) - 1; i >= 0 && ok; i-- {
		var hi uint64
		hi, reverse = bits.Mul64(reverse, dims[i])
		ok = hi == 0
	}
	if !ok {
		d.fail(errors.New("tensor size overflows"))
		return tensor[T]{}
	}
	if uint64(len(data)) != total {
		d.fail(errors.New("tensor storage does not match its dimensions"))
		return tensor[T]{}
	}
	return tensor[T]{data: data, dims: dims}
}

func (d *decoder) extTensor() tensor[ext] {
	return decodeTensor(d, (*decoder).exts)
}

func (d *decoder) feltTensor() tensor[felt] {
	return decodeTensor(d, (*decoder).felts)
}

func (d *decoder) digestTensor() tensor[digest] {
	return decodeTensor(d, (*decoder).digests)
}

// decodeMap decodes a map with string keys into its entries sorted by key, keeping the last value
// of a repeated key, as Rust's BTreeMap does.
func decodeMap[V any](d *decoder, value func(*decoder) V) []namedValue[V] {
	n := d.length(9)
	// Both callers decode chip maps. No valid proof has more than maxChips
	// distinct names; reject as soon as this monotone bound is exceeded.
	// Keep a small sorted slice so duplicate keys do not retain extra values.
	out := make([]namedValue[V], 0, min(n, maxChips))
	for range n {
		k := d.str()
		if len(k) > maxChipNameBytes {
			d.fail(errors.New("chip name exceeds limit"))
		}
		if d.err != nil {
			return nil
		}
		index, found := slices.BinarySearchFunc(out, k, func(a namedValue[V], b string) int { return strings.Compare(a.name, b) })
		if !found && len(out) == maxChips {
			d.fail(errors.New("chip count exceeds limit"))
			return nil
		}
		v := value(d)
		if d.err != nil {
			return nil
		}
		entry := namedValue[V]{k, v}
		if found {
			out[index] = entry
		} else {
			out = slices.Insert(out, index, entry)
		}
	}
	return out
}

type namedValue[V any] struct {
	name  string
	value V
}

// The proof types mirror SP1's, in field order.

type compressedProof struct {
	vk            verifyingKey
	shard         shardProof
	vkMerkleIndex uint64
	vkMerklePath  []digest
}

type verifyingKey struct {
	pcStart            [3]felt
	globalSumX         [7]felt
	globalSumY         [7]felt
	preprocessedCommit digest
	untrustedPrograms  felt
}

type shardProof struct {
	publicValues   []felt
	mainCommitment digest
	gkr            gkrProof
	zerocheck      sumcheckProof
	openings       []namedValue[chipOpening]
	pcs            jaggedProof
}

type gkrProof struct {
	numerator   tensor[ext]
	denominator tensor[ext]
	rounds      []gkrRound
	point       []ext
	chipEvals   []namedValue[chipEvaluation]
	witness     felt
}

type gkrRound struct {
	numerator0, numerator1, denominator0, denominator1 ext
	sumcheck                                           sumcheckProof
}

type chipEvaluation struct {
	main         tensor[ext]
	preprocessed *tensor[ext]
}

type sumcheckProof struct {
	polys      [][]ext
	claimedSum ext
	point      []ext
	eval       ext
}

type chipOpening struct {
	preprocessed []ext
	main         []ext
	degree       []felt
}

type jaggedProof struct {
	stacked        stackedProof
	sumcheck       sumcheckProof
	jaggedEval     sumcheckProof
	rowColCounts   [][][2]uint64
	commitments    []digest
	expectedEval   ext
	maxLogRowCount uint64
	logM           uint64
}

type stackedProof struct {
	basefold   basefoldProof
	batchEvals []tensor[ext]
}

type basefoldProof struct {
	univariate        [][2]ext
	friCommitments    []digest
	componentOpenings []merkleOpening
	queryOpenings     []merkleOpening
	finalPoly         ext
	powWitness        felt
	batchWitness      felt
}

type merkleOpening struct {
	values    tensor[felt]
	root      digest
	logHeight uint64
	width     uint64
	paths     tensor[digest]
}

func (d *decoder) sumcheck() sumcheckProof {
	var p sumcheckProof
	p.polys = make([][]ext, d.length(8))
	for i := range p.polys {
		p.polys[i] = d.exts()
	}
	p.claimedSum = d.ext()
	p.point = d.exts()
	p.eval = d.ext()
	return p
}

func (d *decoder) merkleOpenings() []merkleOpening {
	out := make([]merkleOpening, d.length(8+8+4*digestSize+16+16))
	for i := range out {
		o := &out[i]
		o.values = d.feltTensor()
		o.root = d.digest()
		o.logHeight = d.u64()
		o.width = d.u64()
		o.paths = d.digestTensor()
	}
	return out
}

func (d *decoder) shardProof() shardProof {
	var p shardProof
	p.publicValues = d.felts()
	p.mainCommitment = d.digest()

	g := &p.gkr
	g.numerator = d.extTensor()
	g.denominator = d.extTensor()
	g.rounds = make([]gkrRound, d.length(4*16+8))
	for i := range g.rounds {
		r := &g.rounds[i]
		r.numerator0, r.numerator1, r.denominator0, r.denominator1 = d.ext(), d.ext(), d.ext(), d.ext()
		r.sumcheck = d.sumcheck()
	}
	g.point = d.exts()
	g.chipEvals = decodeMap(d, func(d *decoder) chipEvaluation {
		var e chipEvaluation
		e.main = d.extTensor()
		if d.option() {
			t := d.extTensor()
			e.preprocessed = &t
		}
		return e
	})
	g.witness = d.felt()

	p.zerocheck = d.sumcheck()
	p.openings = decodeMap(d, func(d *decoder) chipOpening {
		return chipOpening{preprocessed: d.exts(), main: d.exts(), degree: d.felts()}
	})

	j := &p.pcs
	b := &j.stacked.basefold
	b.univariate = make([][2]ext, d.length(32))
	for i := range b.univariate {
		b.univariate[i] = [2]ext{d.ext(), d.ext()}
	}
	b.friCommitments = d.digests()
	b.componentOpenings = d.merkleOpenings()
	b.queryOpenings = d.merkleOpenings()
	b.finalPoly = d.ext()
	b.powWitness = d.felt()
	b.batchWitness = d.felt()
	j.stacked.batchEvals = make([]tensor[ext], d.length(16))
	for i := range j.stacked.batchEvals {
		j.stacked.batchEvals[i] = d.extTensor()
	}
	j.sumcheck = d.sumcheck()
	j.jaggedEval = d.sumcheck()
	j.rowColCounts = make([][][2]uint64, d.length(8))
	for i := range j.rowColCounts {
		round := make([][2]uint64, d.length(16))
		for k := range round {
			round[k] = [2]uint64{d.u64(), d.u64()}
		}
		j.rowColCounts[i] = round
	}
	j.commitments = d.digests()
	j.expectedEval = d.ext()
	j.maxLogRowCount = d.u64()
	j.logM = d.u64()
	return p
}

// sp1ProofCompressed is the index of the Compressed variant of SP1's SP1Proof enum.
const sp1ProofCompressed = 1

// decodeCompressedProof decodes a bincode-encoded SP1Proof that must be the Compressed variant,
// with no trailing bytes.
func decodeCompressedProof(b []byte) (*compressedProof, error) {
	if len(b) > maxProofBytes {
		return nil, errors.New("malformed proof: exceeds the decode limit")
	}
	d := &decoder{buf: b}
	variant := d.u32()
	if d.err == nil && variant != sp1ProofCompressed {
		return nil, errors.New("aggregate proof is not an SP1 compressed proof")
	}
	var p compressedProof
	for i := range p.vk.pcStart {
		p.vk.pcStart[i] = d.felt()
	}
	for i := range p.vk.globalSumX {
		p.vk.globalSumX[i] = d.felt()
	}
	for i := range p.vk.globalSumY {
		p.vk.globalSumY[i] = d.felt()
	}
	p.vk.preprocessedCommit = d.digest()
	p.vk.untrustedPrograms = d.felt()
	p.shard = d.shardProof()
	p.vkMerkleIndex = d.u64()
	p.vkMerklePath = d.digests()
	if d.err != nil {
		return nil, fmt.Errorf("malformed proof: %w", d.err)
	}
	if len(d.buf) != 0 {
		return nil, errors.New("trailing bytes after the proof")
	}
	return &p, nil
}
