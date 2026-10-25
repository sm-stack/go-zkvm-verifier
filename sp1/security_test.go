package sp1

import (
	"crypto/sha256"
	"encoding/binary"
	"github.com/stretchr/testify/require"
	"lukechampine.com/blake3"
	"strings"
	"testing"
)

// Exercise bindings *after* shard verification so an earlier transcript failure
// cannot hide a missing public-value check.
func TestCompressedBindings(t *testing.T) {
	f := loadFixture(t)
	p, err := decodeCompressedProof(f.proof)
	require.NoError(t, err)
	var key digest
	for i := range key {
		key[i] = felt(binary.BigEndian.Uint32(f.vkeyHash[4*i:]))
	}
	require.NoError(t, verifyCompressedBindings(p, key))
	for _, tc := range []struct {
		name    string
		at      int
		rehash  bool
		message string
	}{
		{"digest", pvDigest, false, "recursion public values"},
		{"root", pvVkRoot, true, "vk merkle root mismatch"},
		{"complete", pvIsComplete, true, "is_complete"},
		{"program", pvSP1VkDigest, true, "sp1 vk hash mismatch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q, err := decodeCompressedProof(f.proof)
			require.NoError(t, err)
			q.shard.publicValues[tc.at] = q.shard.publicValues[tc.at].add(1)
			if tc.rehash {
				h := hashFelts(q.shard.publicValues[:pvNumHashed])
				copy(q.shard.publicValues[pvDigest:], h[:])
			}
			require.ErrorContains(t, verifyCompressedBindings(q, key), tc.message)
		})
	}
}

func TestCommitmentAlgorithms(t *testing.T) {
	data := []byte("stark-go-verify public values")
	for name, hash := range map[string][32]byte{"sha256": sha256.Sum256(data), "blake3": blake3.Sum256(data)} {
		t.Run(name, func(t *testing.T) {
			pv := make([]felt, numPublicValues)
			for i, b := range hash {
				pv[pvCommittedValueDigest+i] = felt(b)
			}
			require.NoError(t, checkPublicValuesCommitment(pv, data))
			require.Error(t, checkPublicValuesCommitment(pv, append(data, 1)))
		})
	}
}

func TestMapLimits(t *testing.T) {
	for _, tc := range []struct {
		count, width int
		want         string
	}{
		{maxChips, maxChipNameBytes, ""}, {maxChips + 1, 8, "chip count"}, {1, maxChipNameBytes + 1, "chip name"},
	} {
		buf := binary.LittleEndian.AppendUint64(nil, uint64(tc.count))
		for i := 0; i < tc.count; i++ {
			key := strings.Repeat("x", tc.width-1) + string(rune('A'+i))
			buf = binary.LittleEndian.AppendUint64(buf, uint64(len(key)))
			buf = append(buf, key...)
			buf = binary.LittleEndian.AppendUint64(buf, uint64(i))
		}
		d := &decoder{buf: buf}
		got := decodeMap(d, (*decoder).u64)
		if tc.want == "" {
			require.NoError(t, d.err)
			require.Len(t, got, tc.count)
		} else {
			require.ErrorContains(t, d.err, tc.want)
		}
	}
}

func TestDecodeResourceGuards(t *testing.T) {
	_, err := decodeCompressedProof(make([]byte, MaxProofBytes+1))
	require.ErrorContains(t, err, "decode limit")
	d := &decoder{buf: append(binary.LittleEndian.AppendUint64(nil, 1), 0xff)}
	d.str()
	require.ErrorContains(t, d.err, "utf")
	for _, dims := range [][]uint64{{0, 0, 0, 0}, {0, 1 << 63, 2}, {1 << 63, 2, 0}} {
		buf := binary.LittleEndian.AppendUint64(nil, 0) // empty data
		buf = binary.LittleEndian.AppendUint64(buf, uint64(len(dims)))
		for _, v := range dims {
			buf = binary.LittleEndian.AppendUint64(buf, v)
		}
		d := &decoder{buf: buf}
		d.feltTensor()
		if len(dims) > 3 {
			require.ErrorContains(t, d.err, "more than three")
		} else {
			require.ErrorContains(t, d.err, "overflows")
		}
	}
}

func TestMerkleIndexBound(t *testing.T) {
	values := []felt{7}
	root := hashFelts(values)
	o := &merkleOpening{width: 1, logHeight: 0, root: root,
		values: tensor[felt]{data: values, dims: []uint64{1, 1}},
		paths:  tensor[digest]{dims: []uint64{1, 0}}}
	commitment := compress(root, hashFelts([]felt{0, 1}))
	require.NoError(t, verifyMerkleOpenings(commitment, []uint64{0}, o, 1, 0))
	require.ErrorIs(t, verifyMerkleOpenings(commitment, []uint64{1}, o, 1, 0), errMerkleShape)
}

// Reconstruct the fixture transcript at a stage boundary. The valid baseline
// must pass before any decoded claim is changed.
func stageFixture(t *testing.T) (*compressedProof, []shardChip, *challenger) {
	f := loadFixture(t)
	p, err := decodeCompressedProof(f.proof)
	require.NoError(t, err)
	c := newChallenger()
	c.observeDigest(p.vk.preprocessedCommit)
	c.observeFelts(p.vk.pcStart[:])
	c.observeFelts(p.vk.globalSumX[:])
	c.observeFelts(p.vk.globalSumY[:])
	c.observe(p.vk.untrustedPrograms)
	c.observeFelts(make([]felt, 6))
	c.observeFelts(p.shard.publicValues)
	c.observeDigest(p.shard.mainCommitment)
	c.observe(felt(len(p.shard.openings)))
	for _, o := range p.shard.openings {
		c.observe(bitStringEvaluation(o.value.degree))
		c.observe(felt(len(o.name)))
		for _, b := range []byte(o.name) {
			c.observe(felt(b))
		}
	}
	chips := make([]shardChip, len(compressChips))
	for i := range chips {
		chips[i] = shardChip{&compressChips[i], &p.shard.openings[i].value, &p.shard.gkr.chipEvals[i].value}
	}
	return p, chips, c
}

func TestGKRStageBindings(t *testing.T) {
	p, chips, c := stageFixture(t)
	require.NoError(t, verifyGkr(chips, &p.shard.gkr, c))
	// Numerator multiplicities may reside in preprocessed or main columns.
	for i := range chips {
		for _, pre := range []bool{true, false} {
			length := len(chips[i].gkr.main.data)
			if pre {
				if chips[i].gkr.preprocessed == nil {
					continue
				}
				length = len(chips[i].gkr.preprocessed.data)
			}
			for j := 0; j < length; j++ {
				p, chips, c = stageFixture(t)
				data := chips[i].gkr.main.data
				if pre {
					data = chips[i].gkr.preprocessed.data
				}
				data[j] = data[j].add(extOne)
				err := verifyGkr(chips, &p.shard.gkr, c)
				if err != nil && strings.Contains(err.Error(), "numerator evaluation mismatch") {
					return
				}
			}
		}
	}
	t.Fatal("no trace mutation exercised the numerator binding")
}

func TestZerocheckStageBindings(t *testing.T) {
	p, chips, c := stageFixture(t)
	require.NoError(t, verifyGkr(chips, &p.shard.gkr, c))
	require.NoError(t, verifyZerocheck(chips, &p.shard, c))
	p, chips, c = stageFixture(t)
	require.NoError(t, verifyGkr(chips, &p.shard.gkr, c))
	chips[0].gkr.main.data[0] = chips[0].gkr.main.data[0].add(extOne)
	require.ErrorIs(t, verifyZerocheck(chips, &p.shard, c), errSumcheckClaimedSum)
}

func TestJaggedPaddingRows(t *testing.T) {
	prepare := func() (*compressedProof, []digest, [][]ext, *challenger) {
		p, chips, c := stageFixture(t)
		require.NoError(t, verifyGkr(chips, &p.shard.gkr, c))
		require.NoError(t, verifyZerocheck(chips, &p.shard, c))
		claims := make([][]ext, 2)
		for _, ch := range chips {
			claims[0] = append(claims[0], ch.opening.preprocessed...)
			claims[1] = append(claims[1], ch.opening.main...)
		}
		return p, []digest{p.vk.preprocessedCommit, p.shard.mainCommitment}, claims, c
	}
	p, commits, claims, c := prepare()
	require.NoError(t, verifyJagged(commits, p.shard.zerocheck.point, claims, &p.shard.pcs, c))
	p, commits, claims, c = prepare()
	rc := p.shard.pcs.rowColCounts[0]
	rc[len(rc)-2][0]-- // a zero-width padding column still has a required height
	input := []felt{felt(len(rc))}
	for _, e := range rc {
		input = append(input, felt(e[0]))
	}
	for _, e := range rc {
		input = append(input, felt(e[1]))
	}
	commits[0] = compress(p.shard.pcs.commitments[0], hashFelts(input))
	require.ErrorIs(t, verifyJagged(commits, p.shard.zerocheck.point, claims, &p.shard.pcs, c), errJaggedShape)
}

func TestGKRZeroDenominator(t *testing.T) {
	p, chips, initial := stageFixture(t)
	for i := range p.shard.gkr.denominator.data {
		oldD, oldN := p.shard.gkr.denominator.data[i], p.shard.gkr.numerator.data[i]
		p.shard.gkr.denominator.data[i] = extZero
		for _, n := range []ext{oldN, extZero} {
			p.shard.gkr.numerator.data[i] = n
			c := *initial
			c.input = append([]felt(nil), initial.input...)
			c.output = append([]felt(nil), initial.output...)
			require.ErrorContains(t, verifyGkr(chips, &p.shard.gkr, &c), "denominator evaluation has zero value", "index %d", i)
		}
		p.shard.gkr.denominator.data[i], p.shard.gkr.numerator.data[i] = oldD, oldN
	}
}

func TestMapRetainsLastDuplicate(t *testing.T) {
	buf := binary.LittleEndian.AppendUint64(nil, 3)
	for i, key := range []string{"b", "a", "b"} {
		buf = binary.LittleEndian.AppendUint64(buf, uint64(len(key)))
		buf = append(buf, key...)
		buf = binary.LittleEndian.AppendUint64(buf, uint64(i))
	}
	d := &decoder{buf: buf}
	values := decodeMap(d, (*decoder).u64)
	require.NoError(t, d.err)
	require.Equal(t, []namedValue[uint64]{{"a", 1}, {"b", 2}}, values)
}

func TestConcurrentVerify(t *testing.T) {
	f := loadFixture(t)
	results := make(chan error, 2)
	for range 2 {
		go func() { results <- Verify(f.vkeyHash, f.publicValues, f.proof) }()
	}
	for range 2 {
		require.NoError(t, <-results)
	}
}

// Jagged prefix sums are monotonically built from bounded nonnegative areas.
// The retained upstream monotonicity check is therefore redundant on reachable
// inputs. Test the comparator independently, including decreasing boundaries.
func TestBinaryMonotonicity(t *testing.T) {
	for _, a := range []uint64{0, 1, 2, 7, (1 << 29) - 1, 1 << 29, (1 << 30) - 1} {
		for _, b := range []uint64{0, 1, 2, 7, (1 << 29) - 1, 1 << 29, (1 << 30) - 1} {
			want := extZero
			if b >= a {
				want = extOne
			}
			require.Equal(t, want, fullGeq(pointFromUint(a, 31), pointFromUint(b, 31)))
		}
	}
}

func TestMerkleBatchErrorOrder(t *testing.T) {
	const rows = 32
	const depth = 8
	o := &merkleOpening{width: 1, logHeight: depth,
		values: tensor[felt]{data: make([]felt, rows), dims: []uint64{rows, 1}},
		paths:  tensor[digest]{data: make([]digest, rows*depth), dims: []uint64{rows, depth}}}
	for i := range o.values.data {
		o.values.data[i] = 7
	}
	o.root = hashFelts([]felt{7})
	for range depth {
		o.root = compress(o.root, digest{})
	}
	commitment := compress(o.root, hashFelts([]felt{depth, 1}))
	indices := make([]uint64, rows)
	require.NoError(t, verifyMerkleOpenings(commitment, indices, o, 1, depth))
	indices[rows-1] = 1 << depth
	require.ErrorIs(t, verifyMerkleOpenings(commitment, indices, o, 1, depth), errMerkleShape)
	o.values.data[0] = 8
	require.ErrorIs(t, verifyMerkleOpenings(commitment, indices, o, 1, depth), errMerkleRoot)
}

// The early total-area bound makes the later ordinary area arithmetic safe.
// Requiring this specific rejection keeps later shape failures from masking it.
func TestJaggedTotalAreaBound(t *testing.T) {
	for _, area := range []uint64{1 << 30, 1<<30 + 1, fieldOrder - 1} {
		p := jaggedProof{
			rowColCounts:   [][][2]uint64{{{area, 1}, {0, 0}, {0, 1}}, {{0, 0}, {0, 1}}},
			commitments:    make([]digest, numCommitments),
			maxLogRowCount: maxLogRowCount,
			logM:           29,
		}
		err := verifyJagged(make([]digest, numCommitments), make([]ext, maxLogRowCount),
			[][]ext{{extZero}, nil}, &p, &challenger{})
		require.ErrorIs(t, err, errJaggedAreaBounds)
	}
}
