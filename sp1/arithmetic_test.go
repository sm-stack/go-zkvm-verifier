package sp1

import (
	"github.com/stretchr/testify/require"
	"math/rand/v2"
	"testing"
)

// internalDiagonalShifts[i-1] is log2 of the internal matrix's diagonal entry for i >= 1. The entry
// for i = 0 is -2.
var internalDiagonalShifts = [poseidon2Width - 1]uint{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 15}

func TestMontgomeryReduction(t *testing.T) {
	r := rand.New(rand.NewPCG(17, 42))
	limit := uint64(fieldOrder) << 32
	check := func(x uint64) {
		require.Equal(t, felt((x%fieldOrder)*uint64(montyInverse)%fieldOrder), montgomeryReduce(x), "t=%d", x)
	}
	for _, x := range []uint64{0, 1, fieldOrder - 1, fieldOrder, 1<<32 - 1, 1 << 32, limit - 2, limit - 1} {
		check(x)
	}
	for range 100000 {
		check(r.Uint64() % limit)
	}
}
func TestInternalLayerArithmetic(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for n := 0; n < 10000; n++ {
		var state [16]felt
		for i := range state {
			if n == 0 {
				state[i] = fieldOrder - 1
			} else {
				state[i] = feltFromU32(r.Uint32())
			}
		}
		want := state
		var sum felt
		for _, x := range want {
			sum = sum.add(x)
		}
		want[0] = sum.sub(want[0].add(want[0])).mul(montyInverse)
		for i := 1; i < 16; i++ {
			want[i] = sum.add(want[i].mul(felt(1) << internalDiagonalShifts[i-1])).mul(montyInverse)
		}
		internalLinearLayer(&state)
		require.Equal(t, want, state)
	}
}

// applyMat4 multiplies four state elements by the circulant-like matrix
// [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]].
func applyMat4(x *[4]felt) {
	t01 := x[0].add(x[1])
	t23 := x[2].add(x[3])
	t0123 := t01.add(t23)
	t01123 := t0123.add(x[1])
	t01233 := t0123.add(x[3])
	x3 := t01233.add(x[0].add(x[0]))
	x1 := t01123.add(x[2].add(x[2]))
	x0 := t01123.add(t01)
	x2 := t01233.add(t23)
	x[0], x[1], x[2], x[3] = x0, x1, x2, x3
}

// permute applies SP1's KoalaBear Poseidon2 permutation (width 16, x^3 S-box, 8 full and 20 partial
// rounds) in place.
func permuteReference(state *[poseidon2Width]felt) {
	externalLinearLayer(state)
	for r := 0; r < 2*poseidon2HalfFullRound; r++ {
		if r == poseidon2HalfFullRound {
			for p := 0; p < poseidon2PartialRounds; p++ {
				state[0] = sbox(state[0].add(poseidon2InternalFelts[p]))
				internalLinearLayer(state)
			}
		}
		for i := range state {
			state[i] = sbox(state[i].add(poseidon2ExternalFelts[r][i]))
		}
		externalLinearLayer(state)
	}
}

func externalLinearLayer(state *[poseidon2Width]felt) {
	for i := 0; i < poseidon2Width; i += 4 {
		chunk := [4]felt{state[i], state[i+1], state[i+2], state[i+3]}
		applyMat4(&chunk)
		copy(state[i:i+4], chunk[:])
	}
	var sums [4]felt
	for k := range sums {
		for j := 0; j < poseidon2Width; j += 4 {
			sums[k] = sums[k].add(state[j+k])
		}
	}
	for i := range state {
		state[i] = state[i].add(sums[i%4])
	}
}

func internalLinearLayer(state *[16]felt) {
	var sum felt
	for _, x := range state {
		sum = sum.add(x)
	}
	state[0] = sum.sub(state[0].add(state[0])).mul(montyInverse)
	for i := 1; i < 16; i++ {
		state[i] = sum.add(state[i].mul(felt(1) << internalDiagonalShifts[i-1])).mul(montyInverse)
	}
}
func sbox(x felt) felt { return x.square().mul(x) }

var montyInverse = feltFromU64(1 << 32).inverse()

func TestGeneratedPermutation(t *testing.T) {
	r := rand.New(rand.NewPCG(77, 33))
	for n := 0; n < 100000; n++ {
		var x [16]felt
		for i := range x {
			switch n {
			case 0:
				x[i] = 0
			case 1:
				x[i] = fieldOrder - 1
			case 2:
				if i%2 == 0 {
					x[i] = fieldOrder - 1
				}
			default:
				x[i] = feltFromU32(r.Uint32())
			}
		}
		want := x
		permuteReference(&want)
		permute(&x)
		if x != want {
			t.Fatalf("permutation differs at case %d", n)
		}
	}
}
func FuzzPermutation(f *testing.F) {
	f.Add(make([]byte, 64))
	f.Add([]byte{255, 255, 255, 255})
	f.Fuzz(func(t *testing.T, b []byte) {
		var state [16]felt
		for i, v := range b {
			if i >= 64 {
				break
			}
			state[i/4] |= felt(uint32(v) << uint(8*(i%4)))
		}
		for i, v := range state {
			state[i] = feltFromU32(uint32(v))
		}
		want := state
		permuteReference(&want)
		permute(&state)
		if state != want {
			t.Fatal("permutation differs")
		}
	})
}

func TestFactoredLagrange(t *testing.T) {
	r := rand.New(rand.NewPCG(35, 99))
	for n := 0; n <= 32; n++ {
		a, b := make([]ext, 2*n), make([]ext, 2*n)
		for i := range a {
			for k := range a[i] {
				a[i][k] = felt(r.Uint32() % fieldOrder)
				b[i][k] = felt(r.Uint32() % fieldOrder)
			}
		}
		require.Equal(t, fullLagrangeEval(a, b), fullLagrangeEval(a[:n], b[:n]).mul(fullLagrangeEval(a[n:], b[n:])))
	}
}
