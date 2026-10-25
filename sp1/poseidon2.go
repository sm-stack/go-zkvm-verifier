package sp1

const (
	poseidon2Width         = 16
	poseidon2HalfFullRound = 4
	poseidon2PartialRounds = 20
	// digestSize is the number of field elements in a hash digest.
	digestSize = 8
	// spongeRate is the number of elements the sponge absorbs per permutation.
	spongeRate = 8
)

// digest is a Poseidon2 hash output.
type digest [digestSize]felt

func digestFromU32s(words []uint32) digest {
	var d digest
	for i, w := range words {
		d[i] = feltFromU32(w)
	}
	return d
}

// montgomeryReduce returns t*2^-32 mod p for t < p*2^32.
// -p^-1 mod 2^32 = 0x7effffff. Thus t+m*p is divisible by 2^32,
// is less than 2*p*2^32 < 2^64, and its quotient is less than 2*p.
func montgomeryReduce(t uint64) felt {
	m := uint64(uint32(t) * uint32(0x7effffff))
	u := (t + m*fieldOrder) >> 32
	if u >= fieldOrder {
		u -= fieldOrder
	}
	return felt(u)
}

//go:generate python3 ../tools/gen_poseidon2.py

var (
	poseidon2ExternalFelts [2 * poseidon2HalfFullRound][poseidon2Width]felt
	poseidon2InternalFelts [poseidon2PartialRounds]felt
)

func init() {
	for r := range poseidon2ExternalFelts {
		for i := range poseidon2ExternalFelts[r] {
			poseidon2ExternalFelts[r][i] = feltFromU32(poseidon2ExternalConstants[r*poseidon2Width+i])
		}
	}
	for i := range poseidon2InternalFelts {
		poseidon2InternalFelts[i] = feltFromU32(poseidon2InternalConstants[i])
	}
}

// hashFelts is SP1's padding-free sponge: each chunk of up to spongeRate inputs overwrites the start
// of the state, which is then permuted. An empty input hashes to zero.
func hashFelts(input []felt) digest {
	var state [poseidon2Width]felt
	for len(input) > 0 {
		n := min(spongeRate, len(input))
		copy(state[:n], input[:n])
		input = input[n:]
		permute(&state)
	}
	var out digest
	copy(out[:], state[:digestSize])
	return out
}

// compress is SP1's two-to-one compression: the two digests fill the state, which is permuted and
// truncated.
func compress(left, right digest) digest {
	var state [poseidon2Width]felt
	copy(state[:digestSize], left[:])
	copy(state[digestSize:], right[:])
	permute(&state)
	var out digest
	copy(out[:], state[:digestSize])
	return out
}
