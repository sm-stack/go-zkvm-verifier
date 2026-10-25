package sp1

// challenger is SP1's Fiat-Shamir duplex challenger over the Poseidon2 permutation (width 16,
// rate 8). Observations overwrite the start of the state once eight are buffered; samples are taken
// from the end of the last permutation's rate part.
type challenger struct {
	state  [poseidon2Width]felt
	input  []felt
	output []felt
}

func newChallenger() *challenger {
	return &challenger{
		input:  make([]felt, 0, spongeRate),
		output: make([]felt, 0, spongeRate),
	}
}

func (c *challenger) duplex() {
	copy(c.state[:len(c.input)], c.input)
	c.input = c.input[:0]
	permute(&c.state)
	c.output = append(c.output[:0], c.state[:spongeRate]...)
}

func (c *challenger) observe(x felt) {
	c.output = c.output[:0]
	c.input = append(c.input, x)
	if len(c.input) == spongeRate {
		c.duplex()
	}
}

func (c *challenger) observeFelts(xs []felt) {
	for _, x := range xs {
		c.observe(x)
	}
}

func (c *challenger) observeDigest(d digest) {
	c.observeFelts(d[:])
}

func (c *challenger) observeExt(x ext) {
	c.observeFelts(x[:])
}

func (c *challenger) observeExts(xs []ext) {
	for _, x := range xs {
		c.observeExt(x)
	}
}

// observeExtsWithLength observes the length of xs and then its elements, like SP1's
// observe_variable_length_extension_slice.
func (c *challenger) observeExtsWithLength(xs []ext) {
	c.observe(feltFromU64(uint64(len(xs))))
	c.observeExts(xs)
}

func (c *challenger) sample() felt {
	if len(c.input) > 0 || len(c.output) == 0 {
		c.duplex()
	}
	x := c.output[len(c.output)-1]
	c.output = c.output[:len(c.output)-1]
	return x
}

func (c *challenger) sampleExt() ext {
	return ext{c.sample(), c.sample(), c.sample(), c.sample()}
}

func (c *challenger) samplePoint(n int) []ext {
	point := make([]ext, n)
	for i := range point {
		point[i] = c.sampleExt()
	}
	return point
}

// sampleBits returns the low bits of a sampled element's canonical value.
func (c *challenger) sampleBits(bits uint) uint64 {
	return uint64(c.sample()) & (1<<bits - 1)
}

// checkWitness observes a proof-of-work witness and reports whether the next sample has its low
// bits zero.
func (c *challenger) checkWitness(bits uint, witness felt) bool {
	c.observe(witness)
	return c.sampleBits(bits) == 0
}
