package sp1

// Node operations of a chip's constraint DAG, as exported by the generator.
const (
	opConst = iota
	opPreprocessed
	opMain
	opPublic
	opAdd
	opSub
	opNeg
	opMul
)

// chipAir is a compress machine chip: its trace widths, its constraints as a DAG of (op, a, b)
// nodes in topological order, and its lookup interactions.
type chipAir struct {
	name              string
	preprocessedWidth int
	width             int
	// nodes holds three words per node: the operation and two operands. Operands are node indices,
	// column indices, or a constant's canonical value, depending on the operation.
	nodes []uint32
	// constraints are the nodes asserted to be zero, in the order the AIR asserts them.
	constraints []uint32
	sends       []interaction
	receives    []interaction
}

// columnTerm is weight * column, where the column is preprocessed or main.
type columnTerm struct {
	preprocessed bool
	index        int
	weight       uint32
}

// virtualColumn is an affine combination of columns.
type virtualColumn struct {
	constant uint32
	terms    []columnTerm
}

// interaction is a lookup a chip sends or receives: a multiplicity and a tuple of values, tagged
// with the interaction kind.
type interaction struct {
	kind         uint64
	multiplicity virtualColumn
	values       []virtualColumn
}

func (v virtualColumn) eval(preprocessed, main []ext) ext {
	result := extFromFelt(feltFromU32(v.constant))
	for _, t := range v.terms {
		col := main
		if t.preprocessed {
			col = preprocessed
		}
		result = result.add(col[t.index].mulFelt(feltFromU32(t.weight)))
	}
	return result
}

// eval returns the interaction's multiplicity and fingerprint
// alpha + betas[0]*kind + sum_i values[i]*betas[i+1].
func (in interaction) eval(preprocessed, main []ext, alpha ext, betas []ext) (ext, ext) {
	multiplicity := in.multiplicity.eval(preprocessed, main)
	fingerprint := alpha.add(betas[0].mul(extFromU64(in.kind)))
	for i, value := range in.values {
		if i+1 >= len(betas) {
			break
		}
		fingerprint = fingerprint.add(value.eval(preprocessed, main).mul(betas[i+1]))
	}
	return multiplicity, fingerprint
}

// numInteractions returns the number of interactions the chip sends and receives.
func (c *chipAir) numInteractions() int {
	return len(c.sends) + len(c.receives)
}

// evalConstraints folds the chip's constraints at one row of opened values:
// acc = acc*alpha + constraint, in constraint order.
func (c *chipAir) evalConstraints(preprocessed, main []ext, alpha ext, publicValues []felt) ext {
	values := make([]ext, len(c.nodes)/3)
	for i := range values {
		op, a, b := c.nodes[3*i], c.nodes[3*i+1], c.nodes[3*i+2]
		switch op {
		case opConst:
			values[i] = extFromFelt(feltFromU32(a))
		case opPreprocessed:
			values[i] = preprocessed[a]
		case opMain:
			values[i] = main[a]
		case opPublic:
			values[i] = extFromFelt(publicValues[a])
		case opAdd:
			values[i] = values[a].add(values[b])
		case opSub:
			values[i] = values[a].sub(values[b])
		case opNeg:
			values[i] = values[a].neg()
		case opMul:
			values[i] = values[a].mul(values[b])
		default:
			panic("sp1: unknown constraint operation")
		}
	}
	acc := extZero
	for _, root := range c.constraints {
		acc = acc.mul(alpha).add(values[root])
	}
	return acc
}
