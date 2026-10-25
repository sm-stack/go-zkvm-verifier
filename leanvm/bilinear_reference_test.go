package leanvm

func (c *circuit) bilinearExpanded(alpha ext, rowWeights, columnWeights []ext) ext {
	constant := columnWeights[c.constantColumn]
	var total ext
	wires := make([]ext, 0, len(c.gates))
	for _, g := range c.gates {
		var left, right ext
		slot := g.slot
		switch g.kind {
		case gateXor:
			wires = append(wires, wires[g.x].add(wires[g.y]))
			continue
		case gateFree:
			slot = g.x
			left, right = columnWeights[slot], constant
		case gateAnd:
			left, right = wires[g.x], wires[g.y]
		case gateCopy:
			left, right = wires[g.x], constant
		}
		wires = append(wires, columnWeights[slot])
		total = total.add(rowWeights[slot].mul(left.add(alpha.mul(right))))
	}
	return total
}
