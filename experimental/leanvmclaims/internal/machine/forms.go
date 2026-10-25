package machine

import "errors"

// Form is the pinned degree-two polynomial for a recursion slot or identity.
// Coefficients are canonical GF(2^192) limbs, exported from Rust's BusForm.
type Form struct {
	Coeffs   [][3]uint64
	Prods    []Product
	Constant [3]uint64
}
type Product struct {
	A, B  int
	Value [3]uint64
}
type RecTable struct {
	Columns    int
	Slots      [][4]Form
	Identities []Form
}

func validateTables(tables []RecTable) error {
	if len(tables) != 5 {
		return errors.New("mixed: missing recursion table metadata")
	}
	slots := [5]int{4, 4, 16, 65, 8}
	for i, t := range tables {
		if t.Columns != ownedColumns[i] || len(t.Slots) != slots[i] {
			return errors.New("mixed: invalid recursion table shape")
		}
		forms := append([]Form(nil), t.Identities...)
		for _, slot := range t.Slots {
			forms = append(forms, slot[:]...)
		}
		for _, f := range forms {
			if len(f.Coeffs) != t.Columns {
				return errors.New("mixed: invalid recursion coefficients")
			}
			for _, p := range f.Prods {
				if p.A < 0 || p.A >= t.Columns || p.B < 0 || p.B >= t.Columns {
					return errors.New("mixed: invalid recursion product")
				}
			}
		}
	}
	return nil
}
