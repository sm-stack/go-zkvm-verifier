// Field parameters match both pinned leanVM revisions; see NOTICE and UPSTREAM.md.
package field

import "github.com/sm-stack/go-zkvm-verifier/internal/gf2"

type Element = gf2.Element

var Zero = gf2.Zero
var One = gf2.One

func Lift(a uint64) Element    { return gf2.Lift(a) }
func Mul64(a, b uint64) uint64 { return gf2.Mul64(a, b) }
func Square64(a uint64) uint64 { return gf2.Square64(a) }
func Inv64(a uint64) uint64    { return gf2.Inv64(a) }
