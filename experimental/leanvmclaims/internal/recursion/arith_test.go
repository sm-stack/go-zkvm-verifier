package recursion

import (
	"errors"
	fixture "github.com/sm-stack/go-zkvm-verifier/internal/testutil"
	"testing"

	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims/internal/transcript"
)

// A zero product on each side is a valid one-layer GKR. Replacing every child
// on the first side by one changes only that product, independent of lambda.
// These cases end at the tested layer, so no later check can mask its removal.
func TestGKRLayerBindings(t *testing.T) {
	for _, tc := range []struct {
		mu, children int
		want         error
	}{{1, 2, ErrGKROdd}, {2, 4, ErrGKRQuad}} {
		for _, corrupt := range []bool{false, true} {
			var messages fixture.Messages
			messages.Elements(E{}) // Root product.
			for side := range 2 {
				child := E{}
				if corrupt && side == 0 {
					child = one
				}
				for range tc.children {
					messages.Elements(child)
				}
			}
			v, err := transcript.NewVerifier([32]byte{}, []byte{1}, transcript.Proof{Messages: messages})
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = products(&reader{FieldReader: transcript.FieldReader{Verifier: v}}, tc.mu)
			if corrupt {
				if !errors.Is(err, tc.want) {
					t.Fatalf("mu=%d: wanted layer rejection, got %v", tc.mu, err)
				}
			} else if err != nil || v.EOF() != nil {
				t.Fatalf("valid mu=%d: %v", tc.mu, err)
			}
		}
	}
}
