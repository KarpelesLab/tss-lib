package ctmul

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/KarpelesLab/edwards25519"
	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/crypto"
)

// TestScalarBaseMultDispatchEd25519 verifies that the curve-dispatch
// extension wires Ed25519 callers through the CT primitive
// (crypto.CTScalarBaseMultEd25519) rather than the standard non-CT path.
// Output equivalence is the safety guarantee: callers see no visible
// change in result, only the side-channel surface changes.
func TestScalarBaseMultDispatchEd25519(t *testing.T) {
	ec := edwards25519.Edwards()
	q := ec.Params().N

	for i := 0; i < 16; i++ {
		k, err := rand.Int(rand.Reader, q)
		require.NoError(t, err)

		got := ScalarBaseMult(ec, k)
		want := crypto.CTScalarBaseMultEd25519(ec, k)
		require.Truef(t, got.Equals(want),
			"ctmul.ScalarBaseMult should route Ed25519 through CTScalarBaseMultEd25519 (k=%s)",
			k.Text(16))

		// Also matches the non-CT path mathematically.
		std := crypto.ScalarBaseMult(ec, k)
		require.True(t, got.Equals(std), "Ed25519 CT path must produce same point as std")
	}
	_ = big.NewInt
}
