package ctmul

import (
	"errors"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/secp256k1"
	"github.com/KarpelesLab/tss-lib/v2/crypto"
)

// failingReader returns an error on every Read.
type failingReader struct{}

func (failingReader) Read(p []byte) (int, error) { return 0, errors.New("rng failure") }

// TestScalarMultWithRand_PanicsOnRNGFailure verifies that the CT scalar
// mult on secp256k1 panics rather than silently downgrades to the non-CT
// primitive when the RNG fails. A silent downgrade would defeat the
// entire purpose of routing secret-scalar mults through ctmul; failing
// loudly is the correct behavior so a misconfigured RNG cannot leak
// secret-scalar bits via timing.
func TestScalarMultWithRand_PanicsOnRNGFailure(t *testing.T) {
	ec := secp256k1.S256()
	G := crypto.NewECPointNoCurveCheck(ec, ec.Params().Gx, ec.Params().Gy)
	k := big.NewInt(42)

	defer func() {
		r := recover()
		require.NotNil(t, r, "RNG failure must panic, not silently fall back")
	}()
	_ = ScalarMultWithRand(G, k, failingReader{})
	t.Fatalf("did not panic on RNG failure")
}

// TestScalarBaseMultWithRand_PanicsOnRNGFailure is the analogous test for
// the base-point variant.
func TestScalarBaseMultWithRand_PanicsOnRNGFailure(t *testing.T) {
	ec := secp256k1.S256()
	k := big.NewInt(42)

	defer func() {
		r := recover()
		require.NotNil(t, r, "RNG failure must panic")
	}()
	_ = ScalarBaseMultWithRand(ec, k, failingReader{})
	t.Fatalf("did not panic on RNG failure")
}
