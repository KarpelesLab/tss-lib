package common

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestGetRandomPositiveInt_RejectsZero is a property-based check that
// GetRandomPositiveInt does not return 0 — the function now matches its
// "Positive" name. The probability of a single random sample being 0 is
// 1/lessThan, which for cryptographic moduli is negligible; this test
// drives the rejection via a small modulus where 0 is well-represented.
func TestGetRandomPositiveInt_RejectsZero(t *testing.T) {
	// Modulus = 4 → values in [1, 4) = {1, 2, 3}. Repeat enough times
	// that an unbiased sampler that allowed 0 would almost certainly
	// hit it (4^-200 ≈ 10^-120 false-pass probability).
	mod := big.NewInt(4)
	for i := 0; i < 4096; i++ {
		v := GetRandomPositiveInt(rand.Reader, mod)
		require.NotNil(t, v)
		require.NotZero(t, v.Sign(), "GetRandomPositiveInt returned 0 (iteration %d)", i)
		require.True(t, v.Cmp(mod) < 0)
	}
}

// TestGetRandomPositiveInt_NilOnUnreasonableBound verifies the
// degenerate inputs return nil rather than infinite-loop.
func TestGetRandomPositiveInt_NilOnUnreasonableBound(t *testing.T) {
	cases := []*big.Int{
		nil,
		big.NewInt(0),
		big.NewInt(-5),
		big.NewInt(1), // [1, 1) is empty
	}
	for _, bound := range cases {
		v := GetRandomPositiveInt(rand.Reader, bound)
		require.Nil(t, v, "bound=%v should return nil", bound)
	}
}
