package crypto

import (
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/KarpelesLab/edwards25519"
	"github.com/KarpelesLab/secp256k1"
	"github.com/stretchr/testify/require"
)

// TestCTScalarMulAddModN_MatchesBigInt verifies that the CT helper
// produces the same scalar as the standard big.Int formula on both
// supported curves. Equivalence is the safety guarantee: callers see no
// visible change in result, only the side-channel surface changes.
func TestCTScalarMulAddModN_MatchesBigInt(t *testing.T) {
	for _, ec := range []elliptic.Curve{secp256k1.S256(), edwards25519.Edwards()} {
		n := ec.Params().N
		for i := 0; i < 32; i++ {
			a, err := rand.Int(rand.Reader, n)
			require.NoError(t, err)
			b, err := rand.Int(rand.Reader, n)
			require.NoError(t, err)
			c, err := rand.Int(rand.Reader, n)
			require.NoError(t, err)

			got := CTScalarMulAddModN(ec, a, b, c)

			// Reference: (a*b + c) mod n via math/big.
			want := new(big.Int).Mul(a, b)
			want.Add(want, c)
			want.Mod(want, n)

			require.Zerof(t, got.Cmp(want),
				"curve=%T: got=%s want=%s (a=%s b=%s c=%s)",
				ec, got.Text(16), want.Text(16),
				a.Text(16), b.Text(16), c.Text(16))
		}
	}
}

// TestCTScalarMulAddModN_EdgeCases covers a=0, b=0, c=0, and reduced-input
// cases — anything that might exercise different paths in the underlying
// curve-specific implementations.
func TestCTScalarMulAddModN_EdgeCases(t *testing.T) {
	for _, ec := range []elliptic.Curve{secp256k1.S256(), edwards25519.Edwards()} {
		n := ec.Params().N

		cases := []struct {
			a, b, c *big.Int
		}{
			{big.NewInt(0), big.NewInt(0), big.NewInt(0)},
			{big.NewInt(1), big.NewInt(1), big.NewInt(0)},
			{big.NewInt(0), big.NewInt(7), big.NewInt(11)},
			{new(big.Int).Sub(n, big.NewInt(1)), new(big.Int).Sub(n, big.NewInt(1)), big.NewInt(0)},
			// a*b should wrap mod n.
			{big.NewInt(2), new(big.Int).Sub(n, big.NewInt(1)), big.NewInt(0)},
		}
		for _, tc := range cases {
			got := CTScalarMulAddModN(ec, tc.a, tc.b, tc.c)
			want := new(big.Int).Mul(tc.a, tc.b)
			want.Add(want, tc.c)
			want.Mod(want, n)
			require.Zerof(t, got.Cmp(want),
				"curve=%T a=%s b=%s c=%s: got=%s want=%s",
				ec, tc.a, tc.b, tc.c, got, want)
		}
	}
}

// TestCTScalarMulAddModN_UnsupportedCurveFallback verifies the fallback
// path computes the right value (using P-256 as a curve neither secp256k1
// nor edwards25519).
func TestCTScalarMulAddModN_UnsupportedCurveFallback(t *testing.T) {
	ec := elliptic.P256()
	n := ec.Params().N
	a := big.NewInt(42)
	b := big.NewInt(7)
	c := big.NewInt(11)
	got := CTScalarMulAddModN(ec, a, b, c)
	want := new(big.Int).Mul(a, b)
	want.Add(want, c)
	want.Mod(want, n)
	require.Zero(t, got.Cmp(want))
}
