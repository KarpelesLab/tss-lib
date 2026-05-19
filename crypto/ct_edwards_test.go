package crypto

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/KarpelesLab/edwards25519"
	"github.com/stretchr/testify/require"
)

// TestCTScalarBaseMultEd25519MatchesStandard verifies that the CT-base
// scalar mult produces the same on-curve point as the standard non-CT
// path. The two should be byte-identical (same affine coordinates) for
// every input scalar.
func TestCTScalarBaseMultEd25519MatchesStandard(t *testing.T) {
	ec := edwards25519.Edwards()
	q := ec.Params().N

	cases := []*big.Int{
		big.NewInt(1),
		big.NewInt(2),
		big.NewInt(7),
		new(big.Int).Sub(q, big.NewInt(1)),
	}
	for i := 0; i < 16; i++ {
		r, err := rand.Int(rand.Reader, q)
		require.NoError(t, err)
		cases = append(cases, r)
	}

	for _, k := range cases {
		ct := CTScalarBaseMultEd25519(ec, k)
		std := ScalarBaseMult(ec, k)
		require.Truef(t, ct.Equals(std), "k=%s: CT path produced different point than standard",
			k.Text(16))
	}
}

// TestCTScalarBaseMultEd25519ZeroScalar verifies the k=0 case returns
// the curve identity. The reduction mod L means any L-multiple is also
// the identity.
func TestCTScalarBaseMultEd25519ZeroScalar(t *testing.T) {
	ec := edwards25519.Edwards()
	zero := big.NewInt(0)
	id := CTScalarBaseMultEd25519(ec, zero)
	// Identity on Ed25519 is (0, 1).
	require.Equal(t, 0, id.X().Sign())
	require.Equal(t, 0, id.Y().Cmp(big.NewInt(1)))
}

// TestCTScalarBaseMultEd25519ReducesModOrder verifies that k and k+L
// produce the same point (reduction mod L).
func TestCTScalarBaseMultEd25519ReducesModOrder(t *testing.T) {
	ec := edwards25519.Edwards()
	q := ec.Params().N

	k := big.NewInt(12345)
	kPlusL := new(big.Int).Add(k, q)

	p1 := CTScalarBaseMultEd25519(ec, k)
	p2 := CTScalarBaseMultEd25519(ec, kPlusL)
	require.True(t, p1.Equals(p2), "k and k+L must produce the same point")
}
