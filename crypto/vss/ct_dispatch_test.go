package vss

import (
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/KarpelesLab/edwards25519"
	"github.com/KarpelesLab/secp256k1"
	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/crypto"
)

// TestCTScalarBaseMultProducesSamePointAsStandard verifies that on both
// supported curves the CT dispatcher yields the same affine point as the
// standard (non-CT) primitive. Equivalent output is the safety
// guarantee: callers see no visible change, only the side-channel
// surface is reduced.
func TestCTScalarBaseMultProducesSamePointAsStandard(t *testing.T) {
	type curveCase struct {
		name string
		ec   elliptic.Curve
	}
	cases := []curveCase{
		{"secp256k1", secp256k1.S256()},
		{"ed25519", edwards25519.Edwards()},
	}
	for _, cc := range cases {
		t.Run(cc.name, func(t *testing.T) {
			q := cc.ec.Params().N
			for i := 0; i < 8; i++ {
				k, err := rand.Int(rand.Reader, q)
				require.NoError(t, err)

				ct := ctScalarBaseMult(cc.ec, k)
				std := crypto.ScalarBaseMult(cc.ec, k)
				require.Truef(t, ct.Equals(std),
					"%s k=%s: CT and standard mult must produce same point",
					cc.name, k.Text(16))
			}
		})
	}
}

// TestVSSCreateOutputIsValid is a sanity check that the VSS.Verify
// round-trip still succeeds after Create was rewritten to use the CT
// dispatcher.
func TestVSSCreateOutputIsValid(t *testing.T) {
	for _, ec := range []elliptic.Curve{secp256k1.S256(), edwards25519.Edwards()} {
		q := ec.Params().N
		secret, err := rand.Int(rand.Reader, q)
		require.NoError(t, err)

		ids := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3)}
		vs, shares, err := Create(ec, 1, secret, ids, rand.Reader)
		require.NoError(t, err)
		for i, sh := range shares {
			require.Truef(t, sh.Verify(ec, 1, vs), "share %d failed verify on %T", i, ec)
		}
	}
}
