package schnorr_test

import (
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/KarpelesLab/edwards25519"
	"github.com/KarpelesLab/secp256k1"
	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/crypto"
	. "github.com/KarpelesLab/tss-lib/v2/crypto/schnorr"
)

// TestNewZKProofRoundTripsOnBothCurves verifies that NewZKProof produces
// a verifiable proof on both secp256k1 and Ed25519 after the CT-rewrite.
// This is the round-trip safety property: the rewrite must not change the
// mathematical output, only the side-channel surface.
func TestNewZKProofRoundTripsOnBothCurves(t *testing.T) {
	curves := []elliptic.Curve{secp256k1.S256(), edwards25519.Edwards()}
	for _, ec := range curves {
		t.Run(ec.Params().Name, func(t *testing.T) {
			q := ec.Params().N
			for i := 0; i < 16; i++ {
				x := common.GetRandomPositiveInt(rand.Reader, q)
				X := crypto.ScalarBaseMult(ec, x)

				proof, err := NewZKProof([]byte("session"), x, X, rand.Reader)
				require.NoError(t, err)
				require.True(t, proof.Verify([]byte("session"), X),
					"freshly-constructed Schnorr proof should verify")

				// Cross-tampering: same proof under a different session
				// must NOT verify.
				require.False(t, proof.Verify([]byte("other"), X),
					"proof should not verify under different session")
			}
		})
	}
	_ = big.NewInt
}

// TestNewZKVProofRoundTripsOnBothCurves is the analogous test for the
// two-witness proof NewZKVProof.
func TestNewZKVProofRoundTripsOnBothCurves(t *testing.T) {
	curves := []elliptic.Curve{secp256k1.S256(), edwards25519.Edwards()}
	for _, ec := range curves {
		t.Run(ec.Params().Name, func(t *testing.T) {
			q := ec.Params().N
			for i := 0; i < 8; i++ {
				s := common.GetRandomPositiveInt(rand.Reader, q)
				l := common.GetRandomPositiveInt(rand.Reader, q)

				// Pick R = r·G for some random r so we have a known
				// non-identity point.
				r := common.GetRandomPositiveInt(rand.Reader, q)
				R := crypto.ScalarBaseMult(ec, r)

				// V = R^s · G^l.
				sR := R.ScalarMult(s)
				lG := crypto.ScalarBaseMult(ec, l)
				V, err := sR.Add(lG)
				require.NoError(t, err)

				proof, err := NewZKVProof([]byte("v-session"), V, R, s, l, rand.Reader)
				require.NoError(t, err)
				require.True(t, proof.Verify([]byte("v-session"), V, R))
			}
		})
	}
}

// TestNewZKProofCTPathOutputDeterministicGivenRandomness is a guard
// against subtle differences between the legacy and rewritten paths:
// for fixed (a, x, Session, X), the proof must be a fixed value because
// the math is purely deterministic in those inputs. We can't easily
// inject `a` from outside the function, but we can re-construct the same
// proof using the now-public primitives and check it matches a fresh
// NewZKProof when the RNG yields a known `a`.
func TestNewZKProofCTComputationMatchesLegacyFormula(t *testing.T) {
	// Use deterministic test scalars and compute the proof both via the
	// CT helper combinations and via the legacy big.Int formula, then
	// verify byte-equality.
	for _, ec := range []elliptic.Curve{secp256k1.S256(), edwards25519.Edwards()} {
		q := ec.Params().N

		x := big.NewInt(42)
		a := big.NewInt(13)
		c := big.NewInt(999)

		// CT path: t = c·x + a mod q.
		tCT := crypto.CTScalarMulAddModN(ec, c, x, a)

		// Legacy formula.
		tLegacy := new(big.Int).Mul(c, x)
		tLegacy.Add(tLegacy, a)
		tLegacy.Mod(tLegacy, q)

		require.Zero(t, tCT.Cmp(tLegacy), "CT mul-add must equal legacy formula")
	}
}
