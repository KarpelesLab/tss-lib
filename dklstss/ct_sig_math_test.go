package dklstss

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// TestShatiCTMatchesLegacyFormula verifies that the rewritten
// ŝ_i = ρ_i·H + r·σ_i computation via crypto.CTScalarMulAddModN yields
// the same scalar as the previous math/big.Int.Mul + Add form. This is
// the safety property of the CT rewrite: identical output, only the
// side-channel surface changes.
func TestShatiCTMatchesLegacyFormula(t *testing.T) {
	ec := tss.S256()
	q := ec.Params().N
	zero := new(big.Int)

	for i := 0; i < 32; i++ {
		rho, err := rand.Int(rand.Reader, q)
		require.NoError(t, err)
		sigma, err := rand.Int(rand.Reader, q)
		require.NoError(t, err)
		h, err := rand.Int(rand.Reader, q)
		require.NoError(t, err)
		r, err := rand.Int(rand.Reader, q)
		require.NoError(t, err)

		// CT path.
		t1CT := crypto.CTScalarMulAddModN(ec, rho, h, zero)
		shatiCT := crypto.CTScalarMulAddModN(ec, r, sigma, t1CT)

		// Legacy path.
		t1Legacy := new(big.Int).Mul(rho, h)
		t1Legacy.Mod(t1Legacy, q)
		t2Legacy := new(big.Int).Mul(r, sigma)
		t2Legacy.Mod(t2Legacy, q)
		shatiLegacy := new(big.Int).Add(t1Legacy, t2Legacy)
		shatiLegacy.Mod(shatiLegacy, q)

		require.Zero(t, shatiCT.Cmp(shatiLegacy),
			"CT ŝ_i should match legacy formula")
	}
}

// TestDiagonalProductCTMatchesLegacyFormula verifies the same for the
// per-party diagonal product k_i · ρ_i (and the analogous sx_i · ρ_i).
func TestDiagonalProductCTMatchesLegacyFormula(t *testing.T) {
	ec := tss.S256()
	q := ec.Params().N
	zero := new(big.Int)

	for i := 0; i < 32; i++ {
		a, err := rand.Int(rand.Reader, q)
		require.NoError(t, err)
		b, err := rand.Int(rand.Reader, q)
		require.NoError(t, err)

		ct := crypto.CTScalarMulAddModN(ec, a, b, zero)
		legacy := new(big.Int).Mul(a, b)
		legacy.Mod(legacy, q)

		require.Zero(t, ct.Cmp(legacy))
	}
}
