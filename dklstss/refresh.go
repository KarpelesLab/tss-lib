package dklstss

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"

	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// Refresh runs proactive share refresh on the given Keys, atomically:
//
//   - Each party samples a degree-T polynomial with constant term 0 and
//     Feldman-VSS-shares it to all parties. Σ of constant terms = 0, so
//     the joint secret x is unchanged; only the per-party shares rotate.
//   - All per-pair OT-extension setup is re-established. Compromised
//     long-term OT keys from before the refresh become useless because
//     no future signing will use them.
//   - The presign cache (currently not implemented but reserved) is
//     cleared.
//
// If any sub-step fails, no Keys are mutated and the original slice is
// safe to keep using.
//
// This is the synchronous in-process API. Like Keygen, it runs all
// parties as a single function for tests; a broker-driven async wrapper
// is task #7.
func Refresh(keys []*Key, rng io.Reader) ([]*Key, error) {
	if rng == nil {
		rng = rand.Reader
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("dklstss: Refresh requires at least one key")
	}
	n := keys[0].N
	t := keys[0].T
	pub := keys[0].ECDSAPub
	chainCode := keys[0].ChainCode
	partyIDs := keys[0].PartyIDs
	ec := keys[0].Curve
	q := ec.Params().N

	if len(keys) != n {
		return nil, fmt.Errorf("dklstss: Refresh got %d keys, expected %d", len(keys), n)
	}
	for i, k := range keys {
		if k.N != n || k.T != t || !k.ECDSAPub.Equals(pub) {
			return nil, fmt.Errorf("dklstss: Refresh key[%d] is inconsistent with keys[0]", i)
		}
		if k.Idx != i {
			return nil, fmt.Errorf("dklstss: Refresh key[%d].Idx = %d, expected %d", i, k.Idx, i)
		}
	}

	ids := make([]*big.Int, n)
	for i, pid := range partyIDs {
		ids[i] = pid.KeyInt()
	}

	// Phase 1: each party samples a degree-T polynomial with constant
	// term 0 — f_i(x) = a_{i,1}·x + a_{i,2}·x² + … + a_{i,T}·x^T — and
	// shares its evaluations to peers. Commitments V_{i,k} = a_{i,k} · G
	// for k = 1..T let peers verify their received shares.
	//
	// Note: we cannot reuse crypto/vss because vss.Create scalar-mults
	// the secret directly, which panics on secret = 0 (since 0·G is the
	// stdlib identity (0,0) which is rejected as off-curve). Inline
	// rolling of the zero-constant polynomial avoids that.
	commitments := make([][]*crypto.ECPoint, n) // [n][T] (no V_{i,0})
	shares := make([][]*big.Int, n)             // shares[i][j] = f_i(id_j)
	for i := 0; i < n; i++ {
		coeffs := make([]*big.Int, t) // a_{i,1}..a_{i,T}
		for k := 0; k < t; k++ {
			coeffs[k] = common.GetRandomPositiveInt(rng, q)
		}
		Vs := make([]*crypto.ECPoint, t)
		for k := 0; k < t; k++ {
			Vs[k] = crypto.ScalarBaseMult(ec, coeffs[k])
		}
		commitments[i] = Vs

		row := make([]*big.Int, n)
		for j := 0; j < n; j++ {
			row[j] = evalZeroConstPoly(coeffs, ids[j], q)
		}
		shares[i] = row
	}

	// Phase 2: each party verifies received shares and computes its
	// refresh delta. Verification: s_{i→j} · G == Σ_{k=1}^{T} id_j^k · V_{i,k}.
	delta := make([]*big.Int, n)
	for j := 0; j < n; j++ {
		sum := new(big.Int)
		for i := 0; i < n; i++ {
			if !verifyZeroConstShare(commitments[i], ids[j], shares[i][j]) {
				return nil, fmt.Errorf("dklstss: Refresh VSS verify party %d→%d failed", i, j)
			}
			sum.Add(sum, shares[i][j])
			sum.Mod(sum, q)
		}
		delta[j] = sum
	}

	// Phase 3: compute new shares x_j' = x_j + delta_j (mod q) and new
	// public commitments BigXj' = BigXj + delta_j · G.
	newXj := make([]*big.Int, n)
	newBigXj := make([]*crypto.ECPoint, n)
	for j := 0; j < n; j++ {
		newXj[j] = new(big.Int).Add(keys[j].Xi, delta[j])
		newXj[j].Mod(newXj[j], q)
		deltaG := crypto.ScalarBaseMult(ec, delta[j])
		Xj, err := keys[0].BigXj[j].Add(deltaG)
		if err != nil {
			return nil, fmt.Errorf("dklstss: Refresh BigXj[%d] aggregate: %w", j, err)
		}
		newBigXj[j] = Xj
		// Sanity: newXj[j] · G == newBigXj[j].
		expect := crypto.ScalarBaseMult(ec, newXj[j])
		if !expect.Equals(Xj) {
			return nil, fmt.Errorf("dklstss: Refresh consistency check failed at party %d", j)
		}
	}

	// Phase 4: re-establish pairwise OT setup with fresh randomness.
	// The session id binds to (pub, refresh-nonce) for uniqueness across
	// refresh events.
	var nonce [16]byte
	if _, err := io.ReadFull(rng, nonce[:]); err != nil {
		return nil, fmt.Errorf("dklstss: Refresh nonce: %w", err)
	}
	sidPrefix := append([]byte("DKLS23-refresh-otsetup-v1-"), pub.X().Bytes()...)
	sidPrefix = append(sidPrefix, '|')
	sidPrefix = append(sidPrefix, nonce[:]...)
	ot, err := setupPairs(n, sidPrefix, rng)
	if err != nil {
		return nil, fmt.Errorf("dklstss: Refresh OT re-setup: %w", err)
	}

	// Phase 5: assemble refreshed Keys.
	out := make([]*Key, n)
	for i := 0; i < n; i++ {
		out[i] = &Key{
			Curve:     ec,
			N:         n,
			T:         t,
			Idx:       i,
			PartyIDs:  partyIDs,
			Xi:        newXj[i],
			BigXj:     newBigXj,
			ECDSAPub:  pub,
			OT:        ot[i],
			ChainCode: append([]byte(nil), chainCode...),
		}
		if err := out[i].ValidateBasic(); err != nil {
			return nil, fmt.Errorf("dklstss: Refresh produced invalid key for party %d: %w", i, err)
		}
	}
	return out, nil
}

// evalZeroConstPoly evaluates f(id) where f has zero constant term:
// f(x) = coeffs[0]·x + coeffs[1]·x² + ... + coeffs[t-1]·x^t.
func evalZeroConstPoly(coeffs []*big.Int, id *big.Int, q *big.Int) *big.Int {
	// Horner from highest degree:
	// result = ((... + coeffs[t-1]) · id + coeffs[t-2]) · id + ... + coeffs[0]) · id
	result := new(big.Int)
	for k := len(coeffs) - 1; k >= 0; k-- {
		result.Mul(result, id)
		result.Add(result, coeffs[k])
		result.Mod(result, q)
	}
	result.Mul(result, id)
	result.Mod(result, q)
	return result
}

// verifyZeroConstShare checks share · G == Σ_{k=1}^{T} id^k · V_k where
// Vs = [V_1, V_2, ..., V_T] are the commitments to a zero-constant-term
// polynomial's non-constant coefficients.
func verifyZeroConstShare(Vs []*crypto.ECPoint, id, share *big.Int) bool {
	if len(Vs) == 0 {
		return false
	}
	curve := Vs[0].Curve()
	q := curve.Params().N

	idPow := new(big.Int).Mod(id, q)
	var rhs *crypto.ECPoint
	for _, V := range Vs {
		term := V.ScalarMult(idPow)
		if rhs == nil {
			rhs = term
		} else {
			var err error
			rhs, err = rhs.Add(term)
			if err != nil {
				return false
			}
		}
		idPow = new(big.Int).Mul(idPow, id)
		idPow.Mod(idPow, q)
	}
	if rhs == nil {
		return false
	}
	lhs := crypto.ScalarBaseMult(curve, share)
	return lhs.Equals(rhs)
}

// Keep tss.S256 referenced so the import resolves even if no symbol from
// the package is used directly in this file.
var _ = tss.S256
