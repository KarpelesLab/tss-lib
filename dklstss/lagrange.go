package dklstss

import (
	"fmt"
	"math/big"

	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// lagrangeCoefficient returns the Lagrange interpolation coefficient
// λ_i for evaluating f at x=0 given the points (ids[i], f(ids[i])) for
// i ∈ index set S. All arithmetic is mod q.
//
//	λ_i = Π_{j ∈ S, j ≠ i} (−ids[j]) · (ids[i] − ids[j])^{−1} mod q
//
// targetIdx is the index within ids whose coefficient we want.
func lagrangeCoefficient(q *big.Int, ids []*big.Int, targetIdx int) (*big.Int, error) {
	if targetIdx < 0 || targetIdx >= len(ids) {
		return nil, fmt.Errorf("dklstss: lagrangeCoefficient targetIdx %d out of range", targetIdx)
	}
	idI := new(big.Int).Mod(ids[targetIdx], q)
	num := big.NewInt(1)
	den := big.NewInt(1)
	for j, idJ := range ids {
		if j == targetIdx {
			continue
		}
		jMod := new(big.Int).Mod(idJ, q)
		// numerator factor: (0 - id_j) mod q = (-id_j) mod q
		numFactor := new(big.Int).Neg(jMod)
		numFactor.Mod(numFactor, q)
		num.Mul(num, numFactor)
		num.Mod(num, q)

		// denominator factor: (id_i - id_j) mod q
		diff := new(big.Int).Sub(idI, jMod)
		diff.Mod(diff, q)
		if diff.Sign() == 0 {
			return nil, fmt.Errorf("dklstss: lagrangeCoefficient duplicate ids at %d and %d", targetIdx, j)
		}
		den.Mul(den, diff)
		den.Mod(den, q)
	}
	denInv := common.ModInt(q).ModInverse(den)
	if denInv == nil {
		return nil, fmt.Errorf("dklstss: lagrangeCoefficient denominator has no inverse")
	}
	lambda := new(big.Int).Mul(num, denInv)
	lambda.Mod(lambda, q)
	return lambda, nil
}

// validateSortedSubset asserts that subset is strictly ascending by
// PartyID.KeyInt(). The `tss.SortedPartyIDs` type is just an alias for
// `[]*PartyID`, so a caller passing in unsorted data is structurally
// indistinguishable from a sorted one at the type level. Signing
// conventions (HD tweak absorbed at myPos==0; Lagrange coefficients
// computed in subset order) depend on every signer agreeing on the
// canonical order — a single signer with a permuted subset would
// absorb the tweak in a different slot or use mismatched Lagrange
// weights, producing a non-verifying joint signature with no clear
// error site to debug.
func validateSortedSubset(subset tss.SortedPartyIDs) error {
	for i := 1; i < len(subset); i++ {
		if subset[i-1].KeyInt().Cmp(subset[i].KeyInt()) >= 0 {
			return fmt.Errorf("dklstss: subset not strictly ascending at index %d (got %s before %s)",
				i, subset[i-1].KeyInt(), subset[i].KeyInt())
		}
	}
	return nil
}

// hashToScalar converts an arbitrary-length message digest into the
// scalar e used in ECDSA signing, following the standard SEC 1 §4.1.3
// rule: take the leftmost q.BitLen() bits of the hash, then reduce mod q.
//
// The legacy form `new(big.Int).SetBytes(hash).Mod(q)` is equivalent ONLY
// when the hash is at most q.BitLen() bits long. For a 32-byte SHA-256
// digest on secp256k1 (q.BitLen() == 256), both formulations coincide; for
// any longer digest (SHA-384 / SHA-512 / domain-separated transcripts)
// they diverge and `SetBytes mod q` silently produces a signature that
// does NOT verify under crypto/ecdsa.Verify (which truncates correctly).
//
// This implementation:
//   1. If len(hash)*8 <= q.BitLen(): big-endian SetBytes is canonical.
//   2. Otherwise: right-shift so only the top q.BitLen() bits remain.
//   3. Reduce mod q.
//
// The function is constant-time on the value of `hash` (the only branch
// is on length, which is public protocol metadata).
func hashToScalar(q *big.Int, hash []byte) *big.Int {
	z := new(big.Int).SetBytes(hash)
	qBits := q.BitLen()
	hBits := len(hash) * 8
	if hBits > qBits {
		z.Rsh(z, uint(hBits-qBits))
	}
	z.Mod(z, q)
	return z
}
