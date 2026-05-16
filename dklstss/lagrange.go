package dklstss

import (
	"fmt"
	"math/big"

	"github.com/KarpelesLab/tss-lib/v2/common"
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
