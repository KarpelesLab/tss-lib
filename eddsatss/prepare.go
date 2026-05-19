package eddsatss

import (
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/crypto"
)

// PrepareForSigning computes the Lagrange-scaled share
//
//	wi = xi · Π_{j ≠ i} kj / (kj - ki) (mod q)
//
// used during the EdDSA signing preparation phase.
//
// CT discipline: `xi` is the secret share and `wi` carries that secret
// throughout the loop. Each iteration accumulates `wi = wi · coef mod q`
// where `coef` is a Lagrange coefficient derived from public party IDs.
// Using math/big.Int.Mul on the secret-bearing `wi` leaks bits via
// timing; route the running product through crypto.CTScalarMulAddModN
// (with c=0) so each multiplication stays inside the curve-aware CT
// primitive. The coefficient itself is computed via non-CT modQ.Mul /
// ModInverse on PUBLIC inputs — that's fine.
func PrepareForSigning(ec elliptic.Curve, i, pax int, xi *big.Int, ks []*big.Int) *big.Int {
	modQ := common.ModInt(ec.Params().N)
	if len(ks) != pax {
		panic(fmt.Errorf("PrepareForSigning: len(ks) != pax (%d != %d)", len(ks), pax))
	}
	if len(ks) <= i {
		panic(fmt.Errorf("PrepareForSigning: len(ks) <= i (%d <= %d)", len(ks), i))
	}

	zero := new(big.Int)
	wi := new(big.Int).Set(xi)
	for j := 0; j < pax; j++ {
		if j == i {
			continue
		}
		ksj := ks[j]
		ksi := ks[i]
		if ksj.Cmp(ksi) == 0 {
			panic(fmt.Errorf("index of two parties are equal"))
		}
		// coef is built from public party indexes — non-CT here is OK.
		coef := modQ.Mul(ks[j], modQ.ModInverse(new(big.Int).Sub(ksj, ksi)))
		// wi · coef + 0 via the CT primitive (witness `wi` carries `xi`).
		wi = crypto.CTScalarMulAddModN(ec, wi, coef, zero)
	}

	return wi
}
