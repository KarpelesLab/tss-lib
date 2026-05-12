package frostristretto255tss

import (
	"fmt"
	"math/big"

	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/crypto/group"
)

// PrepareForSigning computes wi = xi * product(kj/(kj-ki)) for j != i, used
// by resharing's old-committee side to derive its contribution to the new
// committee. Identical in structure to frosttss.PrepareForSigning but works
// over an arbitrary group order.
func PrepareForSigning(g group.Group, i, pax int, xi *big.Int, ks []*big.Int) *big.Int {
	modQ := common.ModInt(g.Order())
	if len(ks) != pax {
		panic(fmt.Errorf("PrepareForSigning: len(ks) != pax (%d != %d)", len(ks), pax))
	}
	if len(ks) <= i {
		panic(fmt.Errorf("PrepareForSigning: len(ks) <= i (%d <= %d)", len(ks), i))
	}

	wi := new(big.Int).Set(xi)
	for j := 0; j < pax; j++ {
		if j == i {
			continue
		}
		ksj := ks[j]
		ksi := ks[i]
		if ksj.Cmp(ksi) == 0 {
			panic(fmt.Errorf("identical party indexes"))
		}
		coef := modQ.Mul(ks[j], modQ.ModInverse(new(big.Int).Sub(ksj, ksi)))
		wi = modQ.Mul(wi, coef)
	}
	return wi
}
