package frosttss

import (
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/KarpelesLab/tss-lib/v2/common"
)

// PrepareForSigning computes wi = xi * product(kj/(kj-ki)) for j != i, the
// Lagrange coefficient applied to the local share. Used by resharing's
// old-committee side to derive its contribution to the new committee.
//
// Note: signing itself uses crypto/frost.LagrangeCoefficient directly so this
// helper is resharing-only. It mirrors eddsatss.PrepareForSigning byte-for-byte
// to keep the resharing protocol shape identical.
func PrepareForSigning(ec elliptic.Curve, i, pax int, xi *big.Int, ks []*big.Int) *big.Int {
	modQ := common.ModInt(ec.Params().N)
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
			panic(fmt.Errorf("index of two parties are equal"))
		}
		coef := modQ.Mul(ks[j], modQ.ModInverse(new(big.Int).Sub(ksj, ksi)))
		wi = modQ.Mul(wi, coef)
	}

	return wi
}
