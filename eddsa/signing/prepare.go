// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/crypto"
)

// PrepareForSigning(), Fig. 7
func PrepareForSigning(ec elliptic.Curve, i, pax int, xi *big.Int, ks []*big.Int) (wi *big.Int) {
	modQ := common.ModInt(ec.Params().N)
	if len(ks) != pax {
		panic(fmt.Errorf("PrepareForSigning: len(ks) != pax (%d != %d)", len(ks), pax))
	}
	if len(ks) <= i {
		panic(fmt.Errorf("PrepareForSigning: len(ks) <= i (%d <= %d)", len(ks), i))
	}

	// 1-4.
	wi = xi
	for j := 0; j < pax; j++ {
		if j == i {
			continue
		}
		ksj := ks[j]
		ksi := ks[i]
		if ksj.Cmp(ksi) == 0 {
			panic(fmt.Errorf("index of two parties are equal"))
		}
		// big.Int Div is calculated as: a/b = a * modInv(b,q).
		// coef is public (party indexes); the running product `wi`
		// carries the secret share xi, so the wi·coef step must be CT.
		coef := modQ.Mul(ks[j], modQ.ModInverse(new(big.Int).Sub(ksj, ksi)))
		wi = crypto.CTScalarMulAddModN(ec, wi, coef, new(big.Int))
	}

	return
}
