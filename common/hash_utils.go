// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common

import (
	"math/big"
)

// RejectionSample maps a hash value into [0, q) via a single modular
// reduction: e' = eHash mod q. Despite the name, it does NOT perform
// rejection sampling — there is no retry loop and the result is simply the
// reduced value. The name is retained for backwards compatibility with its
// callers (crypto/modproof, facproof, mta, schnorr).
//
// Because this is a bare reduction, the output is only (near-)uniform when q
// is within a small factor of the digest width. The input eHash is a 256-bit
// SHA-512/256 output, so for the ~256-bit curve / RSA-modulus orders used by
// all current callers the modular bias is at most ~2^{-128}, which is
// negligible. Do NOT use this for a q whose bit length is materially smaller
// than the digest (~256 bits): the reduction bias would then become
// security-relevant and a true rejection-sampling routine would be required.
func RejectionSample(q *big.Int, eHash *big.Int) *big.Int { // e' = eHash
	e := new(big.Int).Mod(eHash, q)
	return e
}
