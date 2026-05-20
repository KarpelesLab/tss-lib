// Copyright © 2026 KarpelesLab.
//
// This file is part of tss-lib. The full copyright notice, including terms
// governing use, modification, and redistribution, is contained in the file
// LICENSE at the root of the source code distribution tree.

package common

import (
	"math/big"
)

// ZeroizeBigInt overwrites the limbs backing b with zeros and resets b to
// the numeric value 0. Best-effort only: Go's GC may have already copied
// the limbs to another allocation that we cannot reach, and SetBits below
// re-allocates a length-zero slice rather than reusing the wiped one.
// Callers that care about deterministic erasure should pair this with
// process-isolation, swap-off, and core-dump suppression.
//
// Safe to call with a nil receiver; in that case the function is a no-op.
func ZeroizeBigInt(b *big.Int) {
	if b == nil {
		return
	}
	w := b.Bits()
	for i := range w {
		w[i] = 0
	}
	// SetInt64(0) resets the abs slice to length 0; the underlying array
	// (which we just zeroed) is then eligible for reuse by future
	// big.Int operations on the same value.
	b.SetInt64(0)
}

// ZeroizeBytes overwrites every byte in b with zero. Safe to call on a
// nil slice (no-op). Best-effort like ZeroizeBigInt — Go's escape analysis
// may have spilled copies elsewhere.
func ZeroizeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
