// Copyright © 2026 KarpelesLab.

package frosttss

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestKeyZeroizeClearsXi confirms that Key.Zeroize overwrites the secret
// Shamir share with zero and that the operation is best-effort: the
// numeric value reads 0 afterwards.
func TestKeyZeroizeClearsXi(t *testing.T) {
	k := &Key{
		Xi: new(big.Int).SetBytes([]byte{
			0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
			0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
			0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
			0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
		}),
	}
	require.NotZero(t, k.Xi.Sign())
	k.Zeroize()
	require.Equal(t, 0, k.Xi.Sign(), "Xi must read 0 after Zeroize")
}

// TestKeyZeroizeNilSafe: calling Zeroize on a nil key must not panic.
func TestKeyZeroizeNilSafe(t *testing.T) {
	var k *Key
	k.Zeroize()
}

// TestKeyZeroizeXiNilSafe: a key with nil Xi must zeroize without panic.
func TestKeyZeroizeXiNilSafe(t *testing.T) {
	k := &Key{}
	k.Zeroize() // must not panic
}

// TestKeyZeroizeAliasingSubset confirms that the documented aliasing of
// Xi across SubsetForParties is consistent with Zeroize semantics: zeroing
// either the parent or the subset clears both.
func TestKeyZeroizeAliasingSubset(t *testing.T) {
	parent := &Key{
		Xi: big.NewInt(12345),
	}
	// Subset by manual aliasing (we don't need a full SubsetForParties run
	// here; the documented contract is just Xi-shared-by-pointer).
	subset := &Key{Xi: parent.Xi}

	subset.Zeroize()
	require.Equal(t, 0, parent.Xi.Sign(), "zeroing subset must clear parent Xi")
}
