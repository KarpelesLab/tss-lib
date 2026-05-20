// Copyright © 2026 KarpelesLab.

package common

import (
	"math/big"
	"testing"
)

func TestZeroizeBigIntOverwritesLimbs(t *testing.T) {
	// Build a big.Int large enough to span multiple machine words.
	original, ok := new(big.Int).SetString(
		"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", 16)
	if !ok {
		t.Fatal("SetString failed")
	}
	if len(original.Bits()) < 2 {
		t.Fatalf("expected multi-word value; got %d words", len(original.Bits()))
	}

	// Capture the backing array pointer before zeroize so we can confirm
	// the same allocation was overwritten in place.
	pre := original.Bits()
	preArray := pre[:cap(pre):cap(pre)]
	preLen := len(preArray)

	ZeroizeBigInt(original)

	if original.Sign() != 0 {
		t.Fatalf("post-zeroize Sign() = %d, want 0", original.Sign())
	}
	// Inspect the original backing array — limbs must be zero.
	for i := 0; i < preLen; i++ {
		if preArray[i] != 0 {
			t.Fatalf("backing limb[%d] = %x, want 0", i, preArray[i])
		}
	}
}

func TestZeroizeBigIntNilSafe(t *testing.T) {
	// Must not panic.
	ZeroizeBigInt(nil)
}

func TestZeroizeBigIntZeroValueSafe(t *testing.T) {
	b := big.NewInt(0)
	ZeroizeBigInt(b) // must not panic
	if b.Sign() != 0 {
		t.Fatalf("zero value should remain zero, got %v", b)
	}
}

func TestZeroizeBytesOverwrites(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	ZeroizeBytes(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("b[%d] = %d, want 0", i, v)
		}
	}
}

func TestZeroizeBytesNilSafe(t *testing.T) {
	ZeroizeBytes(nil) // must not panic
}

func TestZeroizeBytesEmptySafe(t *testing.T) {
	ZeroizeBytes([]byte{}) // must not panic
}
