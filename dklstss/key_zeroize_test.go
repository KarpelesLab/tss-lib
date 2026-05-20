// Copyright © 2026 KarpelesLab.

package dklstss

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/crypto/ot/baseot"
	"github.com/KarpelesLab/tss-lib/v2/crypto/ot/otext"
)

// TestKeyZeroizeClearsXiAndChainCode validates that Zeroize overwrites
// both the secret Shamir share and the chain code.
func TestKeyZeroizeClearsXiAndChainCode(t *testing.T) {
	cc := make([]byte, 32)
	_, err := rand.Read(cc)
	require.NoError(t, err)
	k := &Key{
		Xi:        new(big.Int).SetBytes([]byte{0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89}),
		ChainCode: cc,
	}
	preCCSum := 0
	for _, b := range cc {
		preCCSum += int(b)
	}
	require.Greater(t, preCCSum, 0, "chain code must be non-zero before Zeroize")

	k.Zeroize()

	require.Equal(t, 0, k.Xi.Sign())
	for i, b := range k.ChainCode {
		require.Equal(t, byte(0), b, "ChainCode[%d] = %d, want 0", i, b)
	}
}

// TestKeyZeroizeWalksOTState confirms Zeroize walks every PairOTState and
// zeros its OT-extension secrets.
func TestKeyZeroizeWalksOTState(t *testing.T) {
	makePair := func() *PairOTState {
		delta := make([]byte, otext.DeltaBytes)
		_, err := rand.Read(delta)
		require.NoError(t, err)
		keys := make([][baseot.KeyLen]byte, otext.Kappa)
		for j := range keys {
			_, err := rand.Read(keys[j][:])
			require.NoError(t, err)
		}
		s, err := otext.NewExtSenderFromBase(delta, keys)
		require.NoError(t, err)

		k0 := make([][baseot.KeyLen]byte, otext.Kappa)
		k1 := make([][baseot.KeyLen]byte, otext.Kappa)
		for j := range k0 {
			_, err := rand.Read(k0[j][:])
			require.NoError(t, err)
			_, err = rand.Read(k1[j][:])
			require.NoError(t, err)
		}
		r, err := otext.NewExtReceiverFromBase(k0, k1)
		require.NoError(t, err)

		return &PairOTState{AsAlice: r, AsBob: s}
	}

	k := &Key{
		Idx:       1,
		Xi:        big.NewInt(42),
		ChainCode: make([]byte, 32),
		OT:        []*PairOTState{makePair(), nil, makePair()},
	}

	// Pre-condition: Δ has some non-zero bytes on each non-nil pair.
	for _, pair := range k.OT {
		if pair == nil {
			continue
		}
		delta := pair.AsBob.Delta()
		anyNonZero := false
		for _, b := range delta {
			if b != 0 {
				anyNonZero = true
				break
			}
		}
		require.True(t, anyNonZero, "OT pair Δ must be non-zero before Zeroize")
	}

	k.Zeroize()

	for i, pair := range k.OT {
		if pair == nil {
			continue
		}
		delta := pair.AsBob.Delta()
		for j, b := range delta {
			require.Equal(t, byte(0), b, "OT[%d].AsBob.delta[%d] not zero", i, j)
		}
	}
}

// TestKeyZeroizeNilSafe must not panic on nil receiver.
func TestKeyZeroizeNilSafe(t *testing.T) {
	var k *Key
	k.Zeroize()
}

// TestKeyZeroizeNilFieldsSafe ensures Zeroize tolerates nil sub-fields.
func TestKeyZeroizeNilFieldsSafe(t *testing.T) {
	k := &Key{} // all fields zero/nil
	k.Zeroize() // must not panic
}
