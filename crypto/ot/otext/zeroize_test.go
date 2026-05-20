// Copyright © 2026 KarpelesLab.

package otext

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/crypto/ot/baseot"
)

// TestExtSenderZeroizeClearsDeltaAndSeeds confirms that Zeroize overwrites
// the κ-bit secret correlation Δ and all base-OT seeds with zeros.
func TestExtSenderZeroizeClearsDeltaAndSeeds(t *testing.T) {
	delta := make([]byte, DeltaBytes)
	_, err := rand.Read(delta)
	require.NoError(t, err)
	// Verify entropy: at least one non-zero byte (overwhelming probability).
	allZero := true
	for _, b := range delta {
		if b != 0 {
			allZero = false
			break
		}
	}
	require.False(t, allZero, "delta seed must not be all-zero before Zeroize")

	keys := make([][baseot.KeyLen]byte, Kappa)
	for j := range keys {
		_, err := rand.Read(keys[j][:])
		require.NoError(t, err)
	}

	s, err := NewExtSenderFromBase(delta, keys)
	require.NoError(t, err)

	// Pre-zeroize delta capture (post-NewExtSenderFromBase, since it copies).
	preDelta := s.Delta()
	allZero = true
	for _, b := range preDelta {
		if b != 0 {
			allZero = false
			break
		}
	}
	require.False(t, allZero, "ExtSender.delta should mirror caller delta before Zeroize")

	s.Zeroize()

	postDelta := s.Delta()
	for i, b := range postDelta {
		require.Equal(t, byte(0), b, "delta[%d] not zero", i)
	}
	for j := range s.seeds {
		for i, b := range s.seeds[j] {
			require.Equal(t, byte(0), b, "seeds[%d][%d] not zero", j, i)
		}
	}
}

// TestExtReceiverZeroizeClearsSeeds confirms that Zeroize overwrites both
// seed arrays with zeros.
func TestExtReceiverZeroizeClearsSeeds(t *testing.T) {
	k0 := make([][baseot.KeyLen]byte, Kappa)
	k1 := make([][baseot.KeyLen]byte, Kappa)
	for j := range k0 {
		_, err := rand.Read(k0[j][:])
		require.NoError(t, err)
		_, err = rand.Read(k1[j][:])
		require.NoError(t, err)
	}

	r, err := NewExtReceiverFromBase(k0, k1)
	require.NoError(t, err)

	r.Zeroize()

	for j := range r.seeds0 {
		for i, b := range r.seeds0[j] {
			require.Equal(t, byte(0), b, "seeds0[%d][%d] not zero", j, i)
		}
		for i, b := range r.seeds1[j] {
			require.Equal(t, byte(0), b, "seeds1[%d][%d] not zero", j, i)
		}
	}
}

// TestExtSenderZeroizeNilSafe must not panic on nil receiver.
func TestExtSenderZeroizeNilSafe(t *testing.T) {
	var s *ExtSender
	s.Zeroize()
}

// TestExtReceiverZeroizeNilSafe must not panic on nil receiver.
func TestExtReceiverZeroizeNilSafe(t *testing.T) {
	var r *ExtReceiver
	r.Zeroize()
}
