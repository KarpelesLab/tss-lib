package dklstss

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFullPipeline exercises every public entry-point in sequence:
// keygen → presign+sign → HD-derive+sign → refresh → sign again.
// Catches integration regressions across feature boundaries.
func TestFullPipeline(t *testing.T) {
	const n, threshold = 4, 2
	ids := genPartyIDs(n)

	// 1. Keygen.
	keys, err := Keygen(n, threshold, ids, rand.Reader)
	require.NoError(t, err)
	require.Len(t, keys, n)

	pub := &ecdsa.PublicKey{
		Curve: keys[0].ECDSAPub.Curve(),
		X:     keys[0].ECDSAPub.X(),
		Y:     keys[0].ECDSAPub.Y(),
	}

	// 2. Combined signing across two different T+1 subsets.
	digest := sha256.Sum256([]byte("integration: combined sign"))
	for _, subset := range [][]int{{0, 1, 2}, {1, 2, 3}, {0, 2, 3}} {
		sig, err := Sign(keys, subset, digest[:], rand.Reader)
		require.NoErrorf(t, err, "Sign subset %v", subset)
		require.Truef(t, ecdsa.Verify(pub, digest[:], sig.R, sig.S), "verify subset %v", subset)
	}

	// 3. Presign + SignWithPresign.
	presign, err := Presign(keys, []int{0, 1, 3}, rand.Reader)
	require.NoError(t, err)
	require.False(t, presign.Consumed())
	digest2 := sha256.Sum256([]byte("integration: presign+sign"))
	sig2, err := SignWithPresign(presign, digest2[:], nil)
	require.NoError(t, err)
	require.True(t, ecdsa.Verify(pub, digest2[:], sig2.R, sig2.S))
	require.True(t, presign.Consumed())

	// 4. HD derivation + sign.
	path := []uint32{84, 0, 0}
	tweak, childPub, err := DeriveChild(keys[0], path)
	require.NoError(t, err)
	require.NotZero(t, tweak.Sign())
	digest3 := sha256.Sum256([]byte("integration: HD"))
	sig3, child2, err := DeriveAndSign(keys, []int{0, 2, 3}, path, digest3[:], rand.Reader)
	require.NoError(t, err)
	require.True(t, child2.Equals(childPub))
	childECDSA := &ecdsa.PublicKey{
		Curve: childPub.Curve(),
		X:     childPub.X(),
		Y:     childPub.Y(),
	}
	require.True(t, ecdsa.Verify(childECDSA, digest3[:], sig3.R, sig3.S))

	// 5. Refresh (preserves pub) and sign with refreshed shares.
	refreshed, err := Refresh(keys, rand.Reader)
	require.NoError(t, err)
	require.True(t, refreshed[0].ECDSAPub.Equals(keys[0].ECDSAPub))
	digest4 := sha256.Sum256([]byte("integration: post-refresh"))
	sig4, err := Sign(refreshed, []int{1, 2, 3}, digest4[:], rand.Reader)
	require.NoError(t, err)
	require.True(t, ecdsa.Verify(pub, digest4[:], sig4.R, sig4.S))

	// 6. HD with presign on refreshed shares.
	presign2, err := Presign(refreshed, []int{0, 1, 2}, rand.Reader)
	require.NoError(t, err)
	tweak2, childPub2, err := DeriveChild(refreshed[0], path)
	require.NoError(t, err)
	require.Equal(t, tweak.String(), tweak2.String(), "tweak must match across refresh (chain code unchanged)")
	require.True(t, childPub2.Equals(childPub))
	digest5 := sha256.Sum256([]byte("integration: post-refresh HD via presign"))
	sig5, err := SignWithPresign(presign2, digest5[:], tweak2)
	require.NoError(t, err)
	require.True(t, ecdsa.Verify(childECDSA, digest5[:], sig5.R, sig5.S))
}

// TestKeygenPanicResistance verifies that pathological inputs to Keygen
// do not panic but return errors.
func TestKeygenPanicResistance(t *testing.T) {
	cases := []struct {
		n, t int
	}{
		{0, 0},
		{1, 0},
		{2, 0}, // threshold = 0 should be rejected (signing needs >= 2 parties for an actual share)
		{2, 2}, // threshold = N requires N parties, only valid for some interpretations
		{-1, 1},
		{3, -1},
	}
	for _, tc := range cases {
		ids := genPartyIDs(maxInt(tc.n, 1))
		if tc.n <= 0 {
			ids = nil
		}
		_, err := Keygen(tc.n, tc.t, ids, rand.Reader)
		assert.Errorf(t, err, "expected error for N=%d T=%d", tc.n, tc.t)
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// TestKeyValidateBasic is a quick smoke test of the Key validator.
func TestKeyValidateBasic(t *testing.T) {
	keys, err := Keygen(3, 1, genPartyIDs(3), rand.Reader)
	require.NoError(t, err)
	for i, k := range keys {
		require.NoErrorf(t, k.ValidateBasic(), "key %d failed validation", i)
	}

	// Corrupt one and ensure detection.
	bad := *keys[0]
	bad.Xi = nil
	require.Error(t, bad.ValidateBasic())
}
