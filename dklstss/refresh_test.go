package dklstss

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRefreshPreservesPublicKey verifies that proactive refresh keeps the
// joint public key unchanged.
func TestRefreshPreservesPublicKey(t *testing.T) {
	keys, err := Keygen(3, 1, genPartyIDs(3), rand.Reader)
	require.NoError(t, err)
	oldPub := keys[0].ECDSAPub

	refreshed, err := Refresh(keys, rand.Reader)
	require.NoError(t, err)
	require.Len(t, refreshed, 3)
	for i, k := range refreshed {
		assert.Truef(t, k.ECDSAPub.Equals(oldPub), "party %d public key changed after refresh", i)
	}
}

// TestRefreshRotatesShares verifies that the per-party shares actually
// change (with overwhelming probability).
func TestRefreshRotatesShares(t *testing.T) {
	keys, err := Keygen(3, 1, genPartyIDs(3), rand.Reader)
	require.NoError(t, err)
	oldShares := make([]string, len(keys))
	for i, k := range keys {
		oldShares[i] = k.Xi.String()
	}

	refreshed, err := Refresh(keys, rand.Reader)
	require.NoError(t, err)
	for i, k := range refreshed {
		assert.NotEqualf(t, oldShares[i], k.Xi.String(), "party %d share did not rotate", i)
	}
}

// TestRefreshOTStateRotates verifies that the OT extension state changes
// across refresh (necessary for forward security).
func TestRefreshOTStateRotates(t *testing.T) {
	keys, err := Keygen(2, 1, genPartyIDs(2), rand.Reader)
	require.NoError(t, err)
	oldDelta := keys[0].OT[1].AsBob.Delta()

	refreshed, err := Refresh(keys, rand.Reader)
	require.NoError(t, err)
	newDelta := refreshed[0].OT[1].AsBob.Delta()
	assert.NotEqual(t, oldDelta, newDelta, "OT extension Delta should rotate on refresh")
}

// TestRefreshThenSign is the end-to-end check: refresh then sign with the
// new shares, verify under the unchanged public key.
func TestRefreshThenSign(t *testing.T) {
	keys, err := Keygen(3, 1, genPartyIDs(3), rand.Reader)
	require.NoError(t, err)

	refreshed, err := Refresh(keys, rand.Reader)
	require.NoError(t, err)

	msg := sha256.Sum256([]byte("post-refresh signing"))
	sig, err := Sign(refreshed, []int{0, 1}, msg[:], rand.Reader)
	require.NoError(t, err)

	pub := &ecdsa.PublicKey{
		Curve: keys[0].ECDSAPub.Curve(),
		X:     keys[0].ECDSAPub.X(),
		Y:     keys[0].ECDSAPub.Y(),
	}
	assert.True(t, ecdsa.Verify(pub, msg[:], sig.R, sig.S), "signature with refreshed shares should verify under original public key")
}

// TestRefreshMultipleTimes verifies refresh can be chained without state
// drift.
func TestRefreshMultipleTimes(t *testing.T) {
	keys, err := Keygen(3, 1, genPartyIDs(3), rand.Reader)
	require.NoError(t, err)
	pubX := keys[0].ECDSAPub.X().String()

	cur := keys
	for round := 0; round < 3; round++ {
		next, err := Refresh(cur, rand.Reader)
		require.NoErrorf(t, err, "round %d", round)
		require.Equal(t, pubX, next[0].ECDSAPub.X().String(), "round %d: public key should not change")

		// Each round, sign and verify.
		msg := sha256.Sum256([]byte{byte(round)})
		sig, err := Sign(next, []int{0, 2}, msg[:], rand.Reader)
		require.NoError(t, err)
		pub := &ecdsa.PublicKey{
			Curve: next[0].ECDSAPub.Curve(),
			X:     next[0].ECDSAPub.X(),
			Y:     next[0].ECDSAPub.Y(),
		}
		require.True(t, ecdsa.Verify(pub, msg[:], sig.R, sig.S), "round %d signing failed", round)

		cur = next
	}
}

// TestRefreshErrorPaths checks malformed-input rejections.
func TestRefreshErrorPaths(t *testing.T) {
	_, err := Refresh(nil, rand.Reader)
	require.Error(t, err)

	keys, err := Keygen(3, 1, genPartyIDs(3), rand.Reader)
	require.NoError(t, err)

	// Truncated keys slice (n inconsistent).
	_, err = Refresh(keys[:2], rand.Reader)
	require.Error(t, err)
}
