package dklstss

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/crypto/ckd"
)

// TestDeriveChildEmpty verifies that an empty path returns (tweak=0, child=parent).
func TestDeriveChildEmpty(t *testing.T) {
	keys, err := Keygen(2, 1, genPartyIDs(2), rand.Reader)
	require.NoError(t, err)

	tweak, child, err := DeriveChild(keys[0], nil)
	require.NoError(t, err)
	assert.Zero(t, tweak.Sign(), "tweak should be 0 for empty path")
	assert.True(t, child.Equals(keys[0].ECDSAPub), "child should equal parent for empty path")

	tweak, child, err = DeriveChild(keys[0], []uint32{})
	require.NoError(t, err)
	assert.Zero(t, tweak.Sign())
	assert.True(t, child.Equals(keys[0].ECDSAPub))
}

// TestDeriveChildHardenedRejected verifies that hardened indices are
// rejected.
func TestDeriveChildHardenedRejected(t *testing.T) {
	keys, err := Keygen(2, 1, genPartyIDs(2), rand.Reader)
	require.NoError(t, err)

	cases := [][]uint32{
		{ckd.HardenedKeyStart},
		{0, 1, ckd.HardenedKeyStart},
		{ckd.HardenedKeyStart + 5},
	}
	for _, path := range cases {
		_, _, err := DeriveChild(keys[0], path)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrHardenedNotSupported)
	}
}

// TestDeriveChildDeterministic verifies that all parties derive the same
// child key and tweak for the same path.
func TestDeriveChildDeterministic(t *testing.T) {
	keys, err := Keygen(4, 2, genPartyIDs(4), rand.Reader)
	require.NoError(t, err)
	path := []uint32{0, 1, 2, 0}

	var refTweak *big.Int
	var refPub = (*[2]*big.Int)(nil)

	for i, k := range keys {
		tweak, child, err := DeriveChild(k, path)
		require.NoError(t, err)
		if i == 0 {
			refTweak = tweak
			refPub = &[2]*big.Int{child.X(), child.Y()}
		} else {
			assert.Equalf(t, refTweak.String(), tweak.String(), "party %d tweak differs", i)
			assert.Equalf(t, refPub[0].String(), child.X().String(), "party %d child X differs", i)
			assert.Equalf(t, refPub[1].String(), child.Y().String(), "party %d child Y differs", i)
		}
	}
}

// TestDeriveAndSign is the main HD end-to-end test: derive a child, sign,
// verify against the child public key.
func TestDeriveAndSign(t *testing.T) {
	keys, err := Keygen(3, 1, genPartyIDs(3), rand.Reader)
	require.NoError(t, err)

	paths := [][]uint32{
		{0},
		{44},
		{44, 0, 0, 0, 7},
		{1, 2, 3},
	}
	msg := sha256.Sum256([]byte("HD signing test"))

	for _, path := range paths {
		t.Run("", func(t *testing.T) {
			sig, childPub, err := DeriveAndSign(keys, []int{0, 1}, path, msg[:], rand.Reader)
			require.NoError(t, err)
			require.NotNil(t, sig)
			require.NotNil(t, childPub)

			pub := &ecdsa.PublicKey{
				Curve: childPub.Curve(),
				X:     childPub.X(),
				Y:     childPub.Y(),
			}
			ok := ecdsa.Verify(pub, msg[:], sig.R, sig.S)
			assert.Truef(t, ok, "path %v: signature does not verify under child public key", path)

			// Negative: signature should NOT verify under parent.
			parent := &ecdsa.PublicKey{
				Curve: keys[0].ECDSAPub.Curve(),
				X:     keys[0].ECDSAPub.X(),
				Y:     keys[0].ECDSAPub.Y(),
			}
			parentOk := ecdsa.Verify(parent, msg[:], sig.R, sig.S)
			assert.Falsef(t, parentOk, "path %v: signature unexpectedly verifies under parent (HD scaling bug?)", path)
		})
	}
}

// TestDeriveAndSignAcrossSubsets verifies that different signing subsets
// produce signatures that all verify under the SAME child public key.
func TestDeriveAndSignAcrossSubsets(t *testing.T) {
	keys, err := Keygen(4, 2, genPartyIDs(4), rand.Reader)
	require.NoError(t, err)
	path := []uint32{10, 20, 30}
	msg := sha256.Sum256([]byte("HD subset consistency"))

	_, refChild, err := DeriveChild(keys[0], path)
	require.NoError(t, err)
	pub := &ecdsa.PublicKey{
		Curve: refChild.Curve(),
		X:     refChild.X(),
		Y:     refChild.Y(),
	}

	subsets := [][]int{{0, 1, 2}, {0, 1, 3}, {1, 2, 3}}
	for _, subset := range subsets {
		sig, child, err := DeriveAndSign(keys, subset, path, msg[:], rand.Reader)
		require.NoError(t, err)
		require.True(t, child.Equals(refChild), "child must match across subsets")
		ok := ecdsa.Verify(pub, msg[:], sig.R, sig.S)
		assert.Truef(t, ok, "subset %v signature does not verify", subset)
	}
}
