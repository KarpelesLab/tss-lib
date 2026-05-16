package dklstss

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// TestReshareSameSize: 3-of-3 keygen, reshare to a different 3-of-3
// (same N, T, but fresh committee IDs). New shares must sign and
// verify under the unchanged public key.
func TestReshareSameSize(t *testing.T) {
	oldKeys, err := Keygen(3, 1, genPartyIDs(3), rand.Reader)
	require.NoError(t, err)
	oldPub := oldKeys[0].ECDSAPub

	// Reshare from old subset {0,1} to a new 3-party committee with
	// fresh IDs and threshold T=1.
	newIDs := genPartyIDsOffset(3, 100)
	newKeys, err := Reshare(oldKeys, []int{0, 1}, newIDs, 1, rand.Reader)
	require.NoError(t, err)
	require.Len(t, newKeys, 3)

	// Public key preserved.
	for i, k := range newKeys {
		assert.Truef(t, k.ECDSAPub.Equals(oldPub), "new key %d: pubkey changed", i)
	}

	// New committee can sign.
	msg := sha256.Sum256([]byte("after-reshare-3-of-3"))
	sig, err := Sign(newKeys, []int{0, 1}, msg[:], rand.Reader)
	require.NoError(t, err)
	pub := &ecdsa.PublicKey{Curve: oldPub.Curve(), X: oldPub.X(), Y: oldPub.Y()}
	assert.True(t, ecdsa.Verify(pub, msg[:], sig.R, sig.S))
}

// TestReshareDifferentSize: 3-of-3 → 5-of-7. New committee is bigger
// with higher threshold; public key preserved.
func TestReshareDifferentSize(t *testing.T) {
	oldKeys, err := Keygen(3, 1, genPartyIDs(3), rand.Reader)
	require.NoError(t, err)
	oldPub := oldKeys[0].ECDSAPub

	newKeys, err := Reshare(oldKeys, []int{0, 1}, genPartyIDsOffset(7, 1000), 4, rand.Reader)
	require.NoError(t, err)
	require.Len(t, newKeys, 7)
	assert.Equal(t, 7, newKeys[0].N)
	assert.Equal(t, 4, newKeys[0].T)
	assert.True(t, newKeys[0].ECDSAPub.Equals(oldPub))

	// Sign with the new committee (any 5 of 7).
	msg := sha256.Sum256([]byte("reshared-5-of-7"))
	sig, err := Sign(newKeys, []int{0, 2, 3, 5, 6}, msg[:], rand.Reader)
	require.NoError(t, err)
	pub := &ecdsa.PublicKey{Curve: oldPub.Curve(), X: oldPub.X(), Y: oldPub.Y()}
	assert.True(t, ecdsa.Verify(pub, msg[:], sig.R, sig.S))
}

// TestReshareSmaller: 5-of-7 → 2-of-3. Reduce committee size and
// threshold.
func TestReshareSmaller(t *testing.T) {
	oldKeys, err := Keygen(7, 4, genPartyIDs(7), rand.Reader)
	require.NoError(t, err)
	oldPub := oldKeys[0].ECDSAPub

	// Reshare from any 5-of-7 to a fresh 3-party committee with T=1.
	newKeys, err := Reshare(oldKeys, []int{0, 1, 3, 5, 6}, genPartyIDsOffset(3, 2000), 1, rand.Reader)
	require.NoError(t, err)
	require.Len(t, newKeys, 3)
	assert.True(t, newKeys[0].ECDSAPub.Equals(oldPub))

	// New committee signs.
	msg := sha256.Sum256([]byte("reshared-smaller"))
	sig, err := Sign(newKeys, []int{0, 2}, msg[:], rand.Reader)
	require.NoError(t, err)
	pub := &ecdsa.PublicKey{Curve: oldPub.Curve(), X: oldPub.X(), Y: oldPub.Y()}
	assert.True(t, ecdsa.Verify(pub, msg[:], sig.R, sig.S))
}

// TestReshareOldCommitteeCannotSignAfterDiscard verifies that if the old
// committee discards its OT setup state (simulating the "old keys
// expire" rotation), the new committee can sign while the old can't
// produce a verifying signature without recovering its keys.
//
// Operational note: rotating away from old keys is a procedural step
// (delete old files), not a cryptographic one — the math doesn't
// prevent the old committee from continuing to sign with the same
// public key if they still have their shares. The point of resharing
// is that the OPERATOR can now safely discard the old material.
func TestReshareNewCommitteeIndependent(t *testing.T) {
	oldKeys, err := Keygen(3, 1, genPartyIDs(3), rand.Reader)
	require.NoError(t, err)
	oldPub := oldKeys[0].ECDSAPub

	newKeys, err := Reshare(oldKeys, []int{0, 1}, genPartyIDsOffset(3, 5000), 1, rand.Reader)
	require.NoError(t, err)

	// New keys have DIFFERENT party IDs, DIFFERENT shares, but the SAME
	// public key.
	for i := range newKeys {
		assert.NotEqualf(t, oldKeys[i].PartyIDs[i].KeyInt().String(),
			newKeys[i].PartyIDs[i].KeyInt().String(),
			"new party %d should have different ID from old", i)
	}
	assert.True(t, newKeys[0].ECDSAPub.Equals(oldPub))

	// Both committees can each sign (old material is still active —
	// rotation is procedural).
	msg := sha256.Sum256([]byte("both-can-sign"))
	sigOld, err := Sign(oldKeys, []int{0, 1}, msg[:], rand.Reader)
	require.NoError(t, err)
	sigNew, err := Sign(newKeys, []int{0, 1}, msg[:], rand.Reader)
	require.NoError(t, err)

	pub := &ecdsa.PublicKey{Curve: oldPub.Curve(), X: oldPub.X(), Y: oldPub.Y()}
	assert.True(t, ecdsa.Verify(pub, msg[:], sigOld.R, sigOld.S))
	assert.True(t, ecdsa.Verify(pub, msg[:], sigNew.R, sigNew.S))
}

// TestReshareErrorPaths covers input validation.
func TestReshareErrorPaths(t *testing.T) {
	oldKeys, err := Keygen(3, 1, genPartyIDs(3), rand.Reader)
	require.NoError(t, err)
	newIDs := genPartyIDsOffset(3, 100)

	// Empty oldKeys.
	_, err = Reshare(nil, []int{0, 1}, newIDs, 1, rand.Reader)
	require.Error(t, err)

	// Insufficient old participants (T_old + 1 = 2 required).
	_, err = Reshare(oldKeys, []int{0}, newIDs, 1, rand.Reader)
	require.Error(t, err)

	// Duplicate participants.
	_, err = Reshare(oldKeys, []int{0, 0}, newIDs, 1, rand.Reader)
	require.Error(t, err)

	// Empty new committee.
	_, err = Reshare(oldKeys, []int{0, 1}, nil, 1, rand.Reader)
	require.Error(t, err)

	// Invalid threshold.
	_, err = Reshare(oldKeys, []int{0, 1}, newIDs, 0, rand.Reader)
	require.Error(t, err)
	_, err = Reshare(oldKeys, []int{0, 1}, newIDs, 3, rand.Reader)
	require.Error(t, err)
}

// genPartyIDsOffset returns n test PartyIDs with sequential keys
// starting from `start`. Used to construct fresh committees disjoint
// from a baseline.
func genPartyIDsOffset(n, start int) tss.SortedPartyIDs {
	unsorted := make(tss.UnSortedPartyIDs, n)
	for i := 0; i < n; i++ {
		unsorted[i] = tss.NewPartyID(
			"id-"+strconv.Itoa(start+i),
			"moniker-"+strconv.Itoa(start+i),
			big.NewInt(int64(start+i)),
		)
	}
	return tss.SortPartyIDs(unsorted)
}
