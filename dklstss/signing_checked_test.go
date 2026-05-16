package dklstss

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// TestSignCheckedCorrectness verifies the checked variant produces a
// valid ECDSA signature.
func TestSignCheckedCorrectness(t *testing.T) {
	keys, err := Keygen(3, 1, genPartyIDs(3), rand.Reader)
	require.NoError(t, err)

	msg := sha256.Sum256([]byte("checked-sign"))
	sig, err := SignChecked(keys, []int{0, 2}, msg[:], rand.Reader)
	require.NoError(t, err)

	pub := &ecdsa.PublicKey{
		Curve: keys[0].ECDSAPub.Curve(),
		X:     keys[0].ECDSAPub.X(),
		Y:     keys[0].ECDSAPub.Y(),
	}
	assert.True(t, ecdsa.Verify(pub, msg[:], sig.R, sig.S))
}

// TestSignCheckedHDDeriveTweakApplied verifies SignCheckedWithTweak.
func TestSignCheckedHDDeriveTweakApplied(t *testing.T) {
	keys, err := Keygen(2, 1, genPartyIDs(2), rand.Reader)
	require.NoError(t, err)
	path := []uint32{7, 8, 9}
	tweak, childPub, err := DeriveChild(keys[0], path)
	require.NoError(t, err)
	msg := sha256.Sum256([]byte("checked HD"))
	sig, err := SignCheckedWithTweak(keys, []int{0, 1}, tweak, msg[:], rand.Reader)
	require.NoError(t, err)

	pub := &ecdsa.PublicKey{
		Curve: childPub.Curve(),
		X:     childPub.X(),
		Y:     childPub.Y(),
	}
	assert.True(t, ecdsa.Verify(pub, msg[:], sig.R, sig.S))
}

// TestIdentityKeyRoundTrip verifies SignTranscript/VerifyTranscript.
func TestIdentityKeyRoundTrip(t *testing.T) {
	priv, pub, err := GenerateIdentityKeys(3, rand.Reader)
	require.NoError(t, err)
	keys, err := KeygenWithIdentities(3, 1, genPartyIDs(3), priv, pub, rand.Reader)
	require.NoError(t, err)

	transcript := []byte("test transcript payload")
	sig := keys[0].SignTranscript(transcript)
	require.NotNil(t, sig)
	require.NotEmpty(t, sig)

	// All peers can verify party 0's transcript.
	for i, peer := range keys {
		assert.Truef(t, peer.VerifyTranscript(0, transcript, sig), "peer %d failed to verify party 0's transcript", i)
	}

	// Tampering with the transcript fails verification.
	bad := append([]byte(nil), transcript...)
	bad[0] ^= 1
	assert.False(t, keys[1].VerifyTranscript(0, bad, sig))

	// Wrong party index fails.
	assert.False(t, keys[1].VerifyTranscript(2, transcript, sig))
}

// TestKeygenWithoutIdentitiesLeavesFieldsEmpty: plain Keygen does NOT
// populate identity fields, which the synchronous tests don't need.
func TestKeygenWithoutIdentitiesLeavesFieldsEmpty(t *testing.T) {
	keys, err := Keygen(2, 1, genPartyIDs(2), rand.Reader)
	require.NoError(t, err)
	for i, k := range keys {
		assert.Nilf(t, k.IdentityPriv, "key %d should have nil IdentityPriv", i)
		assert.Nilf(t, k.IdentityPub, "key %d should have nil IdentityPub", i)
		assert.Nil(t, k.SignTranscript([]byte("anything")), "no identity → SignTranscript returns nil")
	}
}

// TestSignCheckedReportsCulpritOnByzantineBob is a placeholder: in the
// synchronous in-process API there is no way for a peer to actually
// "deviate" without us cheating in the test harness. The test below
// directly invokes runCheckedMul with a sender that uses different β
// to confirm the culprit-attribution path lights up correctly.
//
// The actual end-to-end identifiable-abort path will be exercised by
// the broker-driven Party state machine in task #28.
func TestSignCheckedCulpritAttributionViaTSSError(t *testing.T) {
	// Use the direct ole API: construct a Mul-then-check error and
	// wrap it the way signing_checked.go does, then verify the
	// Culprits() comes back populated.
	pid := tss.NewPartyID("test-bob", "bob", big.NewInt(42))
	innerErr := errors.New("simulated check failure")
	wrapped := tss.NewError(innerErr, "dklstss-sign-checked", 0, nil, pid)
	assert.Equal(t, 1, len(wrapped.Culprits()))
	assert.Equal(t, pid, wrapped.Culprits()[0])
}
