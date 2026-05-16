package dklstss

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMakeSidNoTruncationAcross256Boundary verifies the audit fix that
// replaced makeSid's `byte(alice), byte(bob)` (truncating indexes to one
// byte) with a 4-byte big-endian encoding. With the v1 encoding the
// pair (0, 1) and the pair (256, 257) would produce identical sids; the
// new encoding must keep them distinct.
//
// Collisions in this sid would cause the OT-extension layer to derive
// identical per-call PRG outputs for unrelated party pairs in
// committees with 256+ members, which combined with seed reuse would
// reintroduce the choice-bit XOR leak that the prg.go fix closes.
func TestMakeSidNoTruncationAcross256Boundary(t *testing.T) {
	ssid := []byte("ssid")
	kind := "test"
	sid01 := makeSid(ssid, kind, 0, 1)
	sid256_257 := makeSid(ssid, kind, 256, 257)
	require.False(t, bytes.Equal(sid01, sid256_257),
		"makeSid(0,1) must not equal makeSid(256,257) — pre-fix the byte() truncation made them identical")

	// Also check a less obvious case: pairs whose low bytes match.
	sid42_43 := makeSid(ssid, kind, 42, 43)
	sid298_299 := makeSid(ssid, kind, 42+256, 43+256)
	require.False(t, bytes.Equal(sid42_43, sid298_299),
		"makeSid pairs differing only in the high byte must be distinct")

	// Sanity: same inputs are deterministic.
	sid01b := makeSid(ssid, kind, 0, 1)
	assert.Equal(t, sid01, sid01b, "makeSid must be deterministic on the same inputs")
}

// TestSyncSignRepeatedReusesOTSafely is the synchronous-Sign analogue of
// TestSigningPartyRepeatedSignReusesOTSafely. Each Sign() call samples
// its own ssidNonce, so even before the audit the SIDs were already
// nonced — but the OT-extension state is reused across calls, so this
// test exercises the prgExpand sid-binding fix from crypto/ot/otext.
// Without that fix the receiver's u rows on the wire would leak
// bitsLE(k_i⁽¹⁾) ⊕ bitsLE(k_i⁽²⁾) to the partner, and key extraction
// would follow with enough signings.
func TestSyncSignRepeatedReusesOTSafely(t *testing.T) {
	keys, err := Keygen(3, 1, genPartyIDs(3), rand.Reader)
	require.NoError(t, err)
	msg := sha256.Sum256([]byte("sync-repeated"))

	sig1, err := Sign(keys, []int{0, 1}, msg[:], rand.Reader)
	require.NoError(t, err)
	sig2, err := Sign(keys, []int{0, 1}, msg[:], rand.Reader)
	require.NoError(t, err)

	pub := &ecdsa.PublicKey{
		Curve: keys[0].ECDSAPub.Curve(),
		X:     keys[0].ECDSAPub.X(),
		Y:     keys[0].ECDSAPub.Y(),
	}
	assert.True(t, ecdsa.Verify(pub, msg[:], sig1.R, sig1.S), "first sync sign must verify")
	assert.True(t, ecdsa.Verify(pub, msg[:], sig2.R, sig2.S), "second sync sign must verify")
	assert.NotEqual(t, sig1.R.String(), sig2.R.String(),
		"two ECDSA signatures of the same hash should have different R (fresh nonces)")
}

// TestReshareRejectsZeroScaledShare exercises the post-audit error path
// in resharing.go where `λ_i · x_i mod q == 0`. Natural probability is
// ~ 2⁻²⁵⁶ so we manufacture the precondition by zeroing one
// participant's Xi (BigXj is left as-is — Reshare doesn't recompute or
// cross-check it before the scaled-share calculation, so the test
// reaches the intended branch). The pre-audit code silently substituted
// scaled = 1 and let the protocol continue, eventually hitting a
// confusing pubkey-mismatch error downstream; the new code returns a
// clear "λ·x_i ≡ 0" error before any VSS material is generated.
func TestReshareRejectsZeroScaledShare(t *testing.T) {
	keys, err := Keygen(2, 1, genPartyIDs(2), rand.Reader)
	require.NoError(t, err)

	// Surgically zero out the FIRST participant's share. We don't
	// touch BigXj — Reshare uses Xi directly to form the scaled share
	// and the bug's branch fires before any BigXj-derived check runs.
	keys[0].Xi = new(big.Int)

	newIDs := genPartyIDs(2)
	_, err = Reshare(keys, []int{0, 1}, newIDs, 1, rand.Reader)
	require.Error(t, err, "Reshare with Xi=0 must error rather than silently substituting")
	assert.Contains(t, err.Error(), "λ·x_i ≡ 0",
		"error must clearly identify the corrupted share rather than a misleading downstream pubkey mismatch")
}
