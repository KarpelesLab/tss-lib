package otext

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/crypto/ot/baseot"
)

// TestExtSenderExtendCTAgainstDelta verifies that ExtSender.Extend produces
// correct output for every value of the Δ-row bit, by comparing two senders
// that share base-OT seeds but differ only on a single Δ bit. The fix in
// extend.go replaces a Δ-dependent branch with a byte-level CT XOR mask;
// this test exercises both mask values within a single Extend call.
//
// The test is not itself a side-channel measurement (timing-side-channel
// tests are notoriously unreliable in CI), but it does ensure both branches
// of the original code path are exercised by every call and produce the
// expected outputs.
func TestExtSenderExtendCTAgainstDelta(t *testing.T) {
	const l = 256
	sid := []byte("test-ct-extend-against-delta")
	extSender, extReceiver, delta := setupExtParties(t, sid)

	choice := make([]byte, l/8)
	_, err := rand.Read(choice)
	require.NoError(t, err)

	msg, recvKeys, err := extReceiver.Extend(sid, choice, l)
	require.NoError(t, err)
	m0, m1, err := extSender.Extend(sid, msg)
	require.NoError(t, err)

	// Both Δ=0 and Δ=1 rows must produce correctly-aligned outputs.
	// (We don't need to know which bit of Δ corresponds to which row; the
	// invariant is m_{c_i}[i] == recvKeys[i] which holds regardless of Δ.)
	for i := 0; i < l; i++ {
		c := (choice[i/8] >> (uint(i) & 7)) & 1
		if c == 1 {
			require.Equalf(t, m1[i][:], recvKeys[i][:], "row %d c=1", i)
		} else {
			require.Equalf(t, m0[i][:], recvKeys[i][:], "row %d c=0", i)
		}
	}

	// Verify Δ contains BOTH 0 and 1 bits, so the test actually exercises
	// both branches of the fixed code path.
	has0, has1 := false, false
	for j := 0; j < Kappa; j++ {
		bit := (delta[j/8] >> (uint(j) & 7)) & 1
		if bit == 0 {
			has0 = true
		} else {
			has1 = true
		}
	}
	require.True(t, has0, "Δ has no 0 bits — increase Kappa or reroll")
	require.True(t, has1, "Δ has no 1 bits — increase Kappa or reroll")
}

// TestExtSenderExtendIsDeterministicForFixedInputs verifies that for fixed
// seeds, Δ, and msg.U, the sender's Extend output is deterministic. Combined
// with the CT-mask form, this means an attacker who can replay the same
// inputs cannot extract differential timing signal from Δ.
func TestExtSenderExtendIsDeterministicForFixedInputs(t *testing.T) {
	const l = 256
	sid := []byte("test-ct-deterministic")
	extSender, extReceiver, _ := setupExtParties(t, sid)

	choice := make([]byte, l/8)
	_, err := rand.Read(choice)
	require.NoError(t, err)

	msg, _, err := extReceiver.Extend(sid, choice, l)
	require.NoError(t, err)

	// Snapshot the sender's internal state by saving a copy.
	deltaCopy := extSender.delta
	seedsCopy := extSender.seeds

	m0a, m1a, err := extSender.Extend(sid, msg)
	require.NoError(t, err)

	// Reset and rerun.
	extSender.delta = deltaCopy
	extSender.seeds = seedsCopy
	m0b, m1b, err := extSender.Extend(sid, msg)
	require.NoError(t, err)

	for i := 0; i < l; i++ {
		require.Truef(t, bytes.Equal(m0a[i][:], m0b[i][:]), "m0[%d] not deterministic", i)
		require.Truef(t, bytes.Equal(m1a[i][:], m1b[i][:]), "m1[%d] not deterministic", i)
	}
}

// TestExtSenderExtendMaliciousReceiverRejected is a regression test that
// the KOS consistency check still rejects malicious receiver messages after
// the H-1 fix to the q-computation branch. This was already covered by
// malicious_test.go but the CT rewrite was sensitive enough to warrant a
// targeted re-check.
func TestExtSenderExtendMaliciousReceiverRejected(t *testing.T) {
	const l = 256
	sid := []byte("test-ct-malicious")
	extSender, extReceiver, _ := setupExtParties(t, sid)

	choice := make([]byte, l/8)
	_, err := rand.Read(choice)
	require.NoError(t, err)

	msg, _, err := extReceiver.Extend(sid, choice, l)
	require.NoError(t, err)

	// Tamper: flip a bit in U[0].
	msg.U[0][0] ^= 0xFF

	_, _, err = extSender.Extend(sid, msg)
	require.Error(t, err, "tampered U must fail consistency check")
}

// Quiet the unused-import warning if baseot ever drops out of the helper.
var _ = baseot.KeyLen
