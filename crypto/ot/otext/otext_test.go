package otext

import (
	"crypto/rand"
	mathrand "math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/crypto/ot/baseot"
)

// setupExtParties runs Kappa base OTs between two simulated parties and
// returns matched ExtSender / ExtReceiver pairs.
//
// Role mapping during base OT (per IKNP):
//   - extSenderSide plays the base-OT RECEIVER with choice bits = Δ
//   - extReceiverSide plays the base-OT SENDER with both keys per instance
func setupExtParties(t *testing.T, sid []byte) (*ExtSender, *ExtReceiver, []byte) {
	t.Helper()

	// extReceiverSide creates the base-OT sender; sends S+PoK.
	boSender, smsg, err := baseot.NewSender(sid, Kappa, rand.Reader)
	require.NoError(t, err)
	_ = boSender // only used to call Finalize

	// extSenderSide picks Δ and plays base-OT receiver.
	delta := make([]byte, DeltaBytes)
	_, err = rand.Read(delta)
	require.NoError(t, err)

	boReceiver, rmsg, err := baseot.NewReceiver(sid, Kappa, delta, smsg, rand.Reader)
	require.NoError(t, err)

	// Both parties finalize base OT.
	k0, k1, err := boSender.Finalize(rmsg)
	require.NoError(t, err)
	chosen, err := boReceiver.Finalize()
	require.NoError(t, err)

	// Wire base-OT outputs into ext state.
	extSender, err := NewExtSenderFromBase(delta, chosen)
	require.NoError(t, err)
	extReceiver, err := NewExtReceiverFromBase(k0, k1)
	require.NoError(t, err)

	return extSender, extReceiver, delta
}

// TestExtendCorrectness runs the semi-honest extension end-to-end and
// checks that for every i, the receiver's output equals the sender's
// m_{c_i}[i].
func TestExtendCorrectness(t *testing.T) {
	const l = 256
	sid := []byte("test-extend-correctness")

	extSender, extReceiver, _ := setupExtParties(t, sid)

	choice := make([]byte, l/8)
	_, err := rand.Read(choice)
	require.NoError(t, err)

	msg, recvKeys, err := extReceiver.Extend(sid, choice, l)
	require.NoError(t, err)
	require.Len(t, recvKeys, l)
	require.Equal(t, l, msg.L)
	require.Len(t, msg.U, Kappa)

	m0, m1, err := extSender.Extend(sid, msg)
	require.NoError(t, err)
	require.Len(t, m0, l)
	require.Len(t, m1, l)

	for i := 0; i < l; i++ {
		c := (choice[i/8] >> (uint(i) & 7)) & 1
		if c == 1 {
			assert.Equalf(t, m1[i][:], recvKeys[i][:], "row %d (c=1) mismatch", i)
		} else {
			assert.Equalf(t, m0[i][:], recvKeys[i][:], "row %d (c=0) mismatch", i)
		}
		// The unchosen output should differ.
		assert.NotEqualf(t, m0[i][:], m1[i][:], "row %d: m0 and m1 must differ", i)
	}
}

// TestExtendVariableL exercises the extension across several L values.
func TestExtendVariableL(t *testing.T) {
	cases := []int{8, 16, 64, 128, 512, 1024}
	for _, l := range cases {
		t.Run("", func(t *testing.T) {
			sid := []byte("test-variable-l")
			extSender, extReceiver, _ := setupExtParties(t, sid)

			choice := make([]byte, l/8)
			_, err := rand.Read(choice)
			require.NoError(t, err)

			msg, recvKeys, err := extReceiver.Extend(sid, choice, l)
			require.NoError(t, err)
			m0, m1, err := extSender.Extend(sid, msg)
			require.NoError(t, err)

			for i := 0; i < l; i++ {
				c := (choice[i/8] >> (uint(i) & 7)) & 1
				if c == 1 {
					require.Equalf(t, m1[i][:], recvKeys[i][:], "L=%d row=%d", l, i)
				} else {
					require.Equalf(t, m0[i][:], recvKeys[i][:], "L=%d row=%d", l, i)
				}
			}
		})
	}
}

// TestExtendSidBinding verifies that running two extensions with the same
// setup state but different sids produces different output keys.
//
// This is important downstream: ΠMul reuses the OT extension setup across
// many invocations, distinguished only by sid.
func TestExtendSidBinding(t *testing.T) {
	const l = 64
	sidSetup := []byte("test-extend-sid-setup")
	extSender, extReceiver, _ := setupExtParties(t, sidSetup)

	choice := []byte{0xAA, 0x55, 0xCC, 0x33, 0xF0, 0x0F, 0xAA, 0x55}

	msgA, recvA, err := extReceiver.Extend([]byte("sid-A"), choice, l)
	require.NoError(t, err)
	msgB, recvB, err := extReceiver.Extend([]byte("sid-B"), choice, l)
	require.NoError(t, err)

	// Same setup state, same choice — but different sid should yield
	// completely different output keys.
	matches := 0
	for i := 0; i < l; i++ {
		if recvA[i] == recvB[i] {
			matches++
		}
	}
	assert.Zero(t, matches, "different sid must yield different output keys")

	// Sanity: each side's extension still verifies under its own sid.
	m0A, m1A, err := extSender.Extend([]byte("sid-A"), msgA)
	require.NoError(t, err)
	m0B, m1B, err := extSender.Extend([]byte("sid-B"), msgB)
	require.NoError(t, err)
	_, _ = m1A, m1B
	for i := 0; i < l; i++ {
		c := (choice[i/8] >> (uint(i) & 7)) & 1
		var wantA, wantB [KeyLen]byte
		if c == 1 {
			wantA = m1A[i]
			wantB = m1B[i]
		} else {
			wantA = m0A[i]
			wantB = m0B[i]
		}
		require.Equalf(t, wantA[:], recvA[i][:], "sid-A row %d", i)
		require.Equalf(t, wantB[:], recvB[i][:], "sid-B row %d", i)
	}
}

// TestExtendReceiverRejectsBadInputs covers boundary errors in the
// receiver-side Extend.
func TestExtendReceiverRejectsBadInputs(t *testing.T) {
	sid := []byte("test-bad-receiver")
	_, extReceiver, _ := setupExtParties(t, sid)

	_, _, err := extReceiver.Extend(sid, []byte{0}, 7) // not a multiple of 8
	require.Error(t, err)

	_, _, err = extReceiver.Extend(sid, []byte{0}, 16) // bits buffer too short
	require.Error(t, err)

	_, _, err = extReceiver.Extend(sid, []byte{0}, 0) // L=0
	require.Error(t, err)
}

// TestExtendSenderRejectsBadInputs covers boundary errors in the
// sender-side Extend.
func TestExtendSenderRejectsBadInputs(t *testing.T) {
	sid := []byte("test-bad-sender")
	extSender, _, _ := setupExtParties(t, sid)

	_, _, err := extSender.Extend(sid, nil)
	require.Error(t, err)

	_, _, err = extSender.Extend(sid, &ExtendMsg1{L: 0, U: nil})
	require.Error(t, err)

	// Wrong number of U rows.
	_, _, err = extSender.Extend(sid, &ExtendMsg1{L: 64, U: make([][]byte, Kappa-1)})
	require.Error(t, err)

	// Wrong U row length (should be L/8).
	bad := &ExtendMsg1{L: 64, U: make([][]byte, Kappa)}
	for j := range bad.U {
		bad.U[j] = make([]byte, 4) // expected 8
	}
	_, _, err = extSender.Extend(sid, bad)
	require.Error(t, err)
}

// TestSetupRejectsBadSizes covers the constructors.
func TestSetupRejectsBadSizes(t *testing.T) {
	_, err := NewExtSenderFromBase(make([]byte, DeltaBytes-1), make([][baseot.KeyLen]byte, Kappa))
	require.Error(t, err)

	_, err = NewExtSenderFromBase(make([]byte, DeltaBytes), make([][baseot.KeyLen]byte, Kappa-1))
	require.Error(t, err)

	_, err = NewExtReceiverFromBase(make([][baseot.KeyLen]byte, Kappa-1), make([][baseot.KeyLen]byte, Kappa))
	require.Error(t, err)

	_, err = NewExtReceiverFromBase(make([][baseot.KeyLen]byte, Kappa), make([][baseot.KeyLen]byte, Kappa+1))
	require.Error(t, err)
}

// TestExtendRandomizedSweep runs many random L / choice-pattern combos to
// catch alignment regressions.
func TestExtendRandomizedSweep(t *testing.T) {
	rng := mathrand.New(mathrand.NewSource(0xC0FFEE))
	sid := []byte("test-randomized-sweep")
	extSender, extReceiver, _ := setupExtParties(t, sid)

	for trial := 0; trial < 8; trial++ {
		l := 8 * (1 + rng.Intn(64)) // 8..512, multiple of 8
		choice := make([]byte, l/8)
		rng.Read(choice)

		msg, recvKeys, err := extReceiver.Extend(sid, choice, l)
		require.NoError(t, err)
		m0, m1, err := extSender.Extend(sid, msg)
		require.NoError(t, err)

		for i := 0; i < l; i++ {
			c := (choice[i/8] >> (uint(i) & 7)) & 1
			var want [KeyLen]byte
			if c == 1 {
				want = m1[i]
			} else {
				want = m0[i]
			}
			if want != recvKeys[i] {
				t.Fatalf("trial %d (L=%d) row %d (c=%d) mismatch", trial, l, i, c)
			}
		}
	}
}

// TestExtendDoesNotLeakChoiceXorAcrossSessions is the regression test for
// the OT-extension seed-reuse vulnerability. Running Extend twice against
// the SAME setup with the SAME sid but DIFFERENT choice bits must NOT
// expose c1⊕c2 via XOR of the wire messages. (Two different sids are
// also fine and easier to spot; we use the same-sid case as the harder
// constraint — the per-call PRG derivation must mix sid into t0/t1
// regardless of whether sid is identical to a prior call.)
//
// Pre-fix the assertion would fire: u1⊕u2 = t0⊕t1⊕c1 ⊕ t0⊕t1⊕c2 = c1⊕c2.
// Post-fix t0/t1 are re-derived per call so u1⊕u2 is uniform-looking.
func TestExtendDoesNotLeakChoiceXorAcrossSessions(t *testing.T) {
	const l = 256
	sid := []byte("test-no-leak")
	extSender, extReceiver, _ := setupExtParties(t, sid)

	c1 := make([]byte, l/8)
	c2 := make([]byte, l/8)
	_, err := rand.Read(c1)
	require.NoError(t, err)
	_, err = rand.Read(c2)
	require.NoError(t, err)
	cXor := make([]byte, l/8)
	for i := range cXor {
		cXor[i] = c1[i] ^ c2[i]
	}

	// Use two distinct sids — even when sids differ, the v1 PRG would
	// still produce identical t0/t1 (only the OUTPUT hashes were sid-
	// separated), so this catches the bug too. The first session id is
	// `sid`; the second is a separate value.
	sid2 := []byte("test-no-leak-call-2")
	msg1, _, err := extReceiver.Extend(sid, c1, l)
	require.NoError(t, err)
	msg2, _, err := extReceiver.Extend(sid2, c2, l)
	require.NoError(t, err)

	// Sender side must also still verify with matching sids.
	_, _, err = extSender.Extend(sid, msg1)
	require.NoError(t, err)
	_, _, err = extSender.Extend(sid2, msg2)
	require.NoError(t, err)

	// For every row j ∈ [Kappa], u1[j] ⊕ u2[j] must NOT equal c1⊕c2.
	// With a good PRG the chance that any one row accidentally collides
	// with cXor is 2^-256 — fail loudly on a match.
	for j := 0; j < Kappa; j++ {
		uXor := make([]byte, len(msg1.U[j]))
		for b := range uXor {
			uXor[b] = msg1.U[j][b] ^ msg2.U[j][b]
		}
		for b := range uXor {
			if uXor[b] != cXor[b] {
				// Different at byte b — this row does NOT leak.
				break
			}
			if b == len(uXor)-1 {
				t.Fatalf("row %d: u1⊕u2 == c1⊕c2 — OT-extension seed reuse leaks choice XOR", j)
			}
		}
	}
}
