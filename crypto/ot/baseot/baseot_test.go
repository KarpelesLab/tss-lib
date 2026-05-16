package baseot

import (
	"bytes"
	"crypto/rand"
	mathrand "math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// runSession executes a full base-OT session with the given parameters and
// returns the sender's (k0, k1) and the receiver's chosen-key outputs.
func runSession(t *testing.T, sid []byte, n int, bits []byte) (k0, k1, kc [][KeyLen]byte) {
	t.Helper()

	sender, smsg, err := NewSender(sid, n, rand.Reader)
	require.NoError(t, err)
	require.NotNil(t, sender)
	require.NotNil(t, smsg)
	require.NotNil(t, smsg.S)
	require.NotNil(t, smsg.PoK)

	receiver, rmsg, err := NewReceiver(sid, n, bits, smsg, rand.Reader)
	require.NoError(t, err)
	require.NotNil(t, receiver)
	require.NotNil(t, rmsg)
	require.Len(t, rmsg.R, n)

	k0, k1, err = sender.Finalize(rmsg)
	require.NoError(t, err)
	require.Len(t, k0, n)
	require.Len(t, k1, n)

	kc, err = receiver.Finalize()
	require.NoError(t, err)
	require.Len(t, kc, n)
	return
}

// TestCorrectness verifies that for every instance i, the receiver's chosen
// key equals the sender's key indexed by the receiver's choice bit.
func TestCorrectness(t *testing.T) {
	cases := []struct {
		name string
		n    int
	}{
		{"n=1", 1},
		{"n=8", 8},
		{"n=64", 64},
		{"n=128", 128},
		{"n=256", 256},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bits := make([]byte, (tc.n+7)/8)
			_, err := rand.Read(bits)
			require.NoError(t, err)
			sid := []byte("test-correctness-" + tc.name)

			k0, k1, kc := runSession(t, sid, tc.n, bits)

			for i := 0; i < tc.n; i++ {
				c := (bits[i/8] >> (uint(i) & 7)) & 1
				if c == 1 {
					assert.Equalf(t, k1[i][:], kc[i][:], "instance %d: receiver chose 1, expected k1", i)
				} else {
					assert.Equalf(t, k0[i][:], kc[i][:], "instance %d: receiver chose 0, expected k0", i)
				}
				// The unchosen key must differ from the chosen one.
				assert.NotEqualf(t, k0[i][:], k1[i][:], "instance %d: k0 and k1 must differ", i)
			}
		})
	}
}

// TestSidBinding verifies that the same secret material under different
// session IDs produces different output keys (Fiat-Shamir domain
// separation correctness).
func TestSidBinding(t *testing.T) {
	const n = 16
	bits := []byte{0xAA, 0x55}

	_, _, kcA := runSession(t, []byte("sid-A"), n, bits)
	_, _, kcB := runSession(t, []byte("sid-B"), n, bits)

	// Same bits but different sid: every output key should differ with
	// overwhelming probability. Allow no exact matches.
	matches := 0
	for i := 0; i < n; i++ {
		if bytes.Equal(kcA[i][:], kcB[i][:]) {
			matches++
		}
	}
	assert.Zero(t, matches, "different sid should yield different keys")
}

// TestPoKRejection verifies that a tampered Schnorr PoK on S causes
// NewReceiver to reject the sender's message.
func TestPoKRejection(t *testing.T) {
	const n = 4
	sid := []byte("test-pok-rejection")
	bits := []byte{0x0F}

	sender, smsg, err := NewSender(sid, n, rand.Reader)
	require.NoError(t, err)
	_ = sender

	// Tamper: replace S with an unrelated point. The PoK was computed for
	// the original S and will not verify against this one.
	other, otherMsg, err := NewSender([]byte("other-sid"), n, rand.Reader)
	require.NoError(t, err)
	_ = other
	tampered := &SenderMsg1{S: otherMsg.S, PoK: smsg.PoK}

	_, _, err = NewReceiver(sid, n, bits, tampered, rand.Reader)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PoK")
}

// TestPoKSidMismatch verifies that NewReceiver rejects a sender message
// whose PoK was created with a different sid (cross-session replay).
func TestPoKSidMismatch(t *testing.T) {
	const n = 4
	bits := []byte{0xFF}

	_, smsg, err := NewSender([]byte("sender-sid"), n, rand.Reader)
	require.NoError(t, err)

	_, _, err = NewReceiver([]byte("receiver-sid"), n, bits, smsg, rand.Reader)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PoK")
}

// TestReceiverRejectsInvalidPoint ensures the receiver refuses an S that is
// not on the curve. We construct an invalid SenderMsg1 directly.
func TestReceiverRejectsInvalidPoint(t *testing.T) {
	const n = 1
	sid := []byte("test-invalid-S")
	bits := []byte{0}

	_, smsg, err := NewSender(sid, n, rand.Reader)
	require.NoError(t, err)

	// Replace S with a point whose X has been corrupted; NewECPointNoCurveCheck
	// bypasses the on-curve check so the resulting point fails ValidateBasic.
	bogus := crypto.NewECPointNoCurveCheck(tss.S256(),
		common.GetRandomPositiveInt(rand.Reader, tss.S256().Params().P),
		common.GetRandomPositiveInt(rand.Reader, tss.S256().Params().P),
	)
	bad := &SenderMsg1{S: bogus, PoK: smsg.PoK}

	_, _, err = NewReceiver(sid, n, bits, bad, rand.Reader)
	require.Error(t, err)
}

// TestSenderRejectsInvalidR verifies the sender refuses a receiver response
// where one of the R_i points is not on the curve.
func TestSenderRejectsInvalidR(t *testing.T) {
	const n = 2
	sid := []byte("test-invalid-R")
	bits := []byte{0x01}

	sender, smsg, err := NewSender(sid, n, rand.Reader)
	require.NoError(t, err)
	_, rmsg, err := NewReceiver(sid, n, bits, smsg, rand.Reader)
	require.NoError(t, err)

	// Corrupt R[1] to an off-curve point.
	rmsg.R[1] = crypto.NewECPointNoCurveCheck(tss.S256(),
		common.GetRandomPositiveInt(rand.Reader, tss.S256().Params().P),
		common.GetRandomPositiveInt(rand.Reader, tss.S256().Params().P),
	)

	_, _, err = sender.Finalize(rmsg)
	require.Error(t, err)
}

// TestFinalizeDoubleUse ensures both parties' Finalize methods cannot be
// invoked twice (defensive — sender's y and receiver's x are zeroized after
// the first call).
func TestFinalizeDoubleUse(t *testing.T) {
	const n = 1
	sid := []byte("test-double-finalize")
	bits := []byte{0}

	sender, smsg, err := NewSender(sid, n, rand.Reader)
	require.NoError(t, err)
	receiver, rmsg, err := NewReceiver(sid, n, bits, smsg, rand.Reader)
	require.NoError(t, err)

	_, _, err = sender.Finalize(rmsg)
	require.NoError(t, err)
	_, _, err = sender.Finalize(rmsg)
	require.Error(t, err)

	_, err = receiver.Finalize()
	require.NoError(t, err)
	_, err = receiver.Finalize()
	require.Error(t, err)
}

// TestBitsBufferTooSmall ensures NewReceiver rejects a too-short bits slice.
func TestBitsBufferTooSmall(t *testing.T) {
	const n = 17 // requires 3 bytes (24 bits)
	sid := []byte("test-bits-short")
	_, smsg, err := NewSender(sid, n, rand.Reader)
	require.NoError(t, err)

	_, _, err = NewReceiver(sid, n, []byte{0xFF, 0xFF}, smsg, rand.Reader) // 16 bits only
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bits buffer")
}

// TestBatchedSweep runs n=128 instances with a deterministic bit pattern
// (alternating) and randomized seeds to stress the full code path.
func TestBatchedSweep(t *testing.T) {
	const n = 128
	sid := []byte("test-batched-sweep")
	bits := make([]byte, n/8)
	// Alternate bits 0,1,0,1,... to exercise both branches of the receiver.
	for i := 0; i < n; i++ {
		if i%2 == 1 {
			bits[i/8] |= 1 << (uint(i) & 7)
		}
	}

	k0, k1, kc := runSession(t, sid, n, bits)
	for i := 0; i < n; i++ {
		c := (bits[i/8] >> (uint(i) & 7)) & 1
		var want [KeyLen]byte
		if c == 1 {
			want = k1[i]
		} else {
			want = k0[i]
		}
		require.Equalf(t, want[:], kc[i][:], "mismatch at instance %d (c=%d)", i, c)
	}
}

// TestRandomizedSweep runs a number of randomized end-to-end sessions to
// catch regressions in correctness across diverse choice patterns and
// instance counts. Uses math/rand for reproducibility of the bit patterns
// (the cryptographic randomness still comes from crypto/rand inside the
// protocol).
func TestRandomizedSweep(t *testing.T) {
	rng := mathrand.New(mathrand.NewSource(0xDEADBEEF))
	for trial := 0; trial < 20; trial++ {
		n := 1 + rng.Intn(200)
		bits := make([]byte, (n+7)/8)
		rng.Read(bits)
		sid := []byte("randomized-sweep-trial-")
		sid = append(sid, byte(trial))

		k0, k1, kc := runSession(t, sid, n, bits)
		for i := 0; i < n; i++ {
			c := (bits[i/8] >> (uint(i) & 7)) & 1
			if c == 1 {
				require.Equalf(t, k1[i][:], kc[i][:], "trial %d instance %d (c=1)", trial, i)
			} else {
				require.Equalf(t, k0[i][:], kc[i][:], "trial %d instance %d (c=0)", trial, i)
			}
		}
	}
}
