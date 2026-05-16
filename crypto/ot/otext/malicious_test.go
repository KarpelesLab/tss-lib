package otext

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCheckRejectsFlippedU verifies that flipping a single bit of one U
// row after the receiver has computed it causes the sender's consistency
// check to fail with overwhelming probability.
//
// Rationale: a malicious receiver who modifies U after computing X,T has
// effectively encoded an inconsistent choice vector across rows. With
// σ=80 independent FS challenges, the check rejects with probability
// 1 − 2⁻⁸⁰.
func TestCheckRejectsFlippedU(t *testing.T) {
	const l = 128
	sid := []byte("test-check-flipped-u")
	extSender, extReceiver, _ := setupExtParties(t, sid)

	choice := make([]byte, l/8)
	_, err := rand.Read(choice)
	require.NoError(t, err)

	msg, _, err := extReceiver.Extend(sid, choice, l)
	require.NoError(t, err)

	// Flip a single bit somewhere in the middle of U.
	msg.U[7][3] ^= 0x10

	_, _, err = extSender.Extend(sid, msg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "consistency check")
}

// TestCheckRejectsFlippedT verifies that tampering with the receiver's
// T-vector triggers the consistency check.
func TestCheckRejectsFlippedT(t *testing.T) {
	const l = 64
	sid := []byte("test-check-flipped-t")
	extSender, extReceiver, _ := setupExtParties(t, sid)

	choice := make([]byte, l/8)
	_, err := rand.Read(choice)
	require.NoError(t, err)

	msg, _, err := extReceiver.Extend(sid, choice, l)
	require.NoError(t, err)

	// Flip a bit in T[0].
	msg.T[0][0] ^= 0x01

	_, _, err = extSender.Extend(sid, msg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "consistency check")
}

// TestCheckRejectsFlippedX verifies that tampering with the receiver's
// X-vector triggers the consistency check.
func TestCheckRejectsFlippedX(t *testing.T) {
	const l = 64
	sid := []byte("test-check-flipped-x")
	extSender, extReceiver, _ := setupExtParties(t, sid)

	choice := make([]byte, l/8)
	_, err := rand.Read(choice)
	require.NoError(t, err)

	msg, _, err := extReceiver.Extend(sid, choice, l)
	require.NoError(t, err)

	// Flip a bit in X.
	msg.X[0] ^= 0x01

	_, _, err = extSender.Extend(sid, msg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "consistency check")
}

// TestCheckRejectsInconsistentChoiceAcrossRows simulates a malicious
// receiver that uses choice vector c for some U rows and c' = c ⊕ d for
// others (with d nonzero). The standard `Extend` doesn't expose this, so
// we re-construct the message manually using the receiver's seeds.
//
// This is the canonical attack the consistency check defends against:
// a receiver who tries to "selectively unmask" via per-row inconsistency.
//
// Soundness note: a deviation at row j only manifests when the sender's
// Δ_j = 1 (otherwise q_j = t_{j,0} regardless of u_j). For a single-row
// flip the manifest probability is 1/2 (over the random Δ). To make
// detection overwhelming we flip MANY rows: with k flipped rows, P(all
// Δ_j = 0 across flipped rows) = 2^-k, beyond which σ=80 FS-soundness
// catches with 1 - 2^-80.
func TestCheckRejectsInconsistentChoiceAcrossRows(t *testing.T) {
	const l = 128
	sid := []byte("test-check-inconsistent")
	extSender, extReceiver, _ := setupExtParties(t, sid)
	lb := l / 8

	// Compute legitimate U with choice c.
	c := make([]byte, lb)
	_, err := rand.Read(c)
	require.NoError(t, err)

	// Manually replay the receiver protocol but flip choice bits for many
	// rows of U (simulating per-row inconsistency).
	t0 := make([][]byte, Kappa)
	t1 := make([][]byte, Kappa)
	for j := 0; j < Kappa; j++ {
		t0[j] = prgExpand(extReceiver.seeds0[j], sid, lb)
		t1[j] = prgExpand(extReceiver.seeds1[j], sid, lb)
	}
	u := make([][]byte, Kappa)
	for j := 0; j < Kappa; j++ {
		u[j] = make([]byte, lb)
		for b := 0; b < lb; b++ {
			u[j][b] = t0[j][b] ^ t1[j][b] ^ c[b]
		}
	}
	// Inject inconsistency across 32 rows so that with overwhelming
	// probability at least one of them lands on a Δ_j = 1 position.
	for j := 0; j < 32; j++ {
		u[4*j][0] ^= 0x01
	}

	v := transposeBits(t0, Kappa, l)
	chi := deriveChallenges(sid, u, l)

	// Compute X, T honestly under choice c (so the receiver passes the
	// check from its own perspective — but the deviation will still be
	// caught because the sender's q-matrix will reflect the per-row
	// inconsistency at Δ-bit positions).
	var xCheck [SigmaBytes]byte
	var tCheck [Sigma][DeltaBytes]byte
	for h := 0; h < Sigma; h++ {
		var xbit byte
		for byteIdx := 0; byteIdx < lb; byteIdx++ {
			selected := chi[h][byteIdx] & c[byteIdx]
			xbit ^= popcountByte(selected) & 1
			chiByte := chi[h][byteIdx]
			if chiByte == 0 {
				continue
			}
			base := byteIdx * 8
			for bit := 0; bit < 8; bit++ {
				if (chiByte>>uint(bit))&1 == 1 {
					i := base + bit
					if i >= l {
						break
					}
					for b := 0; b < DeltaBytes; b++ {
						tCheck[h][b] ^= v[i][b]
					}
				}
			}
		}
		if xbit == 1 {
			xCheck[h/8] |= 1 << (uint(h) & 7)
		}
	}

	bad := &ExtendMsg1{L: l, U: u, X: xCheck, T: tCheck}
	_, _, err = extSender.Extend(sid, bad)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "consistency check")
}

// TestCheckRejectsBitFlippedAfterCommit verifies that flipping ANY bit of
// any U row independently triggers the check. Iterates a small sample of
// flip positions to confirm the check is sensitive across the message.
func TestCheckRejectsBitFlippedAfterCommit(t *testing.T) {
	const l = 64
	sid := []byte("test-check-flipped-sample")

	flipPositions := []struct{ row, byteIdx int; bitMask byte }{
		{0, 0, 0x01},
		{0, 7, 0x80},
		{63, 3, 0x10},
		{127, 7, 0x08},
	}

	for _, fp := range flipPositions {
		t.Run("", func(t *testing.T) {
			extSender, extReceiver, _ := setupExtParties(t, sid)
			choice := make([]byte, l/8)
			_, err := rand.Read(choice)
			require.NoError(t, err)

			msg, _, err := extReceiver.Extend(sid, choice, l)
			require.NoError(t, err)
			msg.U[fp.row][fp.byteIdx] ^= fp.bitMask

			_, _, err = extSender.Extend(sid, msg)
			require.Errorf(t, err, "flip at row %d byte %d mask %#x should fail check", fp.row, fp.byteIdx, fp.bitMask)
		})
	}
}

// TestPopcountByte sanity-checks the popcount helper.
func TestPopcountByte(t *testing.T) {
	cases := []struct {
		in   byte
		want byte
	}{
		{0x00, 0},
		{0x01, 1},
		{0x03, 2},
		{0x07, 3},
		{0x0F, 4},
		{0x1F, 5},
		{0x3F, 6},
		{0x7F, 7},
		{0xFF, 8},
		{0xAA, 4},
		{0x55, 4},
	}
	for _, tc := range cases {
		got := popcountByte(tc.in)
		assert.Equalf(t, tc.want, got, "popcountByte(%#x)", tc.in)
	}
}
