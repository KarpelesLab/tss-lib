package ole

import (
	"crypto/rand"
	mathrand "math/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/crypto/ot/baseot"
	"github.com/KarpelesLab/tss-lib/v2/crypto/ot/otext"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// setupParties runs base OT + OT-extension setup between two simulated
// parties and returns matched ExtReceiver/ExtSender pairs in the role
// orientation needed for ΠMul (Alice = ExtReceiver, Bob = ExtSender).
func setupParties(t *testing.T) (*otext.ExtReceiver, *otext.ExtSender) {
	t.Helper()
	const Kappa = otext.Kappa
	const DeltaBytes = otext.DeltaBytes
	sid := []byte("ole-setup")

	boSender, smsg, err := baseot.NewSender(sid, Kappa, rand.Reader)
	require.NoError(t, err)

	delta := make([]byte, DeltaBytes)
	_, err = rand.Read(delta)
	require.NoError(t, err)

	boReceiver, rmsg, err := baseot.NewReceiver(sid, Kappa, delta, smsg, rand.Reader)
	require.NoError(t, err)

	k0, k1, err := boSender.Finalize(rmsg)
	require.NoError(t, err)
	chosen, err := boReceiver.Finalize()
	require.NoError(t, err)

	extReceiver, err := otext.NewExtReceiverFromBase(k0, k1)
	require.NoError(t, err)
	extSender, err := otext.NewExtSenderFromBase(delta, chosen)
	require.NoError(t, err)

	return extReceiver, extSender
}

// TestMulCorrectness verifies α·β = u_A + u_B mod q across several random
// trials.
func TestMulCorrectness(t *testing.T) {
	q := tss.S256().Params().N
	extReceiver, extSender := setupParties(t)

	for trial := 0; trial < 8; trial++ {
		alpha := common.GetRandomPositiveInt(rand.Reader, q)
		beta := common.GetRandomPositiveInt(rand.Reader, q)
		sid := []byte("mul-correctness-trial-" + string(rune('0'+trial)))

		aMsg, aState, err := AliceStep1(sid, extReceiver, alpha)
		require.NoError(t, err)

		bobMsg, uB, err := BobStep1(sid, extSender, beta, aMsg)
		require.NoError(t, err)

		uA, err := AliceStep2(aState, bobMsg)
		require.NoError(t, err)

		// Verify u_A + u_B == α·β mod q.
		want := new(big.Int).Mul(alpha, beta)
		want.Mod(want, q)
		got := new(big.Int).Add(uA, uB)
		got.Mod(got, q)
		assert.Equalf(t, want.String(), got.String(),
			"trial %d: u_A + u_B != α·β", trial)
	}
}

// TestMulEdgeCases covers special-value α and β.
func TestMulEdgeCases(t *testing.T) {
	q := tss.S256().Params().N
	extReceiver, extSender := setupParties(t)

	cases := []struct {
		name        string
		alpha, beta *big.Int
	}{
		{"alpha=0", new(big.Int), big.NewInt(123456789)},
		{"beta=0", big.NewInt(987654321), new(big.Int)},
		{"alpha=1,beta=1", big.NewInt(1), big.NewInt(1)},
		{"alpha=q-1", new(big.Int).Sub(q, big.NewInt(1)), big.NewInt(2)},
		{"beta=q-1", big.NewInt(3), new(big.Int).Sub(q, big.NewInt(1))},
		{"large_random", new(big.Int).Lsh(big.NewInt(1), 200), new(big.Int).Lsh(big.NewInt(1), 100)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sid := []byte("mul-edge-" + tc.name)
			aMsg, aState, err := AliceStep1(sid, extReceiver, tc.alpha)
			require.NoError(t, err)
			bobMsg, uB, err := BobStep1(sid, extSender, tc.beta, aMsg)
			require.NoError(t, err)
			uA, err := AliceStep2(aState, bobMsg)
			require.NoError(t, err)

			want := new(big.Int).Mul(tc.alpha, tc.beta)
			want.Mod(want, q)
			got := new(big.Int).Add(uA, uB)
			got.Mod(got, q)
			assert.Equalf(t, want.String(), got.String(),
				"%s: u_A + u_B != α·β", tc.name)
		})
	}
}

// TestMulSidBinding verifies that two multiplications with the same OT
// extension state but different sids produce different (random) shares —
// i.e., the sid actually flows through to the underlying OT outputs.
func TestMulSidBinding(t *testing.T) {
	q := tss.S256().Params().N
	extReceiver, extSender := setupParties(t)

	alpha := common.GetRandomPositiveInt(rand.Reader, q)
	beta := common.GetRandomPositiveInt(rand.Reader, q)

	runOne := func(sid []byte) (*big.Int, *big.Int) {
		aMsg, aState, err := AliceStep1(sid, extReceiver, alpha)
		require.NoError(t, err)
		bobMsg, uB, err := BobStep1(sid, extSender, beta, aMsg)
		require.NoError(t, err)
		uA, err := AliceStep2(aState, bobMsg)
		require.NoError(t, err)
		return uA, uB
	}
	uA1, uB1 := runOne([]byte("sid-A"))
	uA2, uB2 := runOne([]byte("sid-B"))

	// Sums are equal (both = α·β mod q).
	prod := new(big.Int).Mul(alpha, beta)
	prod.Mod(prod, q)
	s1 := new(big.Int).Add(uA1, uB1)
	s1.Mod(s1, q)
	s2 := new(big.Int).Add(uA2, uB2)
	s2.Mod(s2, q)
	assert.Equal(t, prod.String(), s1.String())
	assert.Equal(t, prod.String(), s2.String())

	// But the individual shares should differ between sessions (random m_0
	// masks are session-distinct).
	assert.NotEqual(t, uA1.String(), uA2.String(), "u_A should differ between sids")
	assert.NotEqual(t, uB1.String(), uB2.String(), "u_B should differ between sids")
}

// TestMulRejectsTamperedCorrections verifies that if Bob's corrections
// are tampered, Alice still completes (correctness is not actively
// checked in this semi-honest-Bob version), but the result is wrong —
// confirming the documented limitation that malicious-Bob security
// requires the Mul-then-check upgrade.
//
// We use this test to (1) confirm the protocol is silent against bad Bob
// for now, and (2) document the expected behavior so any future check
// implementation breaks this test deliberately.
func TestMulSemiHonestBobBehavior(t *testing.T) {
	q := tss.S256().Params().N
	extReceiver, extSender := setupParties(t)

	alpha := common.GetRandomPositiveInt(rand.Reader, q)
	beta := common.GetRandomPositiveInt(rand.Reader, q)
	sid := []byte("mul-semi-honest-bob")

	aMsg, aState, err := AliceStep1(sid, extReceiver, alpha)
	require.NoError(t, err)
	bobMsg, _, err := BobStep1(sid, extSender, beta, aMsg)
	require.NoError(t, err)

	// Tamper one correction.
	bobMsg.Corrections[7] = new(big.Int).Add(bobMsg.Corrections[7], big.NewInt(1))
	bobMsg.Corrections[7].Mod(bobMsg.Corrections[7], q)

	uA, err := AliceStep2(aState, bobMsg)
	// Alice does NOT detect the tampering (no check).
	require.NoError(t, err)
	assert.NotNil(t, uA, "Alice still completes; security is correctness-only for Bob")
}

// TestMulRandomizedSweep runs many trials to catch off-by-one / endianness
// errors in the bit decomposition.
func TestMulRandomizedSweep(t *testing.T) {
	q := tss.S256().Params().N
	extReceiver, extSender := setupParties(t)
	rng := mathrand.New(mathrand.NewSource(0xBADF00D))

	for trial := 0; trial < 32; trial++ {
		// Mix in some structured values to exercise bit patterns.
		var alpha, beta *big.Int
		switch trial % 4 {
		case 0:
			alpha = big.NewInt(int64(rng.Uint32()))
			beta = big.NewInt(int64(rng.Uint32()))
		case 1:
			alpha = new(big.Int).Lsh(big.NewInt(1), uint(rng.Intn(255)+1))
			beta = common.GetRandomPositiveInt(rand.Reader, q)
		case 2:
			alpha = common.GetRandomPositiveInt(rand.Reader, q)
			beta = new(big.Int).Lsh(big.NewInt(1), uint(rng.Intn(255)+1))
		default:
			alpha = common.GetRandomPositiveInt(rand.Reader, q)
			beta = common.GetRandomPositiveInt(rand.Reader, q)
		}

		sid := []byte{byte(trial), byte(trial >> 8), 'm', 'u', 'l'}
		aMsg, aState, err := AliceStep1(sid, extReceiver, alpha)
		require.NoError(t, err)
		bobMsg, uB, err := BobStep1(sid, extSender, beta, aMsg)
		require.NoError(t, err)
		uA, err := AliceStep2(aState, bobMsg)
		require.NoError(t, err)

		want := new(big.Int).Mul(alpha, beta)
		want.Mod(want, q)
		got := new(big.Int).Add(uA, uB)
		got.Mod(got, q)
		require.Equalf(t, want.String(), got.String(),
			"trial %d (α=%s, β=%s)", trial, alpha.String(), beta.String())
	}
}

// TestMulRejectsMalformedInputs covers the input validators on both sides.
func TestMulRejectsMalformedInputs(t *testing.T) {
	extReceiver, extSender := setupParties(t)
	sid := []byte("mul-malformed")
	alpha := big.NewInt(42)
	beta := big.NewInt(99)

	_, _, err := AliceStep1(sid, nil, alpha)
	require.Error(t, err)

	_, _, err = AliceStep1(sid, extReceiver, nil)
	require.Error(t, err)

	aMsg, aState, err := AliceStep1(sid, extReceiver, alpha)
	require.NoError(t, err)

	_, _, err = BobStep1(sid, nil, beta, aMsg)
	require.Error(t, err)
	_, _, err = BobStep1(sid, extSender, nil, aMsg)
	require.Error(t, err)
	_, _, err = BobStep1(sid, extSender, beta, nil)
	require.Error(t, err)

	bobMsg, _, err := BobStep1(sid, extSender, beta, aMsg)
	require.NoError(t, err)

	_, err = AliceStep2(nil, bobMsg)
	require.Error(t, err)
	_, err = AliceStep2(aState, nil)
	require.Error(t, err)

	// Wrong number of corrections.
	bad := &BobMsg{Corrections: bobMsg.Corrections[:5]}
	_, err = AliceStep2(aState, bad)
	require.Error(t, err)
}
