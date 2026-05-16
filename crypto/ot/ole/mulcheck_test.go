package ole

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// TestCheckedMulCorrectness verifies the checked variant produces the
// same kind of additive shares as the basic ΠMul.
func TestCheckedMulCorrectness(t *testing.T) {
	q := tss.S256().Params().N
	extReceiver, extSender := setupParties(t)

	alpha := common.GetRandomPositiveInt(rand.Reader, q)
	beta := common.GetRandomPositiveInt(rand.Reader, q)
	sid := []byte("test-checked-correctness")

	msg1, msg2, state, err := CheckedAliceStep1(sid, extReceiver, alpha)
	require.NoError(t, err)
	bMsg, uB, err := CheckedBobStep1(sid, extSender, beta, msg1, msg2)
	require.NoError(t, err)
	uA, err := CheckedAliceStep2(state, bMsg)
	require.NoError(t, err)

	want := new(big.Int).Mul(alpha, beta)
	want.Mod(want, q)
	got := new(big.Int).Add(uA, uB)
	got.Mod(got, q)
	assert.Equal(t, want.String(), got.String())
}

// TestCheckedMulDetectsInconsistentBeta verifies that the consistency
// check rejects when Bob runs the two ΠMul instances with different β.
func TestCheckedMulDetectsInconsistentBeta(t *testing.T) {
	q := tss.S256().Params().N
	extReceiver, extSender := setupParties(t)

	alpha := common.GetRandomPositiveInt(rand.Reader, q)
	beta1 := common.GetRandomPositiveInt(rand.Reader, q)
	beta2 := common.GetRandomPositiveInt(rand.Reader, q)
	sid := []byte("test-checked-inconsistent")

	msg1, msg2, state, err := CheckedAliceStep1(sid, extReceiver, alpha)
	require.NoError(t, err)

	// Bob deviates: uses beta1 in mul1 and beta2 in mul2.
	sid1 := subSid(sid, '1')
	sid2 := subSid(sid, '2')
	bobMsg1, uB1, err := BobStep1(sid1, extSender, beta1, msg1)
	require.NoError(t, err)
	bobMsg2, uB2, err := BobStep1(sid2, extSender, beta2, msg2)
	require.NoError(t, err)

	Z := new(big.Int).Sub(uB1, uB2)
	Z.Mod(Z, q)
	bad := &CheckedBobMsg{Msg1: bobMsg1, Msg2: bobMsg2, Z: Z}

	_, err = CheckedAliceStep2(state, bad)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrMulCheckFailed)
}

// TestCheckedMulDetectsTamperedZ verifies that flipping Bob's Z value
// causes Alice to reject.
func TestCheckedMulDetectsTamperedZ(t *testing.T) {
	q := tss.S256().Params().N
	extReceiver, extSender := setupParties(t)

	alpha := common.GetRandomPositiveInt(rand.Reader, q)
	beta := common.GetRandomPositiveInt(rand.Reader, q)
	sid := []byte("test-checked-tampered-z")

	msg1, msg2, state, err := CheckedAliceStep1(sid, extReceiver, alpha)
	require.NoError(t, err)
	bMsg, _, err := CheckedBobStep1(sid, extSender, beta, msg1, msg2)
	require.NoError(t, err)

	// Tamper Bob's Z by one.
	bMsg.Z = new(big.Int).Add(bMsg.Z, big.NewInt(1))
	bMsg.Z.Mod(bMsg.Z, q)

	_, err = CheckedAliceStep2(state, bMsg)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrMulCheckFailed)
}

// TestCheckedMulErrorPaths covers malformed-input rejections.
func TestCheckedMulErrorPaths(t *testing.T) {
	extReceiver, extSender := setupParties(t)
	sid := []byte("test-checked-errors")
	alpha := big.NewInt(7)
	beta := big.NewInt(11)

	_, _, _, err := CheckedAliceStep1(sid, nil, alpha)
	require.Error(t, err)
	_, _, _, err = CheckedAliceStep1(sid, extReceiver, nil)
	require.Error(t, err)

	msg1, msg2, _, err := CheckedAliceStep1(sid, extReceiver, alpha)
	require.NoError(t, err)
	_, _, err = CheckedBobStep1(sid, nil, beta, msg1, msg2)
	require.Error(t, err)
	_, _, err = CheckedBobStep1(sid, extSender, nil, msg1, msg2)
	require.Error(t, err)

	_, err = CheckedAliceStep2(nil, &CheckedBobMsg{})
	require.Error(t, err)
}
