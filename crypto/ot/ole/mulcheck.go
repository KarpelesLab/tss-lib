package ole

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/KarpelesLab/tss-lib/v2/crypto/ot/otext"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// CheckedBobMsg is Bob's reply for a Mul-then-check session. It bundles
// the two parallel ΠMul corrections (Msg1, Msg2) together with Bob's
// cross-run consistency value Z = u_B1 − u_B2 (mod q).
//
// Alice verifies the consistency by computing her own Z_A = u_A1 − u_A2
// and asserting Z_A + Z_B ≡ 0 (mod q). If Bob used different β values in
// the two runs, the sum is α·(β1 − β2) ≠ 0 and the check fails. The
// check therefore catches "Bob used inconsistent β across the two runs"
// but cannot detect a consistent wrong β — that class is caught at the
// signing layer by ECDSA signature verification.
//
// This implements the simplified consistency check pattern of DKLs23
// §5; the full identifiable-abort version with Pedersen-style β
// commitment is task #17.
type CheckedBobMsg struct {
	Msg1 *BobMsg
	Msg2 *BobMsg
	Z    *big.Int // u_B1 − u_B2 mod q
}

// CheckedAliceState carries Alice's state across the two ΠMul flows.
type CheckedAliceState struct {
	state1 *AliceState
	state2 *AliceState
}

// CheckedAliceStep1 runs Alice's side of Mul-then-check. It launches TWO
// parallel ΠMul instances with the same α, using sub-sids "|1" and "|2"
// derived from the caller-provided sid. Returns both extension envelopes
// (to be sent to Bob) and Alice's combined state for the second step.
func CheckedAliceStep1(sid []byte, extReceiver *otext.ExtReceiver, alpha *big.Int) (*otext.ExtendMsg1, *otext.ExtendMsg1, *CheckedAliceState, error) {
	if extReceiver == nil {
		return nil, nil, nil, errors.New("ole: CheckedAliceStep1 nil ExtReceiver")
	}
	if alpha == nil {
		return nil, nil, nil, errors.New("ole: CheckedAliceStep1 nil alpha")
	}
	sid1 := subSid(sid, '1')
	sid2 := subSid(sid, '2')

	msg1, st1, err := AliceStep1(sid1, extReceiver, alpha)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ole: CheckedAliceStep1 mul1: %w", err)
	}
	msg2, st2, err := AliceStep1(sid2, extReceiver, alpha)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ole: CheckedAliceStep1 mul2: %w", err)
	}
	return msg1, msg2, &CheckedAliceState{state1: st1, state2: st2}, nil
}

// CheckedBobStep1 runs Bob's side. It evaluates both ΠMul instances with
// the SAME β and computes the cross-run consistency value Z = u_B1 − u_B2.
// Returns the combined message and Bob's share (= u_B1, the first
// multiplication's share, which is the canonical output of the checked
// multiplication).
func CheckedBobStep1(sid []byte, extSender *otext.ExtSender, beta *big.Int, aliceMsg1, aliceMsg2 *otext.ExtendMsg1) (*CheckedBobMsg, *big.Int, error) {
	if extSender == nil {
		return nil, nil, errors.New("ole: CheckedBobStep1 nil ExtSender")
	}
	if beta == nil {
		return nil, nil, errors.New("ole: CheckedBobStep1 nil beta")
	}
	sid1 := subSid(sid, '1')
	sid2 := subSid(sid, '2')

	bobMsg1, uB1, err := BobStep1(sid1, extSender, beta, aliceMsg1)
	if err != nil {
		return nil, nil, fmt.Errorf("ole: CheckedBobStep1 mul1: %w", err)
	}
	bobMsg2, uB2, err := BobStep1(sid2, extSender, beta, aliceMsg2)
	if err != nil {
		return nil, nil, fmt.Errorf("ole: CheckedBobStep1 mul2: %w", err)
	}

	q := tss.S256().Params().N
	Z := new(big.Int).Sub(uB1, uB2)
	Z.Mod(Z, q)

	return &CheckedBobMsg{Msg1: bobMsg1, Msg2: bobMsg2, Z: Z}, uB1, nil
}

// ErrMulCheckFailed is returned by CheckedAliceStep2 when the cross-run
// consistency check rejects: Bob used different β values in the two
// parallel ΠMul runs.
var ErrMulCheckFailed = errors.New("ole: Mul-then-check failed — Bob's β differs across parallel runs")

// CheckedAliceStep2 verifies Bob's consistency value and returns Alice's
// share u_A1 such that u_A1 + u_B1 ≡ α·β (mod q). On check failure
// returns ErrMulCheckFailed and no share.
func CheckedAliceStep2(state *CheckedAliceState, bobMsg *CheckedBobMsg) (*big.Int, error) {
	if state == nil || bobMsg == nil {
		return nil, errors.New("ole: CheckedAliceStep2 nil input")
	}
	uA1, err := AliceStep2(state.state1, bobMsg.Msg1)
	if err != nil {
		return nil, fmt.Errorf("ole: CheckedAliceStep2 mul1: %w", err)
	}
	uA2, err := AliceStep2(state.state2, bobMsg.Msg2)
	if err != nil {
		return nil, fmt.Errorf("ole: CheckedAliceStep2 mul2: %w", err)
	}
	q := tss.S256().Params().N

	// Honest Bob: (u_A1 + u_B1) = α·β = (u_A2 + u_B2).
	// ⇒ (u_A1 − u_A2) + (u_B1 − u_B2) = 0.
	// Z_A + Z = 0 mod q.
	Za := new(big.Int).Sub(uA1, uA2)
	Za.Mod(Za, q)
	sum := new(big.Int).Add(Za, bobMsg.Z)
	sum.Mod(sum, q)
	if sum.Sign() != 0 {
		return nil, ErrMulCheckFailed
	}
	return uA1, nil
}

// subSid returns sid || "|" || tag.
func subSid(sid []byte, tag byte) []byte {
	out := make([]byte, 0, len(sid)+2)
	out = append(out, sid...)
	out = append(out, '|', tag)
	return out
}
