package ole

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/KarpelesLab/tss-lib/v2/crypto/ot/otext"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// ScalarBits is the bit length of secp256k1's scalar field. The
// multiplication consumes exactly this many OT extension rows per session.
//
// We deliberately do NOT add statistical padding (extra rows for hiding
// α from a malicious Bob). The protocol below is correct without it; the
// padding rows belong to DKLs23 §5's "Mul-then-check" composition, which
// is task #17 and folds in additional rows on its own.
const ScalarBits = 256

// BobMsg is Bob's message to Alice after his side of the multiplication
// completes: ScalarBits correction values, each in [0, q).
type BobMsg struct {
	Corrections []*big.Int
}

// AliceState carries Alice's per-session intermediate state between
// AliceStep1 (when she sends the OT extension message) and AliceStep2
// (when she processes Bob's reply).
//
// The struct holds Alice's OT extension outputs; treat it as sensitive
// and discard after AliceStep2 completes.
type AliceState struct {
	sid   []byte
	alpha *big.Int
	keys  [][otext.KeyLen]byte
}

// AliceStep1 runs Alice's first step. Alice's choice bits are the
// little-endian bit-decomposition of α reduced mod q. Returns the OT
// extension message to send to Bob and Alice's per-session state.
func AliceStep1(sid []byte, extReceiver *otext.ExtReceiver, alpha *big.Int) (*otext.ExtendMsg1, *AliceState, error) {
	if extReceiver == nil {
		return nil, nil, errors.New("ole: AliceStep1 nil ExtReceiver")
	}
	if alpha == nil {
		return nil, nil, errors.New("ole: AliceStep1 nil alpha")
	}
	q := tss.S256().Params().N
	a := new(big.Int).Mod(alpha, q)

	choice := bitsLE(a)

	extMsg, keys, err := extReceiver.Extend(sid, choice, ScalarBits)
	if err != nil {
		return nil, nil, fmt.Errorf("ole: AliceStep1 OT extension: %w", err)
	}
	if len(keys) != ScalarBits {
		return nil, nil, fmt.Errorf("ole: AliceStep1 unexpected key count %d (want %d)", len(keys), ScalarBits)
	}

	return extMsg, &AliceState{
		sid:   append([]byte(nil), sid...),
		alpha: a,
		keys:  keys,
	}, nil
}

// BobStep1 runs Bob's side of the multiplication given Alice's extension
// message. Returns Bob's message (corrections) and Bob's share u_B ∈ F_q.
//
// Bob's share is u_B := −Σ_i m_0[i] (mod q); Alice's share, after
// AliceStep2, will satisfy u_A + u_B ≡ α·β (mod q).
func BobStep1(sid []byte, extSender *otext.ExtSender, beta *big.Int, aliceMsg *otext.ExtendMsg1) (*BobMsg, *big.Int, error) {
	if extSender == nil {
		return nil, nil, errors.New("ole: BobStep1 nil ExtSender")
	}
	if beta == nil {
		return nil, nil, errors.New("ole: BobStep1 nil beta")
	}
	if aliceMsg == nil {
		return nil, nil, errors.New("ole: BobStep1 nil aliceMsg")
	}
	if aliceMsg.L != ScalarBits {
		return nil, nil, fmt.Errorf("ole: BobStep1 expected L=%d, got %d", ScalarBits, aliceMsg.L)
	}
	q := tss.S256().Params().N
	b := new(big.Int).Mod(beta, q)

	m0, m1, err := extSender.Extend(sid, aliceMsg)
	if err != nil {
		return nil, nil, fmt.Errorf("ole: BobStep1 OT extension: %w", err)
	}

	corrections := make([]*big.Int, ScalarBits)
	uB := new(big.Int)
	twoToI := big.NewInt(1)

	for i := 0; i < ScalarBits; i++ {
		m0i := new(big.Int).SetBytes(m0[i][:])
		m0i.Mod(m0i, q)
		m1i := new(big.Int).SetBytes(m1[i][:])
		m1i.Mod(m1i, q)

		// contrib = β · 2^i (mod q)
		contrib := new(big.Int).Mul(b, twoToI)
		contrib.Mod(contrib, q)

		// c_i = m_0[i] − m_1[i] + β · 2^i (mod q)
		ci := new(big.Int).Sub(m0i, m1i)
		ci.Add(ci, contrib)
		ci.Mod(ci, q)
		corrections[i] = ci

		// u_B accumulates −m_0[i]
		uB.Sub(uB, m0i)

		// Advance 2^i for next round (still over Z; we reduce in the mul).
		twoToI = new(big.Int).Lsh(twoToI, 1)
	}
	uB.Mod(uB, q)

	return &BobMsg{Corrections: corrections}, uB, nil
}

// AliceStep2 combines Bob's corrections with Alice's OT outputs to compute
// Alice's share u_A ∈ F_q. The protocol is invalid if Bob's message is
// missing or malformed; the caller should treat the error as an abort.
//
// After this call the underlying state is logically consumed; callers
// should discard the AliceState.
func AliceStep2(state *AliceState, bobMsg *BobMsg) (*big.Int, error) {
	if state == nil {
		return nil, errors.New("ole: AliceStep2 nil state")
	}
	if bobMsg == nil {
		return nil, errors.New("ole: AliceStep2 nil bobMsg")
	}
	if len(bobMsg.Corrections) != ScalarBits {
		return nil, fmt.Errorf("ole: AliceStep2 expected %d corrections, got %d", ScalarBits, len(bobMsg.Corrections))
	}
	q := tss.S256().Params().N

	uA := new(big.Int)
	for i := 0; i < ScalarBits; i++ {
		ki := new(big.Int).SetBytes(state.keys[i][:])
		ki.Mod(ki, q)
		// t_i = m_{α_i}[i] + α_i · c_i (mod q)
		if state.alpha.Bit(i) == 1 {
			if bobMsg.Corrections[i] == nil {
				return nil, fmt.Errorf("ole: AliceStep2 nil correction[%d]", i)
			}
			ki.Add(ki, bobMsg.Corrections[i])
			ki.Mod(ki, q)
		}
		uA.Add(uA, ki)
	}
	uA.Mod(uA, q)
	return uA, nil
}

// bitsLE returns the little-endian bit packing of v (32 bytes, lowest bit
// first within each byte) suitable for use as OT extension choice bits.
// v is interpreted modulo 2^256; bits at position ≥ 256 are dropped.
func bitsLE(v *big.Int) []byte {
	out := make([]byte, ScalarBits/8)
	for i := 0; i < ScalarBits; i++ {
		if v.Bit(i) == 1 {
			out[i/8] |= 1 << (uint(i) & 7)
		}
	}
	return out
}
