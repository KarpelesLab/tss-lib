package dklstss

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/KarpelesLab/tss-lib/v2/crypto/ot/baseot"
	"github.com/KarpelesLab/tss-lib/v2/crypto/ot/otext"
)

// runBaseOTPair simulates a single base-OT batch between two parties
// in-process, returning the resulting OT-extension state pair where
// `extReceiver` is constructed from the base-OT sender's both-keys output
// and `extSender` is constructed from the base-OT receiver's chosen-key
// output (with the receiver's Δ).
//
// Naming: in OT-extension terminology, the "extension receiver" plays the
// base-OT sender (with both keys), and the "extension sender" plays the
// base-OT receiver (with Δ and chosen keys).
func runBaseOTPair(sid []byte, rng io.Reader) (*otext.ExtReceiver, *otext.ExtSender, error) {
	if rng == nil {
		rng = rand.Reader
	}
	const Kappa = otext.Kappa
	const DeltaBytes = otext.DeltaBytes

	boSender, smsg, err := baseot.NewSender(sid, Kappa, rng)
	if err != nil {
		return nil, nil, fmt.Errorf("dklstss: setup base-OT sender: %w", err)
	}
	delta := make([]byte, DeltaBytes)
	if _, err := io.ReadFull(rng, delta); err != nil {
		return nil, nil, fmt.Errorf("dklstss: setup delta: %w", err)
	}
	boReceiver, rmsg, err := baseot.NewReceiver(sid, Kappa, delta, smsg, rng)
	if err != nil {
		return nil, nil, fmt.Errorf("dklstss: setup base-OT receiver: %w", err)
	}
	k0, k1, err := boSender.Finalize(rmsg)
	if err != nil {
		return nil, nil, fmt.Errorf("dklstss: setup base-OT sender finalize: %w", err)
	}
	chosen, err := boReceiver.Finalize()
	if err != nil {
		return nil, nil, fmt.Errorf("dklstss: setup base-OT receiver finalize: %w", err)
	}
	extReceiver, err := otext.NewExtReceiverFromBase(k0, k1)
	if err != nil {
		return nil, nil, fmt.Errorf("dklstss: setup ext-receiver: %w", err)
	}
	extSender, err := otext.NewExtSenderFromBase(delta, chosen)
	if err != nil {
		return nil, nil, fmt.Errorf("dklstss: setup ext-sender: %w", err)
	}
	return extReceiver, extSender, nil
}

// setupPairs establishes the per-pair OT extension state for all parties
// in-process. For each ordered pair (i, j) with i ≠ j, party i ends up
// with OT[j].AsAlice (ExtReceiver) and party j ends up with OT[i].AsBob
// (ExtSender), with a separate run for the reverse direction.
//
// Returns a slice ot[i][j] = state held by party i for pair (i, j).
// ot[i][i] is nil.
//
// This is a SYNCHRONOUS, IN-PROCESS simulation. A networked equivalent
// would have each party run baseot.NewSender + baseot.NewReceiver against
// its peer and exchange messages via a broker.
func setupPairs(n int, sidPrefix []byte, rng io.Reader) ([][]*PairOTState, error) {
	if n <= 0 {
		return nil, fmt.Errorf("dklstss: setupPairs n must be > 0, got %d", n)
	}
	ot := make([][]*PairOTState, n)
	for i := range ot {
		ot[i] = make([]*PairOTState, n)
	}
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			// Direction A: party i is ExtReceiver (Alice in future ΠMul),
			// party j is ExtSender (Bob).
			//
			// Encode (i, j) as two 4-byte big-endian uint32 values rather
			// than `byte(i), byte(j)` — the byte cast truncates to the low
			// 8 bits, so any setup with n > 256 would produce colliding
			// sids across distinct pairs. With 4-byte encoding the sid is
			// injective for any practical n (≤ 2^32 parties).
			sidA := append([]byte(nil), sidPrefix...)
			sidA = append(sidA, encodePartyPair(i, j, 'A')...)
			rcvA, sndA, err := runBaseOTPair(sidA, rng)
			if err != nil {
				return nil, fmt.Errorf("dklstss: setupPairs (%d,%d)A: %w", i, j, err)
			}

			// Direction B: party j is ExtReceiver (Alice when j initiates
			// ΠMul against i), party i is ExtSender (Bob).
			sidB := append([]byte(nil), sidPrefix...)
			sidB = append(sidB, encodePartyPair(i, j, 'B')...)
			rcvB, sndB, err := runBaseOTPair(sidB, rng)
			if err != nil {
				return nil, fmt.Errorf("dklstss: setupPairs (%d,%d)B: %w", i, j, err)
			}

			// Wire up: party i, pair-with-j: AsAlice = rcvA, AsBob = sndB.
			if ot[i][j] == nil {
				ot[i][j] = &PairOTState{}
			}
			ot[i][j].AsAlice = rcvA
			ot[i][j].AsBob = sndB

			// Party j, pair-with-i: AsAlice = rcvB, AsBob = sndA.
			if ot[j][i] == nil {
				ot[j][i] = &PairOTState{}
			}
			ot[j][i].AsAlice = rcvB
			ot[j][i].AsBob = sndA
		}
	}
	return ot, nil
}

// encodePartyPair packs (i, j, dir) into a 9-byte injective encoding:
// 4 bytes big-endian uint32 for i, 4 bytes big-endian uint32 for j, plus
// a one-byte direction tag. The encoding is injective for i, j ∈ [0,
// 2^32) which exceeds any plausible TSS deployment size.
func encodePartyPair(i, j int, dir byte) []byte {
	return []byte{
		byte(uint32(i) >> 24), byte(uint32(i) >> 16), byte(uint32(i) >> 8), byte(i),
		byte(uint32(j) >> 24), byte(uint32(j) >> 16), byte(uint32(j) >> 8), byte(j),
		dir,
	}
}
