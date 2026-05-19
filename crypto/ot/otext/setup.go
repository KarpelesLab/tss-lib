package otext

import (
	"errors"
	"fmt"

	"github.com/KarpelesLab/tss-lib/v2/crypto/ot/baseot"
)

// ExtSender holds the OT extension sender's per-session state.
//
// Role mapping: in our naming the ExtSender is the party that PRODUCES the
// (m_0, m_1) pairs at the end of the extension. During the base-OT phase
// that precedes setup, however, this party plays the role of the base-OT
// RECEIVER — it picks Δ ∈ {0,1}^κ as its base-OT choice bits and learns
// the seed at index Δ_j for each j.
//
// After Extend is called, the sender's state (Δ and seeds) is intentionally
// NOT zeroized: the same setup is reused across many Extend invocations in
// DKLs23 (one base-OT setup, many ΠMul invocations). Callers must dispose
// of an ExtSender explicitly when the OT extension session is no longer
// needed by overwriting the struct with the zero value.
type ExtSender struct {
	delta [DeltaBytes]byte     // κ-bit secret
	seeds [Kappa][SeedLen]byte // seeds[j] = base-OT output for Δ_j
}

// ExtReceiver holds the OT extension receiver's per-session state.
//
// Role mapping: in our naming the ExtReceiver is the party that supplies
// choice bits c ∈ {0,1}^L and learns m_{c_i} per row. During base OT it
// plays the role of the base-OT SENDER — it produces BOTH seeds per base
// OT instance.
type ExtReceiver struct {
	seeds0 [Kappa][SeedLen]byte // base-OT output for bit 0
	seeds1 [Kappa][SeedLen]byte // base-OT output for bit 1
}

// NewExtSenderFromBase constructs an ExtSender from the outputs of a
// Kappa-instance base-OT batch where this party played the base-OT
// receiver with choice bits `delta` and learned `keys[j]` per instance.
//
// `delta` must be exactly DeltaBytes long; `keys` must have length Kappa.
// The slices are copied, so the caller may zeroize its own copies after
// the call returns.
func NewExtSenderFromBase(delta []byte, keys [][baseot.KeyLen]byte) (*ExtSender, error) {
	if len(delta) != DeltaBytes {
		return nil, fmt.Errorf("otext: NewExtSenderFromBase delta must be %d bytes, got %d", DeltaBytes, len(delta))
	}
	if len(keys) != Kappa {
		return nil, fmt.Errorf("otext: NewExtSenderFromBase keys must have length %d, got %d", Kappa, len(keys))
	}
	s := &ExtSender{}
	copy(s.delta[:], delta)
	for j := 0; j < Kappa; j++ {
		s.seeds[j] = keys[j]
	}
	return s, nil
}

// NewExtReceiverFromBase constructs an ExtReceiver from the outputs of a
// Kappa-instance base-OT batch where this party played the base-OT sender
// and knows both keys per instance.
//
// `k0` and `k1` must both have length Kappa. The slices are copied.
func NewExtReceiverFromBase(k0, k1 [][baseot.KeyLen]byte) (*ExtReceiver, error) {
	if len(k0) != Kappa || len(k1) != Kappa {
		return nil, fmt.Errorf("otext: NewExtReceiverFromBase k0/k1 must each have length %d (got %d/%d)", Kappa, len(k0), len(k1))
	}
	r := &ExtReceiver{}
	for j := 0; j < Kappa; j++ {
		r.seeds0[j] = k0[j]
		r.seeds1[j] = k1[j]
	}
	return r, nil
}

// Delta returns a copy of the sender's secret correlation Δ for use in
// derived protocols (e.g. correlated OT). Callers should treat the result
// as sensitive and zero it after use.
//
// This method is provided primarily for tests and protocol composition;
// production code should generally not need direct access to Δ.
func (s *ExtSender) Delta() [DeltaBytes]byte {
	var out [DeltaBytes]byte
	copy(out[:], s.delta[:])
	return out
}

// validateExtendInputs is a small helper shared by Extend on both sides.
func validateExtendInputs(l int) error {
	if l <= 0 {
		return errors.New("otext: l must be positive")
	}
	if l%8 != 0 {
		return errors.New("otext: l must be a multiple of 8")
	}
	return nil
}
