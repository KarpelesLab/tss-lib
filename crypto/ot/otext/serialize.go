package otext

import (
	"encoding/json"
	"fmt"

	"github.com/KarpelesLab/tss-lib/v2/crypto/ot/baseot"
)

// Marshaled forms used for persistence. The structs are exported and
// JSON-tagged so callers can route them through any standard
// serializer. The Marshal/Unmarshal helpers below are conveniences.

type extSenderJSON struct {
	Delta [DeltaBytes]byte           `json:"delta"`
	Seeds [Kappa][baseot.KeyLen]byte `json:"seeds"`
}

type extReceiverJSON struct {
	Seeds0 [Kappa][baseot.KeyLen]byte `json:"seeds0"`
	Seeds1 [Kappa][baseot.KeyLen]byte `json:"seeds1"`
}

// MarshalJSON implements json.Marshaler.
func (s *ExtSender) MarshalJSON() ([]byte, error) {
	if s == nil {
		return []byte("null"), nil
	}
	return json.Marshal(extSenderJSON{Delta: s.delta, Seeds: s.seeds})
}

// UnmarshalJSON implements json.Unmarshaler.
func (s *ExtSender) UnmarshalJSON(data []byte) error {
	var v extSenderJSON
	if err := json.Unmarshal(data, &v); err != nil {
		return fmt.Errorf("otext: UnmarshalJSON ExtSender: %w", err)
	}
	s.delta = v.Delta
	s.seeds = v.Seeds
	return nil
}

// MarshalJSON implements json.Marshaler.
func (r *ExtReceiver) MarshalJSON() ([]byte, error) {
	if r == nil {
		return []byte("null"), nil
	}
	return json.Marshal(extReceiverJSON{Seeds0: r.seeds0, Seeds1: r.seeds1})
}

// UnmarshalJSON implements json.Unmarshaler.
func (r *ExtReceiver) UnmarshalJSON(data []byte) error {
	var v extReceiverJSON
	if err := json.Unmarshal(data, &v); err != nil {
		return fmt.Errorf("otext: UnmarshalJSON ExtReceiver: %w", err)
	}
	r.seeds0 = v.Seeds0
	r.seeds1 = v.Seeds1
	return nil
}
