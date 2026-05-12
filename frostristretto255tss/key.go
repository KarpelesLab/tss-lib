package frostristretto255tss

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/KarpelesLab/tss-lib/v2/crypto/group"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// Key represents a single participant's share of a FROST(ristretto255) key.
//
// Xi is the secret scalar share s_i; ShareID is the participant's identifier
// (= PartyID.Key); Ks lists keygen identifiers in keygen-party order; BigXj
// lists per-party verification shares Y_j = s_j*G; GroupPublicKey is the
// FROST master public key Y = sum_i a_{i,0}*G.
//
// All group.Element fields belong to the Ristretto255 group (see
// crypto/group.Ristretto255()). Persisting a Key requires preserving the
// canonical 32-byte encodings of each Element (see Bytes/MarshalJSON below if
// needed — Phase 2 ships the type without JSON helpers; storage is the
// caller's responsibility).
type Key struct {
	Xi, ShareID    *big.Int
	Ks             []*big.Int
	BigXj          []group.Element
	GroupPublicKey group.Element
}

// NewKey initializes a Key with slices pre-allocated for the given party count.
func NewKey(partyCount int) *Key {
	return &Key{
		Ks:    make([]*big.Int, partyCount),
		BigXj: make([]group.Element, partyCount),
	}
}

// SubsetForParties returns a new Key whose Ks and BigXj slices are reordered
// to match the given sorted party IDs. Parties are matched by ShareID
// (compared to PartyID.Key).
func (key *Key) SubsetForParties(sortedIDs tss.SortedPartyIDs) (*Key, error) {
	keysToIndices := make(map[string]int, len(key.Ks))
	for j, kj := range key.Ks {
		keysToIndices[hex.EncodeToString(kj.Bytes())] = j
	}
	subset := &Key{
		Xi:             key.Xi,
		ShareID:        key.ShareID,
		Ks:             make([]*big.Int, len(sortedIDs)),
		BigXj:          make([]group.Element, len(sortedIDs)),
		GroupPublicKey: key.GroupPublicKey,
	}
	for j, id := range sortedIDs {
		savedIdx, ok := keysToIndices[hex.EncodeToString(id.Key)]
		if !ok {
			return nil, fmt.Errorf("SubsetForParties: party %s not found in keygen save data", id)
		}
		subset.Ks[j] = key.Ks[savedIdx]
		subset.BigXj[j] = key.BigXj[savedIdx]
	}
	return subset, nil
}
