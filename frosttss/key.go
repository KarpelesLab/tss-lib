package frosttss

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// Key represents a single participant's share of a FROST(Ed25519, SHA-512) key.
//
// Xi is the secret scalar share s_i. ShareID is the participant's identifier
// (equal to the underlying PartyID.Key). Ks is the list of identifiers for all
// keygen participants, in keygen-party order. BigXj is the corresponding list
// of verification shares Y_j = s_j * G. GroupPublicKey is the Ed25519 public
// key Y = sum_i a_{i,0} * G — what an Ed25519 verifier uses to verify
// signatures produced by this key.
//
// Field naming mirrors eddsatss.Key (with EDDSAPub renamed to GroupPublicKey
// to reflect RFC 9591 terminology) so applications migrating from eddsatss
// have a familiar shape.
type Key struct {
	Xi, ShareID    *big.Int
	Ks             []*big.Int
	BigXj          []*crypto.ECPoint
	GroupPublicKey *crypto.ECPoint
}

// NewKey initializes a Key with slices pre-allocated for the given party count.
func NewKey(partyCount int) *Key {
	return &Key{
		Ks:    make([]*big.Int, partyCount),
		BigXj: make([]*crypto.ECPoint, partyCount),
	}
}

// SubsetForParties returns a new Key whose Ks and BigXj slices are reordered
// to match the given sorted party IDs. Parties are matched by ShareID (the Ks
// value stored by keygen, compared to PartyID.Key).
//
// This reindexing is required whenever the current party set is a strict
// subset of the parties that participated in keygen (for example, a t+1
// signing committee picked out of an n-party keygen, or resharing's old
// committee). Signing and resharing rounds index BigXj/Ks by current-party
// index, so they must be in current-party order.
//
// The returned Key shares Xi, ShareID, and GroupPublicKey with the receiver;
// only Ks and BigXj are rebuilt.
func (key *Key) SubsetForParties(sortedIDs tss.SortedPartyIDs) (*Key, error) {
	keysToIndices := make(map[string]int, len(key.Ks))
	for j, kj := range key.Ks {
		keysToIndices[hex.EncodeToString(kj.Bytes())] = j
	}
	subset := &Key{
		Xi:             key.Xi,
		ShareID:        key.ShareID,
		Ks:             make([]*big.Int, len(sortedIDs)),
		BigXj:          make([]*crypto.ECPoint, len(sortedIDs)),
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
