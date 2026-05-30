package frostristretto255tss

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/KarpelesLab/tss-lib/v2/common"
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

// ValidateBasic returns nil if the Key is internally consistent. Checks:
//   - Xi, ShareID, GroupPublicKey are non-nil.
//   - GroupPublicKey is non-identity. (Element validity / prime-order
//     membership is guaranteed structurally: every Element in a Key is
//     produced by keygen arithmetic or DecodeElement, which cofactor-clears
//     and rejects malformed encodings — there is no separate on-curve flag to
//     re-check the way crypto.ECPoint exposes one.)
//   - Ks and BigXj have the same (non-zero) length.
//   - Every BigXj entry is non-nil.
//   - The local share is algebraically bound to its public commitment:
//     Xi · G == BigXj[i] for the slot where Ks[i] == ShareID.
//
// Like frosttss.Key.ValidateBasic, it does NOT verify the joint invariant
// Σ λ_i · BigXj[i] == GroupPublicKey, which depends on a chosen signing
// subset and is exercised at sign time. The local-share check is the
// strictest invariant enforceable statelessly on the Key in hand.
func (key *Key) ValidateBasic() error {
	if key == nil {
		return errors.New("frostristretto255tss: nil Key")
	}
	if key.Xi == nil {
		return errors.New("frostristretto255tss: Xi is nil")
	}
	if key.ShareID == nil {
		return errors.New("frostristretto255tss: ShareID is nil")
	}
	if key.GroupPublicKey == nil {
		return errors.New("frostristretto255tss: GroupPublicKey is nil")
	}
	if key.GroupPublicKey.IsIdentity() {
		return errors.New("frostristretto255tss: GroupPublicKey is the group identity")
	}
	if len(key.Ks) == 0 {
		return errors.New("frostristretto255tss: Ks is empty")
	}
	if len(key.Ks) != len(key.BigXj) {
		return fmt.Errorf("frostristretto255tss: Ks length %d != BigXj length %d", len(key.Ks), len(key.BigXj))
	}
	for j, p := range key.BigXj {
		if p == nil {
			return fmt.Errorf("frostristretto255tss: BigXj[%d] is nil", j)
		}
	}
	// Local share / commitment binding: Xi · G == BigXj[ShareID slot].
	myIdx := -1
	for j, kj := range key.Ks {
		if kj != nil && kj.Cmp(key.ShareID) == 0 {
			myIdx = j
			break
		}
	}
	if myIdx < 0 {
		return errors.New("frostristretto255tss: ShareID not found in Ks")
	}
	g := group.Ristretto255()
	expect := g.ScalarBaseMult(key.Xi)
	if !expect.Equal(key.BigXj[myIdx]) {
		return errors.New("frostristretto255tss: Xi · G does not equal BigXj[ShareID slot] — share / commitment binding broken")
	}
	return nil
}

// Zeroize overwrites the secret material in key — the Shamir share Xi — with
// zeros. The Key is unusable for signing or resharing after this call and is
// safe to discard.
//
// Best-effort like all in-process zeroization on a garbage-collected runtime:
// copies the GC has already relocated cannot be reached. Pair with process
// isolation, swap-off, and core-dump suppression for stronger erasure.
//
// Safe to call on a nil receiver (no-op). Note: subsets produced by
// SubsetForParties share the Xi pointer with their parent; zeroizing either
// clears both.
func (key *Key) Zeroize() {
	if key == nil {
		return
	}
	common.ZeroizeBigInt(key.Xi)
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
