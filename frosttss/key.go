package frosttss

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/crypto/frost"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// KeyVersion is the schema version of a frosttss Key. Currently 1.
// Bump on incompatible field-layout changes; readers should refuse
// values they don't understand.
const KeyVersion uint32 = 1

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

// ValidateBasic returns nil if the Key is internally consistent. Checks:
//   - Xi, ShareID, GroupPublicKey are non-nil.
//   - Ks and BigXj have the same length (party count from keygen).
//   - GroupPublicKey is a valid Ed25519 element (on-curve, non-identity).
//   - Local share is algebraically bound to its public commitment:
//     Xi · G == BigXj[i] for the slot where Ks[i] == ShareID.
//
// Does NOT verify the joint invariant Σ λ_i · BigXj[i] == GroupPublicKey
// (the cross-share check), since computing Lagrange across all keygen
// parties requires a specific signing-subset choice and is exercised
// separately at sign time. The local-share check is the strictest
// invariant that can be enforced statelessly on the Key in hand.
func (k *Key) ValidateBasic() error {
	if k == nil {
		return errors.New("frosttss: nil Key")
	}
	if k.Xi == nil {
		return errors.New("frosttss: Xi is nil")
	}
	if k.ShareID == nil {
		return errors.New("frosttss: ShareID is nil")
	}
	if k.GroupPublicKey == nil || !k.GroupPublicKey.ValidateBasic() {
		return errors.New("frosttss: GroupPublicKey is not a valid curve point")
	}
	if k.GroupPublicKey.IsIdentity() {
		return errors.New("frosttss: GroupPublicKey is the curve identity")
	}
	if len(k.Ks) == 0 {
		return errors.New("frosttss: Ks is empty")
	}
	if len(k.Ks) != len(k.BigXj) {
		return fmt.Errorf("frosttss: Ks length %d != BigXj length %d", len(k.Ks), len(k.BigXj))
	}
	for j, p := range k.BigXj {
		if p == nil || !p.ValidateBasic() {
			return fmt.Errorf("frosttss: BigXj[%d] not a valid curve point", j)
		}
	}
	// Local share / commitment binding.
	myIdx := -1
	for j, kj := range k.Ks {
		if kj != nil && kj.Cmp(k.ShareID) == 0 {
			myIdx = j
			break
		}
	}
	if myIdx < 0 {
		return errors.New("frosttss: ShareID not found in Ks")
	}
	expect := crypto.CTScalarBaseMultEd25519(frost.EdwardsCurve(), k.Xi)
	if !expect.Equals(k.BigXj[myIdx]) {
		return errors.New("frosttss: Xi · G does not equal BigXj[ShareID slot] — share / commitment binding broken")
	}
	return nil
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

// Zeroize overwrites the secret material in k — the Shamir share Xi — with
// zeros. The Key is unusable for signing or resharing after this call and
// is safe to discard.
//
// Best-effort like all in-process zeroization on a garbage-collected
// runtime: copies that the GC has already relocated cannot be reached.
// Pair with process isolation, swap-off, and core-dump suppression for
// stronger erasure.
//
// Safe to call on a nil receiver (no-op). Note: subsets produced by
// SubsetForParties share the Xi pointer with their parent; zeroizing
// either clears both.
func (k *Key) Zeroize() {
	if k == nil {
		return
	}
	common.ZeroizeBigInt(k.Xi)
}
