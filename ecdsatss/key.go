package ecdsatss

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/crypto/paillier"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// Key represents the data for a local share of key.
//
// Key is JSON-compatible with the old ecdsa/keygen.LocalPartySaveData struct,
// so existing serialized key data can be deserialized directly into this type.
type Key struct {
	LocalPreParams
	LocalSecrets

	Ks                []*big.Int // original indexes (ki in signing preparation phase)
	NTildej, H1j, H2j []*big.Int // // n-tilde, h1, h2 for range proofs
	// public keys (Xj = uj*G for each Pj)
	BigXj       []*crypto.ECPoint     // Xj
	PaillierPKs []*paillier.PublicKey // pkj
	// used for test assertions (may be discarded)
	ECDSAPub *crypto.ECPoint // y
}

// NewKey creates a new Key with all slice fields initialized for the given party count.
func NewKey(partyCount int) *Key {
	return &Key{
		Ks:          make([]*big.Int, partyCount),
		NTildej:     make([]*big.Int, partyCount),
		H1j:         make([]*big.Int, partyCount),
		H2j:         make([]*big.Int, partyCount),
		BigXj:       make([]*crypto.ECPoint, partyCount),
		PaillierPKs: make([]*paillier.PublicKey, partyCount),
	}
}

// LocalPreParams contains the pre-computed Paillier key and safe prime parameters for a party.
type LocalPreParams struct {
	PaillierSK                           *paillier.PrivateKey // ski
	NTildei, H1i, H2i, Alpha, Beta, P, Q *big.Int
}

// LocalSecrets holds the secret share data that is not shared with other parties.
type LocalSecrets struct {
	// secret fields (not shared, but stored locally)
	Xi, ShareID *big.Int // xi, kj
}

// Validate returns true if the essential pre-parameters (Paillier key, NTilde, H1, H2) are non-nil.
func (preParams LocalPreParams) Validate() bool {
	return preParams.PaillierSK != nil &&
		preParams.NTildei != nil &&
		preParams.H1i != nil &&
		preParams.H2i != nil
}

// ValidateWithProof returns true if the pre-parameters and all proof-related fields (Alpha, Beta, P, Q) are non-nil.
func (preParams LocalPreParams) ValidateWithProof() bool {
	return preParams.Validate() &&
		preParams.PaillierSK.P != nil &&
		preParams.PaillierSK.Q != nil &&
		preParams.Alpha != nil &&
		preParams.Beta != nil &&
		preParams.P != nil &&
		preParams.Q != nil
}

// SubsetForParties returns a new Key whose per-party slice fields (Ks, NTildej, H1j, H2j,
// BigXj, PaillierPKs) are reordered to match the given sorted party IDs. Parties are matched
// by their ShareID — i.e. the Ks value stored by keygen, compared to PartyID.Key.
//
// This reindexing is required whenever the current party set is a strict subset of the
// parties that participated in keygen (for example, a t+1 signing committee picked out of
// an n-party keygen, or resharing's old committee). The signing and resharing rounds index
// these slices by the current-party index, so the slices must be in current-party order.
//
// The returned Key shares LocalPreParams, LocalSecrets, and ECDSAPub with the receiver;
// only the per-party slices are rebuilt.
func (key *Key) SubsetForParties(sortedIDs tss.SortedPartyIDs) (*Key, error) {
	keysToIndices := make(map[string]int, len(key.Ks))
	for j, kj := range key.Ks {
		keysToIndices[hex.EncodeToString(kj.Bytes())] = j
	}
	subset := NewKey(len(sortedIDs))
	subset.LocalPreParams = key.LocalPreParams
	subset.LocalSecrets = key.LocalSecrets
	subset.ECDSAPub = key.ECDSAPub
	for j, id := range sortedIDs {
		savedIdx, ok := keysToIndices[hex.EncodeToString(id.Key)]
		if !ok {
			return nil, fmt.Errorf("SubsetForParties: party %s not found in keygen save data", id)
		}
		subset.Ks[j] = key.Ks[savedIdx]
		subset.NTildej[j] = key.NTildej[savedIdx]
		subset.H1j[j] = key.H1j[savedIdx]
		subset.H2j[j] = key.H2j[savedIdx]
		subset.BigXj[j] = key.BigXj[savedIdx]
		subset.PaillierPKs[j] = key.PaillierPKs[savedIdx]
	}
	if err := subset.validateConsistency(); err != nil {
		return nil, fmt.Errorf("SubsetForParties: %w", err)
	}
	return subset, nil
}

// validateConsistency re-verifies, on a Key loaded from (possibly untrusted)
// serialized save data, that the per-party public shares BigXj are mutually
// consistent with the stored ECDSAPub.
//
// It checks that:
//   - ECDSAPub is non-nil and on-curve;
//   - every BigXj[j] is non-nil and on-curve;
//   - the Lagrange interpolation in the exponent of the BigXj over the
//     participant Ks, evaluated at x=0, reconstructs ECDSAPub (i.e. f(0)·G).
//
// A single interpolation is performed. This guards the signing/resharing entry
// paths against a tampered or corrupted key whose public shares no longer agree
// with the group public key (which would otherwise surface only as a silently
// invalid signature). The local-share check (Xi·G == BigXj[localIdx]) is done by
// callers that know the local party index.
func (key *Key) validateConsistency() error {
	ec := tss.S256()
	if key.ECDSAPub != nil {
		ec = key.ECDSAPub.Curve()
	}
	if key.ECDSAPub == nil || !key.ECDSAPub.ValidateBasic() {
		return fmt.Errorf("ECDSAPub is nil or not on curve")
	}
	n := len(key.Ks)
	if n == 0 || len(key.BigXj) != n {
		return fmt.Errorf("inconsistent key slice lengths (Ks=%d, BigXj=%d)", len(key.Ks), len(key.BigXj))
	}
	for j := 0; j < n; j++ {
		if key.Ks[j] == nil {
			return fmt.Errorf("Ks[%d] is nil", j)
		}
		if key.BigXj[j] == nil || !key.BigXj[j].ValidateBasic() {
			return fmt.Errorf("BigXj[%d] is nil or not on curve", j)
		}
	}

	// Lagrange interpolation in the exponent at x=0:
	//   reconstructed = Σ_j λ_j · BigXj[j],  λ_j = Π_{c≠j} Ks[c]/(Ks[c]-Ks[j]).
	modQ := common.ModInt(ec.Params().N)
	var reconstructed *crypto.ECPoint
	for j := 0; j < n; j++ {
		lambda := big.NewInt(1)
		for c := 0; c < n; c++ {
			if c == j {
				continue
			}
			if key.Ks[c].Cmp(key.Ks[j]) == 0 {
				return fmt.Errorf("duplicate share id at indexes %d and %d", j, c)
			}
			num := key.Ks[c]
			den := new(big.Int).Sub(key.Ks[c], key.Ks[j])
			lambda = modQ.Mul(lambda, modQ.Mul(num, modQ.ModInverse(den)))
		}
		term := key.BigXj[j].ScalarMult(lambda)
		if reconstructed == nil {
			reconstructed = term
		} else {
			var err error
			reconstructed, err = reconstructed.Add(term)
			if err != nil {
				return fmt.Errorf("interpolation failed: %w", err)
			}
		}
	}
	if reconstructed == nil || !reconstructed.Equals(key.ECDSAPub) {
		return fmt.Errorf("BigXj do not interpolate to ECDSAPub")
	}
	return nil
}
