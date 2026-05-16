package dklstss

import (
	"crypto/ed25519"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/crypto/ot/otext"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// Key is the per-party output of dklstss DKG. It contains both public
// material (the joint public key, every party's commitment) and private
// material (this party's Shamir share, per-pair OT extension state).
//
// A Key is safe to JSON-serialize for persistence: Save (in serialize.go)
// emits the OT extension setup state alongside the key share, and Load
// reconstructs both. Re-use across crash-restart is safe because the
// per-call PRG derivation in crypto/ot/otext binds every Extend
// invocation to its caller-supplied sid (see crypto/ot/otext/prg.go),
// and dklstss/signing_party.go mixes each signing's random K_i values
// into that sid so consecutive signings can never collide on it.
// Identity material (Ed25519 long-term keys for transcript signing) is
// also persisted by Save when KeygenWithIdentities was used.
type Key struct {
	Curve    elliptic.Curve   `json:"-"`
	N        int              // total number of parties
	T        int              // threshold (signing requires T+1 parties)
	Idx      int              // 0-based index of this party in PartyIDs
	PartyIDs tss.SortedPartyIDs

	// Xi is this party's Shamir secret share, evaluated at id_Idx.
	Xi *big.Int

	// BigXj[i] = x_i · G is the public commitment to each party's share,
	// used for verifying signing-round commitments and as additional
	// integrity material.
	BigXj []*crypto.ECPoint

	// ECDSAPub is the joint public key X = (Σ x_j λ_j) · G evaluated at 0
	// — i.e., the actual ECDSA public key under which signatures verify.
	ECDSAPub *crypto.ECPoint

	// OT is the per-pair OT extension state established during DKG. OT[i]
	// is nil for i == Idx (no self-pair). Each entry holds the two
	// directions of OT extension needed by ΠMul: the local party plays
	// Alice (OT-Ext-Receiver) when it owns the multiplication's α input,
	// and Bob (OT-Ext-Sender) when it owns β.
	OT []*PairOTState

	// ChainCode is the BIP32 chain code at the master (= dklstss DKG
	// output) level. Used for non-hardened HD derivation. Deterministic
	// function of the joint public key; identical across all parties.
	ChainCode []byte

	// IdentityPub is the local party's long-term identity public key,
	// used to sign outgoing protocol messages so the receiver can prove
	// to a third party which peer originated a deviating message.
	// Populated by KeygenWithIdentities; nil when Keygen is called
	// without identities (the synchronous in-process API doesn't need
	// them, but the broker-driven API will).
	IdentityPub ed25519.PublicKey

	// IdentityPriv is the local party's long-term identity private key.
	// Treat as sensitive material; zero on disposal. Populated only by
	// KeygenWithIdentities.
	IdentityPriv ed25519.PrivateKey

	// PeerIdentityPubs[i] is the public identity key of party i (across
	// the full committee). Required for verifying signed transcripts
	// during identifiable-abort flows.
	PeerIdentityPubs []ed25519.PublicKey
}

// PairOTState bundles the two directions of OT extension between the
// local party and one peer. Both directions are established at DKG time
// and reused (under distinct sids) across many signings.
type PairOTState struct {
	// AsAlice is the OT-extension receiver state used when the local
	// party is Alice in a ΠMul invocation with this peer.
	AsAlice *otext.ExtReceiver

	// AsBob is the OT-extension sender state used when the local party
	// is Bob in a ΠMul invocation with this peer.
	AsBob *otext.ExtSender
}

// Signature is the ECDSA output of a dklstss signing run. The (R, S) pair
// is the canonical ECDSA signature; it verifies against (*Key).ECDSAPub
// using standard crypto/ecdsa.Verify when R, S are passed as big.Ints.
//
// V is the public recovery byte (0/1) for parity-of-Y, useful for
// Bitcoin/Ethereum-style signature serialization. Callers that don't
// need recovery may ignore it.
type Signature struct {
	R *big.Int
	S *big.Int
	V byte
}

// ValidateBasic returns nil if the Key is internally consistent.
func (k *Key) ValidateBasic() error {
	if k == nil {
		return errors.New("dklstss: nil Key")
	}
	if k.Curve == nil {
		return errors.New("dklstss: Key.Curve is nil")
	}
	if k.N <= 0 || k.T < 0 || k.T >= k.N {
		return fmt.Errorf("dklstss: invalid (N=%d, T=%d)", k.N, k.T)
	}
	if k.Idx < 0 || k.Idx >= k.N {
		return fmt.Errorf("dklstss: Idx=%d out of range [0,%d)", k.Idx, k.N)
	}
	if len(k.PartyIDs) != k.N {
		return fmt.Errorf("dklstss: PartyIDs has %d entries, expected %d", len(k.PartyIDs), k.N)
	}
	if k.Xi == nil {
		return errors.New("dklstss: Xi is nil")
	}
	if len(k.BigXj) != k.N {
		return fmt.Errorf("dklstss: BigXj has %d entries, expected %d", len(k.BigXj), k.N)
	}
	if k.ECDSAPub == nil || !k.ECDSAPub.ValidateBasic() {
		return errors.New("dklstss: ECDSAPub is not a valid curve point")
	}
	if len(k.OT) != k.N {
		return fmt.Errorf("dklstss: OT slice has %d entries, expected %d", len(k.OT), k.N)
	}
	for i, st := range k.OT {
		if i == k.Idx {
			if st != nil {
				return fmt.Errorf("dklstss: OT[%d] (self) must be nil", i)
			}
			continue
		}
		if st == nil || st.AsAlice == nil || st.AsBob == nil {
			return fmt.Errorf("dklstss: OT[%d] missing direction(s)", i)
		}
	}
	if len(k.ChainCode) != 32 {
		return fmt.Errorf("dklstss: ChainCode must be 32 bytes, got %d", len(k.ChainCode))
	}
	return nil
}
