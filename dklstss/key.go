package dklstss

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/crypto/ctmul"
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
//
// Peer authentication is OUTSIDE the scope of this package. The
// broker-driven Party state machines trust whatever tss.MessageBroker
// implementation the caller wires in to authenticate message origin;
// pinning peer identities, signing transport-level messages, and
// detecting equivocating peers are the implementor's job. Earlier
// revisions exposed Ed25519 "identity key" helpers (KeygenWithIdentities,
// SignTranscript, VerifyTranscript) that hinted at automatic
// identifiable abort — that surface was removed because the parties did
// not in fact use it.
type Key struct {
	Curve    elliptic.Curve `json:"-"`
	N        int            // total number of parties
	T        int            // threshold (signing requires T+1 parties)
	Idx      int            // 0-based index of this party in PartyIDs
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
	// Algebraic consistency: Xi · G must equal BigXj[Idx]. The
	// per-field range checks above don't catch a tampered Xi or a
	// mismatched BigXj entry — Load (and any in-memory mutation that
	// breaks the share/commitment binding) is otherwise silent, and a
	// signing run with the bad share emits a non-verifying signature
	// without surfacing the corruption (see byzantine_test.go's tampered
	// share test). Route the scalar mult through ctmul so callers that
	// trigger ValidateBasic in a timing-sensitive path do not leak Xi.
	if k.BigXj[k.Idx] == nil {
		return fmt.Errorf("dklstss: BigXj[Idx=%d] is nil", k.Idx)
	}
	expectXi := ctmul.ScalarBaseMult(k.Curve, k.Xi)
	if !expectXi.Equals(k.BigXj[k.Idx]) {
		return errors.New("dklstss: Xi · G does not equal BigXj[Idx] — share / public-commitment binding broken")
	}
	return nil
}
