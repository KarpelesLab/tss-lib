package dklstss

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/crypto/ot/otext"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// keyWireFormat is the on-disk JSON layout for a dklstss Key. Version
// tagged so future schema changes can be migrated without ambiguity.
//
// Identity material is included (added in v2 of the wire format): the
// long-term Ed25519 keys are required by KeygenWithIdentities-built
// keys, and dropping them on Save would silently strip the ability to
// sign and verify protocol transcripts after a restart. Loading a v1
// payload still works — the identity fields are simply absent.
type keyWireFormat struct {
	Version          uint32              `json:"version"`
	Curve            string              `json:"curve"`
	N                int                 `json:"n"`
	T                int                 `json:"t"`
	Idx              int                 `json:"idx"`
	PartyIDs         tss.SortedPartyIDs  `json:"party_ids"`
	Xi               *big.Int            `json:"xi"`
	BigXj            []*crypto.ECPoint   `json:"big_xj"`
	ECDSAPub         *crypto.ECPoint     `json:"ecdsa_pub"`
	OT               []*pairOTWire       `json:"ot"`
	ChainCode        []byte              `json:"chain_code"`
	IdentityPub      ed25519.PublicKey   `json:"identity_pub,omitempty"`
	IdentityPriv     ed25519.PrivateKey  `json:"identity_priv,omitempty"`
	PeerIdentityPubs []ed25519.PublicKey `json:"peer_identity_pubs,omitempty"`
}

type pairOTWire struct {
	AsAlice *otext.ExtReceiver `json:"as_alice"`
	AsBob   *otext.ExtSender   `json:"as_bob"`
}

// KeyWireVersion is the format-version constant emitted by Save and
// required by Load. Bump on incompatible changes.
//
// v2: added optional IdentityPub / IdentityPriv / PeerIdentityPubs.
// Loading a v1 payload still works — the loader accepts v1 and treats
// the identity fields as absent.
const KeyWireVersion uint32 = 2

// Save serializes the Key to JSON and writes to w. Round-trips with
// Load. Includes the OT extension setup state (which makes a Key
// roughly ~50KB for n=3 to ~500KB for n=10).
func (k *Key) Save(w io.Writer) error {
	if k == nil {
		return errors.New("dklstss: Save nil key")
	}
	if err := k.ValidateBasic(); err != nil {
		return fmt.Errorf("dklstss: Save key fails ValidateBasic: %w", err)
	}
	curveName, ok := tss.GetCurveName(k.Curve)
	if !ok {
		return fmt.Errorf("dklstss: Save unknown curve %T", k.Curve)
	}
	ot := make([]*pairOTWire, len(k.OT))
	for i, p := range k.OT {
		if p == nil {
			ot[i] = nil
			continue
		}
		ot[i] = &pairOTWire{AsAlice: p.AsAlice, AsBob: p.AsBob}
	}
	out := &keyWireFormat{
		Version:          KeyWireVersion,
		Curve:            string(curveName),
		N:                k.N,
		T:                k.T,
		Idx:              k.Idx,
		PartyIDs:         k.PartyIDs,
		Xi:               k.Xi,
		BigXj:            k.BigXj,
		ECDSAPub:         k.ECDSAPub,
		OT:               ot,
		ChainCode:        k.ChainCode,
		IdentityPub:      k.IdentityPub,
		IdentityPriv:     k.IdentityPriv,
		PeerIdentityPubs: k.PeerIdentityPubs,
	}
	enc := json.NewEncoder(w)
	return enc.Encode(out)
}

// Load reads a Key previously produced by Save. Returns an error on
// version mismatch or schema corruption.
func Load(r io.Reader) (*Key, error) {
	var v keyWireFormat
	dec := json.NewDecoder(r)
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("dklstss: Load decode: %w", err)
	}
	// v1 and v2 share the same on-disk layout for everything except the
	// optional identity fields, which JSON simply omits when absent.
	if v.Version != KeyWireVersion && v.Version != 1 {
		return nil, fmt.Errorf("dklstss: Load version mismatch (got %d, expected %d or 1)", v.Version, KeyWireVersion)
	}
	curve, ok := tss.GetCurveByName(tss.CurveName(v.Curve))
	if !ok {
		return nil, fmt.Errorf("dklstss: Load unknown curve %q", v.Curve)
	}
	ot := make([]*PairOTState, len(v.OT))
	for i, p := range v.OT {
		if p == nil {
			ot[i] = nil
			continue
		}
		ot[i] = &PairOTState{AsAlice: p.AsAlice, AsBob: p.AsBob}
	}
	// ECPoint serializers may not have set the curve; fix that up by
	// rebinding every point to the loaded curve.
	if v.ECDSAPub != nil {
		v.ECDSAPub.SetCurve(curve)
	}
	for i := range v.BigXj {
		if v.BigXj[i] != nil {
			v.BigXj[i].SetCurve(curve)
		}
	}
	k := &Key{
		Curve:            curve,
		N:                v.N,
		T:                v.T,
		Idx:              v.Idx,
		PartyIDs:         v.PartyIDs,
		Xi:               v.Xi,
		BigXj:            v.BigXj,
		ECDSAPub:         v.ECDSAPub,
		OT:               ot,
		ChainCode:        v.ChainCode,
		IdentityPub:      v.IdentityPub,
		IdentityPriv:     v.IdentityPriv,
		PeerIdentityPubs: v.PeerIdentityPubs,
	}
	if err := k.ValidateBasic(); err != nil {
		return nil, fmt.Errorf("dklstss: Load loaded key fails ValidateBasic: %w", err)
	}
	return k, nil
}
