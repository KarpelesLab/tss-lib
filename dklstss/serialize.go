package dklstss

import (
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
type keyWireFormat struct {
	Version   uint32             `json:"version"`
	Curve     string             `json:"curve"`
	N         int                `json:"n"`
	T         int                `json:"t"`
	Idx       int                `json:"idx"`
	PartyIDs  tss.SortedPartyIDs `json:"party_ids"`
	Xi        *big.Int           `json:"xi"`
	BigXj     []*crypto.ECPoint  `json:"big_xj"`
	ECDSAPub  *crypto.ECPoint    `json:"ecdsa_pub"`
	OT        []*pairOTWire      `json:"ot"`
	ChainCode []byte             `json:"chain_code"`
}

type pairOTWire struct {
	AsAlice *otext.ExtReceiver `json:"as_alice"`
	AsBob   *otext.ExtSender   `json:"as_bob"`
}

// KeyWireVersion is the format-version constant emitted by Save and
// required by Load. Bump on incompatible changes.
const KeyWireVersion uint32 = 1

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
		Version:   KeyWireVersion,
		Curve:     string(curveName),
		N:         k.N,
		T:         k.T,
		Idx:       k.Idx,
		PartyIDs:  k.PartyIDs,
		Xi:        k.Xi,
		BigXj:     k.BigXj,
		ECDSAPub:  k.ECDSAPub,
		OT:        ot,
		ChainCode: k.ChainCode,
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
	if v.Version != KeyWireVersion {
		return nil, fmt.Errorf("dklstss: Load version mismatch (got %d, expected %d)", v.Version, KeyWireVersion)
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
		Curve:     curve,
		N:         v.N,
		T:         v.T,
		Idx:       v.Idx,
		PartyIDs:  v.PartyIDs,
		Xi:        v.Xi,
		BigXj:     v.BigXj,
		ECDSAPub:  v.ECDSAPub,
		OT:        ot,
		ChainCode: v.ChainCode,
	}
	if err := k.ValidateBasic(); err != nil {
		return nil, fmt.Errorf("dklstss: Load loaded key fails ValidateBasic: %w", err)
	}
	return k, nil
}
