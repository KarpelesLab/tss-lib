package dklstss

import (
	"bytes"
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
// v3 drops the identity-key fields (IdentityPub / IdentityPriv /
// PeerIdentityPubs) that v2 carried — peer authentication is outside
// the scope of this package and the broker-driven parties never
// actually used those fields. Load still accepts v1 and v2 payloads
// for backward compatibility; identity material in v2 payloads is
// silently discarded.
type keyWireFormat struct {
	// Format is a string magic field that disambiguates this wire
	// format from any other JSON document a caller might accidentally
	// feed to Load. Required for v4+; ignored for v1/v2/v3 loads.
	Format string `json:"format,omitempty"`

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

	// v1/v2 legacy fields, present on disk for compatibility but ignored
	// on load. Encoded as json.RawMessage so they round-trip transparently
	// on a re-save (the loader strips them; Save never emits them on v3).
	LegacyIdentityPub      json.RawMessage `json:"identity_pub,omitempty"`
	LegacyIdentityPriv     json.RawMessage `json:"identity_priv,omitempty"`
	LegacyPeerIdentityPubs json.RawMessage `json:"peer_identity_pubs,omitempty"`
}

// keyFormatMagic is the string written to the Format field of v4+
// keyWireFormat documents. Load rejects v4+ payloads that don't match.
const keyFormatMagic = "dklstss-key"

type pairOTWire struct {
	AsAlice *otext.ExtReceiver `json:"as_alice"`
	AsBob   *otext.ExtSender   `json:"as_bob"`
}

// KeyWireVersion is the format-version constant emitted by Save and
// required by Load. Bump on incompatible changes.
//
// v3 dropped the v2 identity-key fields. v4 added the Format magic
// field and a strict curve-identity check at Load. Load still accepts
// v1, v2, and v3 payloads (the Format check is skipped for those).
const KeyWireVersion uint32 = 4

// Save serializes the Key to JSON and writes to w. Round-trips with
// Load. Includes the OT extension setup state (which makes a Key
// roughly ~50KB for n=3 to ~500KB for n=10).
//
// IMPORTANT: the produced JSON is UNENCRYPTED. The OT extension state
// and the secret share Xi are written in cleartext. Callers are
// responsible for transport-level confidentiality and integrity (AEAD
// or detached MAC) over the saved bytes — Save does not.
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
		Format:    keyFormatMagic,
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
	// v1, v2, v3, and v4 share the same on-disk layout for the protocol
	// fields. v2 added optional Ed25519 "identity" fields that were never
	// actually consumed by the broker-driven parties; v3 stops emitting
	// them but still accepts v1/v2 payloads. v4 adds the Format magic
	// field and the strict curve check below.
	if v.Version != KeyWireVersion && v.Version != 1 && v.Version != 2 && v.Version != 3 {
		return nil, fmt.Errorf("dklstss: Load version mismatch (got %d, expected one of 1, 2, 3, %d)", v.Version, KeyWireVersion)
	}
	if v.Version >= 4 && v.Format != keyFormatMagic {
		// v4+ payloads must carry the magic string; this disambiguates
		// a stray JSON document from a real dklstss key blob.
		return nil, fmt.Errorf("dklstss: Load format magic mismatch (got %q, expected %q)", v.Format, keyFormatMagic)
	}
	curve, ok := tss.GetCurveByName(tss.CurveName(v.Curve))
	if !ok {
		return nil, fmt.Errorf("dklstss: Load unknown curve %q", v.Curve)
	}
	// Enforce that the loaded curve is secp256k1. dklstss is secp256k1-
	// only; a payload claiming a different curve is either corrupt or
	// from a different protocol. Fail fast with a clear error rather
	// than letting ValidateBasic surface an opaque algebraic mismatch
	// further downstream.
	if !tss.SameCurve(curve, tss.S256()) {
		return nil, fmt.Errorf("dklstss: Load curve %q is not secp256k1; dklstss is secp256k1-only", v.Curve)
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
	// Cross-check ChainCode against the canonical hash of the loaded
	// ECDSAPub. A tampered ChainCode on disk would otherwise cause every
	// party's HD derivation to diverge silently — the key signs correctly
	// but child keys are wrong.
	want := deriveChainCode(k.ECDSAPub)
	if !bytes.Equal(k.ChainCode, want) {
		return nil, errors.New("dklstss: Load ChainCode does not match canonical hash of ECDSAPub")
	}
	// Cross-check the joint public key against the sum of BigXj weighted
	// by Lagrange coefficients at 0. A tampered ECDSAPub on disk would
	// otherwise yield a Key that signs valid signatures under the wrong
	// public key — invisible to the loader, dangerous to the verifier
	// downstream.
	if err := verifyPubMatchesBigXj(k); err != nil {
		return nil, err
	}
	return k, nil
}

// verifyPubMatchesBigXj asserts that ECDSAPub equals Σ λ_j · BigXj[j] over
// any T+1 party subset. We use the first T+1 parties for determinism.
// Internally consistent keys produced by Keygen / Refresh / Reshare /
// Load(round-trip) satisfy this; tampered loads do not.
func verifyPubMatchesBigXj(k *Key) error {
	if k.T+1 > len(k.BigXj) {
		return fmt.Errorf("dklstss: Load not enough BigXj (%d) for threshold T+1=%d", len(k.BigXj), k.T+1)
	}
	q := k.Curve.Params().N
	ids := make([]*big.Int, k.T+1)
	for i := 0; i < k.T+1; i++ {
		ids[i] = k.PartyIDs[i].KeyInt()
	}
	var acc *crypto.ECPoint
	for i := 0; i < k.T+1; i++ {
		lam, err := lagrangeCoefficient(q, ids, i)
		if err != nil {
			return fmt.Errorf("dklstss: Load lagrange[%d]: %w", i, err)
		}
		term := k.BigXj[i].ScalarMult(lam)
		if acc == nil {
			acc = term
			continue
		}
		next, err := acc.Add(term)
		if err != nil {
			return fmt.Errorf("dklstss: Load aggregate[%d]: %w", i, err)
		}
		acc = next
	}
	if !acc.Equals(k.ECDSAPub) {
		return errors.New("dklstss: Load ECDSAPub does not match Σ λ_j · BigXj[j] — key was tampered with on disk")
	}
	return nil
}
