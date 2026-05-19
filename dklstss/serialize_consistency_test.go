package dklstss

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/crypto"
)

// TestLoadRejectsTamperedChainCode verifies that Load fails if the
// ChainCode field has been modified after Save. Without the canonical-
// hash cross-check, a tampered ChainCode silently survives Load and
// every HD-derived child key diverges across the committee.
func TestLoadRejectsTamperedChainCode(t *testing.T) {
	keys, err := Keygen(3, 1, genPartyIDs(3), rand.Reader)
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, keys[0].Save(&buf))

	// Tamper the JSON: flip one byte of chain_code.
	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(buf.Bytes(), &raw))
	var cc []byte
	require.NoError(t, json.Unmarshal(raw["chain_code"], &cc))
	cc[0] ^= 0x01
	tampered, err := json.Marshal(cc)
	require.NoError(t, err)
	raw["chain_code"] = tampered
	doc, err := json.Marshal(raw)
	require.NoError(t, err)

	_, err = Load(bytes.NewReader(doc))
	require.Error(t, err, "tampered ChainCode must be rejected by Load")
	require.Contains(t, err.Error(), "ChainCode")
}

// TestLoadRejectsTamperedECDSAPub verifies that Load fails if ECDSAPub
// has been changed to a different curve point (regardless of whether
// the point is on the curve). The Σ λ_j·BigXj[j] cross-check catches it.
func TestLoadRejectsTamperedECDSAPub(t *testing.T) {
	keys, err := Keygen(3, 1, genPartyIDs(3), rand.Reader)
	require.NoError(t, err)

	// Serialize key[0], then swap its ECDSAPub for an unrelated point.
	tampered := *keys[0]
	tampered.ECDSAPub = crypto.ScalarBaseMult(keys[0].Curve, big.NewInt(7))
	// ChainCode must still match the new (fake) pub or the chain-code
	// check would catch it first; recompute against the fake.
	tampered.ChainCode = deriveChainCode(tampered.ECDSAPub)

	// Save would refuse via ValidateBasic (Xi·G != BigXj[Idx] check) for
	// real tampering. Skip Save: serialize the wire form directly.
	wire := &keyWireFormat{
		Version:   KeyWireVersion,
		Curve:     "secp256k1",
		N:         tampered.N,
		T:         tampered.T,
		Idx:       tampered.Idx,
		PartyIDs:  tampered.PartyIDs,
		Xi:        tampered.Xi,
		BigXj:     tampered.BigXj,
		ECDSAPub:  tampered.ECDSAPub,
		ChainCode: tampered.ChainCode,
	}
	// Skip OT serialization for this corruption test — the per-pair OT
	// slice must still exist for ValidateBasic length checks.
	wire.OT = make([]*pairOTWire, tampered.N)
	for i, p := range keys[0].OT {
		if p == nil {
			continue
		}
		wire.OT[i] = &pairOTWire{AsAlice: p.AsAlice, AsBob: p.AsBob}
	}
	enc, err := json.Marshal(wire)
	require.NoError(t, err)

	_, err = Load(bytes.NewReader(enc))
	require.Error(t, err, "tampered ECDSAPub must be rejected by Load")
	// The error should be the pub-mismatch one or the ValidateBasic one.
	// Either is acceptable defense; what matters is the call fails.
}

// TestLoadAcceptsHonestRoundTrip is a regression sanity-check that the
// new cross-checks don't break the honest path. Already covered indirectly
// by TestKeySaveLoadRoundTrip; keep this one as a focused minimum case.
func TestLoadAcceptsHonestRoundTrip(t *testing.T) {
	keys, err := Keygen(3, 1, genPartyIDs(3), rand.Reader)
	require.NoError(t, err)

	for i, k := range keys {
		var buf bytes.Buffer
		require.NoError(t, k.Save(&buf), "save %d", i)
		loaded, err := Load(&buf)
		require.NoError(t, err, "load %d", i)
		require.True(t, loaded.ECDSAPub.Equals(k.ECDSAPub))
	}
}
