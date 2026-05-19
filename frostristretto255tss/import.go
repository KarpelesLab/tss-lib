package frostristretto255tss

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/KarpelesLab/tss-lib/v2/crypto/group"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// ImportKey wraps a plain Ristretto255 scalar as a trivial 1-of-1
// frostristretto255tss.Key owned entirely by partyID. The returned Key
// is intended to be passed as the sole old-committee input to
// NewResharing so the full key can be split into a real t-of-n
// FROST(ristretto255) committee that preserves the joint public key.
//
// priv is the Ristretto255 private scalar (interpreted modulo the
// group order, which equals the Ed25519 curve order L); it must not be
// zero. partyID is the identity the sole old-committee party will use
// when running resharing — its KeyInt() becomes both the ShareID and
// the single entry of Ks in the returned Key.
//
// The returned Key's GroupPublicKey is priv · G computed via the
// upstream `github.com/gtank/ristretto255` ScalarBaseMult, which is
// constant-time at the library level (the only CT scalar-mult path
// the upstream package exposes).
//
// ⚠️ At the moment of import, one party holds the complete private
// scalar. This deliberately defeats the "key never existed whole" DKG
// property — only use ImportKey to migrate a pre-existing legacy key.
// For brand-new keys, use NewKeygen instead.
//
// Operational mitigation: run NewResharing immediately to split into a
// real committee, then destroy the importer's local state.
func ImportKey(priv *big.Int, partyID *tss.PartyID) (*Key, error) {
	if priv == nil {
		return nil, errors.New("frostristretto255tss.ImportKey: priv is nil")
	}
	if partyID == nil {
		return nil, errors.New("frostristretto255tss.ImportKey: partyID is nil")
	}

	g := group.Ristretto255()
	q := g.Order()

	xi := new(big.Int).Mod(priv, q)
	if xi.Sign() == 0 {
		return nil, errors.New("frostristretto255tss.ImportKey: priv is zero mod group order")
	}

	pub := g.ScalarBaseMult(xi)

	shareID := partyID.KeyInt()
	if shareID == nil || shareID.Sign() == 0 {
		return nil, errors.New("frostristretto255tss.ImportKey: partyID has empty KeyInt")
	}

	key := &Key{
		Xi:             xi,
		ShareID:        new(big.Int).Set(shareID),
		Ks:             []*big.Int{new(big.Int).Set(shareID)},
		BigXj:          []group.Element{pub},
		GroupPublicKey: pub,
	}
	if key.GroupPublicKey == nil {
		return nil, fmt.Errorf("frostristretto255tss.ImportKey: derived GroupPublicKey is nil")
	}
	return key, nil
}
