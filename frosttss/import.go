package frosttss

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/KarpelesLab/edwards25519"

	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// ImportKey wraps a plain Ed25519 scalar as a trivial 1-of-1 frosttss.Key
// owned entirely by partyID. The returned Key is intended to be passed
// as the sole old-committee input to NewResharing so the full key can
// be split into a real t-of-n FROST(Ed25519) committee that preserves
// the joint public key:
//
//	importer := tss.NewPartyID("importer", "importer", uniqueKey)
//	oldKey, _ := frosttss.ImportKey(priv, importer)
//	rs, _ := frosttss.NewResharing(ctx, params, oldKey)
//	newKey := <-rs.Done   // newKey.GroupPublicKey == priv · G
//
// priv is the Ed25519 private scalar (interpreted modulo the curve
// order L); it must not be zero. partyID is the identity the sole
// old-committee party will use when running resharing — its KeyInt()
// becomes both the ShareID and the single entry of Ks in the returned
// Key.
//
// The returned Key's GroupPublicKey is priv · G on the Ed25519 curve,
// computed via the constant-time fixed-base table. Callers should
// check that value against whatever public key they already have
// before running the reshare so a mismatched private key is caught
// before committee messages start flowing.
//
// ⚠️ At the moment of import, one party holds the complete private
// scalar. This deliberately defeats the "key never existed whole" DKG
// property — only use ImportKey to migrate a pre-existing legacy key
// (e.g., a stock Ed25519 signing key, or an eddsatss threshold key
// whose secret was reconstructed by the importer). For brand-new
// keys, generate them with NewKeygen instead.
//
// Operational mitigation: run a `NewResharing` (or future `NewRefresh`
// when the package adds proactive refresh) on the new committee
// immediately, then destroy the importer's local state. The post-import
// rotation rotates per-party shares without changing the public key,
// so any residual memory of the importer's machine cannot be combined
// with post-rotation shares to reconstruct the secret.
func ImportKey(priv *big.Int, partyID *tss.PartyID) (*Key, error) {
	if priv == nil {
		return nil, errors.New("frosttss.ImportKey: priv is nil")
	}
	if partyID == nil {
		return nil, errors.New("frosttss.ImportKey: partyID is nil")
	}

	ec := edwards25519.Edwards()
	q := ec.Params().N

	xi := new(big.Int).Mod(priv, q)
	if xi.Sign() == 0 {
		return nil, errors.New("frosttss.ImportKey: priv is zero mod curve order")
	}

	// pub = xi · G via the constant-time edwards25519 fixed-base table.
	pub := crypto.CTScalarBaseMultEd25519(ec, xi)

	shareID := partyID.KeyInt()
	if shareID == nil || shareID.Sign() == 0 {
		return nil, errors.New("frosttss.ImportKey: partyID has empty KeyInt")
	}

	key := &Key{
		Xi:             xi,
		ShareID:        new(big.Int).Set(shareID),
		Ks:             []*big.Int{new(big.Int).Set(shareID)},
		BigXj:          []*crypto.ECPoint{pub},
		GroupPublicKey: pub,
	}
	// frosttss.Key has no ValidateBasic; do the basic sanity checks here.
	if key.GroupPublicKey == nil || !key.GroupPublicKey.ValidateBasic() {
		return nil, fmt.Errorf("frosttss.ImportKey: derived GroupPublicKey is not a valid curve point")
	}
	return key, nil
}
