package dklstss

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/crypto/ctmul"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// ImportKey wraps a plain secp256k1 ECDSA private key as a trivial 1-of-1
// dklstss.Key owned entirely by partyID. The returned Key is intended to
// be passed as the sole old-committee input to Reshare / NewResharing,
// so the full key can be split into a real t-of-n committee that
// preserves the joint public key:
//
//	importer := tss.NewPartyID("importer", "importer", uniqueKey)
//	oldKey, _ := dklstss.ImportKey(priv, importer)
//	newKeys, _ := dklstss.Reshare(
//	    []*dklstss.Key{oldKey}, []int{0},
//	    newPartyIDs, newThreshold, rand.Reader)
//	// All newKeys[i].ECDSAPub equal the original priv.PublicKey.
//
// priv supplies both the private scalar (priv.D) and the curve, which
// MUST be secp256k1. partyID is the identity the sole old-committee
// party will use when running resharing — its KeyInt() becomes both
// the PartyIDs[0] entry and the BigXj indexing.
//
// The returned Key has:
//
//   - N = 1, T = 0, Idx = 0
//   - Xi = priv.D mod q
//   - BigXj[0] = ECDSAPub = priv.D · G (computed via the CT primitive)
//   - OT = []*PairOTState{nil} — the self-pair has no OT-extension state;
//     Reshare establishes fresh per-pair OT among the new committee, so
//     no OT material survives from this import.
//   - ChainCode = canonical SHA-256("DKLS23-chaincode-v1" || pub.X || 0 ||
//     pub.Y), so BIP32 non-hardened derivation against any external HD
//     wallet that knows (pub, chainCode) matches the resharded committee.
//
// ⚠️ At the moment of import, one party holds the complete private
// scalar. This deliberately defeats the "key never existed whole" DKG
// property — only use ImportKey to migrate a pre-existing legacy key
// (e.g., a single-signer ECDSA wallet, or a GG18-threshold key whose
// secret was reconstructed by the importer). For brand-new keys, use
// dklstss.Keygen or dklstss.NewKeygen instead.
//
// Operational mitigation: run a `Refresh` on the resharded new committee
// immediately, then destroy the importer's local state (zero the Xi,
// drop the goroutine). The post-import Refresh rotates per-party
// shares + OT-extension state without changing the public key, so any
// residual memory of the importer's machine cannot be combined with
// post-refresh shares to reconstruct the secret.
func ImportKey(priv *ecdsa.PrivateKey, partyID *tss.PartyID) (*Key, error) {
	if priv == nil {
		return nil, errors.New("dklstss.ImportKey: priv is nil")
	}
	if priv.D == nil {
		return nil, errors.New("dklstss.ImportKey: priv.D is nil")
	}
	if priv.Curve == nil {
		return nil, errors.New("dklstss.ImportKey: priv.Curve is nil")
	}
	if !tss.SameCurve(priv.Curve, tss.S256()) {
		return nil, fmt.Errorf("dklstss.ImportKey: requires secp256k1, got %T", priv.Curve)
	}
	if partyID == nil {
		return nil, errors.New("dklstss.ImportKey: partyID is nil")
	}

	ec := tss.S256()
	q := ec.Params().N

	xi := new(big.Int).Mod(priv.D, q)
	if xi.Sign() == 0 {
		return nil, errors.New("dklstss.ImportKey: priv.D is zero mod curve order")
	}

	// Compute pub = xi · G via the constant-time scalar mult — the input
	// is the imported secret, so the same CT discipline that protects
	// signing nonces applies here.
	pub := ctmul.ScalarBaseMult(ec, xi)

	// Cross-check against priv.PublicKey if supplied. Catches the
	// "wrong private key for this pub" caller bug before any committee
	// messages flow.
	if priv.PublicKey.X != nil && priv.PublicKey.Y != nil {
		declared, err := crypto.NewECPoint(ec, priv.PublicKey.X, priv.PublicKey.Y)
		if err != nil {
			return nil, fmt.Errorf("dklstss.ImportKey: declared public key is not on the curve: %w", err)
		}
		if !declared.Equals(pub) {
			return nil, errors.New("dklstss.ImportKey: priv.PublicKey does not match priv.D · G")
		}
	}

	shareID := partyID.KeyInt()
	if shareID == nil || shareID.Sign() == 0 {
		return nil, errors.New("dklstss.ImportKey: partyID has empty KeyInt")
	}

	key := &Key{
		Curve:     ec,
		N:         1,
		T:         0,
		Idx:       0,
		PartyIDs:  tss.SortedPartyIDs{partyID},
		Xi:        xi,
		BigXj:     []*crypto.ECPoint{pub},
		ECDSAPub:  pub,
		OT:        []*PairOTState{nil}, // self-pair: no OT state required
		ChainCode: deriveChainCode(pub),
	}
	if err := key.ValidateBasic(); err != nil {
		return nil, fmt.Errorf("dklstss.ImportKey: produced invalid Key: %w", err)
	}
	return key, nil
}
