package dklstss

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/KarpelesLab/secp256k1/ecckd"

	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/crypto/ckd"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// ErrHardenedNotSupported is returned by Derive* helpers when a BIP32
// path component is ≥ 2^31, which requires the raw parent private key and
// is therefore impossible in a threshold-signing setting.
var ErrHardenedNotSupported = errors.New("dklstss: hardened BIP32 derivation requires the raw private key and is not supported in threshold signing")

// DeriveChild walks a BIP32 non-hardened derivation path from the joint
// public key and returns:
//
//   - tweak: the integer to be added to the parent private key to obtain
//     the child private key (= IL accumulated across the path).
//   - childPub: the derived child public key (parent_pub + tweak · G).
//
// All inputs are public and the operation is deterministic; no party
// secret material is consumed.
func DeriveChild(key *Key, path []uint32) (*big.Int, *crypto.ECPoint, error) {
	if key == nil {
		return nil, nil, errors.New("dklstss: DeriveChild nil key")
	}
	for _, idx := range path {
		if idx >= ckd.HardenedKeyStart {
			return nil, nil, ErrHardenedNotSupported
		}
	}
	if len(path) == 0 {
		// Path of length 0: child = parent, tweak = 0.
		return new(big.Int), key.ECDSAPub, nil
	}
	ec := key.Curve
	q := ec.Params().N

	master := &ckd.ExtendedKey{
		PublicKey: ecdsa.PublicKey{
			Curve: ec,
			X:     key.ECDSAPub.X(),
			Y:     key.ECDSAPub.Y(),
		},
		Depth:      0,
		ChildIndex: 0,
		ChainCode:  append([]byte(nil), key.ChainCode...),
		ParentFP:   []byte{0, 0, 0, 0},
		Version:    ecckd.BitcoinMainnetPublic,
	}

	ilNum, childExt, err := ckd.DeriveChildKeyFromHierarchy(path, master, q, ec)
	if err != nil {
		return nil, nil, fmt.Errorf("dklstss: DeriveChild: %w", err)
	}
	childPub, err := crypto.NewECPoint(ec, childExt.PublicKey.X, childExt.PublicKey.Y)
	if err != nil {
		return nil, nil, fmt.Errorf("dklstss: DeriveChild child point: %w", err)
	}
	return new(big.Int).Mod(ilNum, q), childPub, nil
}

// DeriveAndSign derives the BIP32 child key for `path` and signs `hash`
// under that derived key. Returns the signature, the child public key
// (for the verifier), and an error if anything fails.
//
// Hardened indices in the path return ErrHardenedNotSupported.
//
// Child private shares are not persisted — derivation is re-run at every
// sign call. This matches the recommended threshold-HD pattern (avoids
// share-versioning bugs at the cost of a few HMAC operations per sign).
func DeriveAndSign(keys []*Key, signerIdx []int, path []uint32, hash []byte, rng io.Reader) (*Signature, *crypto.ECPoint, error) {
	if len(keys) == 0 {
		return nil, nil, errors.New("dklstss: DeriveAndSign requires at least one key")
	}
	tweak, childPub, err := DeriveChild(keys[0], path)
	if err != nil {
		return nil, nil, err
	}
	sig, err := SignWithTweak(keys, signerIdx, tweak, hash, rng)
	if err != nil {
		return nil, nil, err
	}
	return sig, childPub, nil
}

// To keep the dependency surface obvious, this package only uses tss for
// the curve registry. Future revisions may add helpers for paths.
var _ = tss.S256
