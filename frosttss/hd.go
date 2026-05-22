// Copyright © 2026 KarpelesLab.

package frosttss

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/KarpelesLab/edwards25519"

	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/crypto/frost"
)

// ErrHardenedNotSupported is returned by DeriveChild when a path component
// is ≥ 2^31. Hardened derivation requires the raw parent private scalar in
// one place, which is fundamentally incompatible with threshold signing.
var ErrHardenedNotSupported = errors.New("frosttss: hardened derivation requires the raw private key and is not supported in threshold signing")

// HardenedKeyStart is the BIP32 hardened-index boundary. Path components
// at or above this value are rejected with ErrHardenedNotSupported.
const HardenedKeyStart uint32 = 0x80000000

// chainCodeDomain is the domain separator for the master chain code
// derivation. Distinct from the dklstss tag and from any standard
// (SLIP-0010, BIP32) so the resulting tree is unambiguously frosttss
// flavor — not interoperable with external Ed25519 HD schemes by design.
const chainCodeDomain = "FROST-Ed25519-chaincode-v1"

// derivationDomain is mixed into the per-step HMAC input alongside the
// parent public key and index, to domain-separate this derivation tree
// from chainCodeDomain and from any future variant.
const derivationDomain = "FROST-Ed25519-HD-v1"

// DeriveChainCode returns the canonical 32-byte chain code for a FROST
// Ed25519 group public key. The chain code is a deterministic function
// of the public key — descendants are publicly derivable by anyone who
// knows the parent public key and the path. This deliberately matches
// the dklstss design and is documented as a privacy property (see
// frosttss/doc.go).
//
// All parties of a keygen agree on the chain code because they agree
// on the joint public key.
func DeriveChainCode(pub *crypto.ECPoint) []byte {
	if pub == nil {
		return nil
	}
	h := sha256.New()
	h.Write([]byte(chainCodeDomain))
	h.Write(frost.EncodeElement(pub))
	return h.Sum(nil)
}

// DeriveChild walks a non-hardened derivation path from the receiver Key
// and returns:
//
//   - tweak: an integer in [0, L) such that child_private = parent_private +
//     tweak (mod L); equal to the accumulated IL across the path. A path
//     of length 0 returns tweak=0 and the parent unchanged.
//   - childPub: the derived child public key, equal to
//     parent_pub + tweak · G on Ed25519.
//   - childChainCode: the chain code at the path terminus (32 bytes).
//
// Path components ≥ 2^31 return ErrHardenedNotSupported. The Key must
// have a populated ChainCode (set by NewKeygen, NewResharing, or
// ImportKey in this package version; absent on legacy Version-1 Keys
// produced before HD support landed — call AttachChainCode first in
// that case).
//
// Derivation is deterministic and consumes no secret material: any
// party that knows the parent public key + chain code + path can
// compute the same childPub. tweak is derived from the same public
// inputs and is itself public.
//
// Note: this is a frosttss-flavor non-hardened tree analogous to
// dklstss's, not SLIP-0010 (which is hardened-only and incompatible
// with threshold signing). Signatures verify under standard Ed25519
// verifiers using childPub as the verification key.
func (k *Key) DeriveChild(path []uint32) (tweak *big.Int, childPub *crypto.ECPoint, childChainCode []byte, err error) {
	if k == nil {
		return nil, nil, nil, errors.New("frosttss: DeriveChild on nil Key")
	}
	if k.GroupPublicKey == nil {
		return nil, nil, nil, errors.New("frosttss: DeriveChild requires GroupPublicKey")
	}
	if len(k.ChainCode) != 32 {
		return nil, nil, nil, fmt.Errorf("frosttss: DeriveChild requires a 32-byte ChainCode (got %d) — Key produced before HD support? Call AttachChainCode", len(k.ChainCode))
	}
	for _, idx := range path {
		if idx >= HardenedKeyStart {
			return nil, nil, nil, ErrHardenedNotSupported
		}
	}

	ec := edwards25519.Edwards()
	L := ec.Params().N

	curCC := append([]byte(nil), k.ChainCode...)
	curPub := k.GroupPublicKey
	acc := new(big.Int)

	for _, idx := range path {
		il, childCC, err := deriveStep(curCC, curPub, idx, L)
		if err != nil {
			return nil, nil, nil, err
		}
		// childPub = curPub + il · G
		deltaG := crypto.CTScalarBaseMultEd25519(ec, il)
		next, err := curPub.Add(deltaG)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("frosttss: DeriveChild add at index %d: %w", idx, err)
		}
		if next.IsIdentity() {
			// Vanishingly unlikely on Ed25519 (would require tweak ≡ -parent
			// scalar mod L) but cryptographically possible; reject so the
			// caller can re-derive with a different index.
			return nil, nil, nil, fmt.Errorf("frosttss: DeriveChild at index %d produced identity point", idx)
		}
		curCC = childCC
		curPub = next
		acc.Add(acc, il)
		acc.Mod(acc, L)
	}

	return acc, curPub, curCC, nil
}

// deriveStep performs one HMAC-SHA512 step:
//
//	I = HMAC-SHA512(parentChainCode, derivationDomain || EncodeElement(parentPub) || index_be32)
//	IL = I[:32] reduced mod L — the additive tweak for this step
//	IR = I[32:] — the child chain code
//
// Note: on Ed25519, L ≈ 2^252.5, so a 256-bit HMAC half is ≥ L with
// probability ≈ 94%. Following BIP32 strictly (skip-on-overflow) would
// make the derivation depend on whether *implementations* happened to
// skip the same indices, which is a footgun. We instead reduce mod L
// unconditionally — a non-standard choice consistent with this being a
// frosttss-flavor tree distinct from SLIP-0010/BIP32 (which neither
// apply cleanly to Ed25519 in a threshold setting anyway). The reduction
// is lossy (~3.5 bits of entropy per step) but the residue is still
// cryptographically pseudorandom from the HMAC-SHA512 PRF assumption.
//
// The one remaining rejection is IL ≡ 0 mod L (probability 1/L ≈ 2^-252,
// astronomically unlikely): a zero tweak at any step would make that
// step a no-op and the child equal to the parent.
func deriveStep(parentChainCode []byte, parentPub *crypto.ECPoint, index uint32, L *big.Int) (il *big.Int, childChainCode []byte, err error) {
	if len(parentChainCode) != 32 {
		return nil, nil, fmt.Errorf("frosttss: deriveStep chain code length %d != 32", len(parentChainCode))
	}
	mac := hmac.New(sha512.New, parentChainCode)
	mac.Write([]byte(derivationDomain))
	mac.Write(frost.EncodeElement(parentPub))
	var idxBE [4]byte
	binary.BigEndian.PutUint32(idxBE[:], index)
	mac.Write(idxBE[:])
	I := mac.Sum(nil)

	// Big-endian interpretation, then unconditional reduction mod L.
	il = new(big.Int).SetBytes(I[:32])
	il.Mod(il, L)
	if il.Sign() == 0 {
		return nil, nil, fmt.Errorf("frosttss: derived IL ≡ 0 mod L at index %d (probability 2^-252; retry with a different index)", index)
	}
	return il, I[32:], nil
}

// AttachChainCode populates k.ChainCode for a legacy Key that was
// produced before HD support landed (KeyVersion 1). The chain code is
// a deterministic function of GroupPublicKey, so attaching it
// post-hoc is safe and produces the same value every party would have
// computed had they been on the HD-supporting version at keygen time.
//
// Returns an error only if the Key is nil or has no GroupPublicKey.
// Idempotent: re-running on a Key with a valid 32-byte ChainCode
// rewrites it to the canonical value (which should match what was
// already there).
func (k *Key) AttachChainCode() error {
	if k == nil {
		return errors.New("frosttss: AttachChainCode on nil Key")
	}
	if k.GroupPublicKey == nil {
		return errors.New("frosttss: AttachChainCode requires GroupPublicKey")
	}
	k.ChainCode = DeriveChainCode(k.GroupPublicKey)
	return nil
}
