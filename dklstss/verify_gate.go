package dklstss

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/crypto/ctmul"
)

// effectiveVerifyPub returns the public key under which a produced
// signature is expected to verify. For a plain signing run that is the
// joint key `pub`; with an HD tweak τ in effect the signature verifies
// under the child key pub + τ·G (the same point DeriveChild hands the
// verifier). tweak may be nil (no tweak) or zero.
func effectiveVerifyPub(pub *crypto.ECPoint, tweak *big.Int) (*crypto.ECPoint, error) {
	if pub == nil {
		return nil, errors.New("dklstss: nil public key for verification")
	}
	if tweak == nil {
		return pub, nil
	}
	q := pub.Curve().Params().N
	tw := new(big.Int).Mod(tweak, q)
	if tw.Sign() == 0 {
		return pub, nil
	}
	// child = pub + τ·G.
	twG := ctmul.ScalarBaseMult(pub.Curve(), tw)
	child, err := pub.Add(twG)
	if err != nil {
		return nil, fmt.Errorf("dklstss: tweaked pubkey: %w", err)
	}
	return child, nil
}

// verifyFinalSignature is the final self-verification gate shared by every
// signature-producing path. Before a (R,S) pair is returned to the caller
// it is checked against the (possibly tweaked) public key with the stdlib
// crypto/ecdsa verifier — the exact check the eventual relying party will
// run. A failure here means an upstream share, peer reveal, or aggregation
// step was corrupt or malicious and the "signature" would not verify; the
// path returns this error instead of a bogus signature.
//
// This is constant extra work and changes no wire format.
func verifyFinalSignature(pub *crypto.ECPoint, tweak *big.Int, hash []byte, r, s *big.Int) error {
	vpub, err := effectiveVerifyPub(pub, tweak)
	if err != nil {
		return err
	}
	ec := vpub.Curve()
	stdPub := &ecdsa.PublicKey{Curve: ec, X: vpub.X(), Y: vpub.Y()}
	if !ecdsa.Verify(stdPub, hash, r, s) {
		return errors.New("dklstss: assembled signature failed self-verification against the public key — corrupt share or malicious peer reveal")
	}
	return nil
}
