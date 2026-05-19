// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Feldman VSS, based on Paul Feldman, 1987., A practical scheme for non-interactive verifiable secret sharing.
// In Foundations of Computer Science, 1987., 28th Annual Symposium on. IEEE, 427–43
//

package vss

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/KarpelesLab/edwards25519"
	"github.com/KarpelesLab/secp256k1"

	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/crypto/ctmul"
)

type (
	// Share represents a single Shamir secret share with its threshold, party ID, and share value.
	Share struct {
		Threshold int
		ID,       // xi
		Share *big.Int // Sigma i
	}

	// Vs is a slice of EC points representing the Feldman VSS commitments (v0..vt).
	Vs []*crypto.ECPoint // v0..vt

	// Shares is a slice of secret shares.
	Shares []*Share
)

var (
	// ErrNumSharesBelowThreshold is returned when there are fewer shares than required by the threshold.
	ErrNumSharesBelowThreshold = fmt.Errorf("not enough shares to satisfy the threshold")

	zero = big.NewInt(0)
	one  = big.NewInt(1)
)

// Check share ids of Shamir's Secret Sharing, return error if duplicate or 0 value found
func CheckIndexes(ec elliptic.Curve, indexes []*big.Int) ([]*big.Int, error) {
	visited := make(map[string]struct{})
	for _, v := range indexes {
		vMod := new(big.Int).Mod(v, ec.Params().N)
		if vMod.Cmp(zero) == 0 {
			return nil, errors.New("party index should not be 0")
		}
		vModStr := vMod.String()
		if _, ok := visited[vModStr]; ok {
			return nil, fmt.Errorf("duplicate indexes %s", vModStr)
		}
		visited[vModStr] = struct{}{}
	}
	return indexes, nil
}

// Returns a new array of secret shares created by Shamir's Secret Sharing Algorithm,
// requiring a minimum number of shares to recreate, of length shares, from the input secret
func Create(ec elliptic.Curve, threshold int, secret *big.Int, indexes []*big.Int, rand io.Reader) (Vs, Shares, error) {
	if secret == nil || indexes == nil {
		return nil, nil, fmt.Errorf("vss secret or indexes == nil: %v %v", secret, indexes)
	}
	if threshold < 1 {
		return nil, nil, errors.New("vss threshold < 1")
	}

	ids, err := CheckIndexes(ec, indexes)
	if err != nil {
		return nil, nil, err
	}

	num := len(indexes)
	if num < threshold {
		return nil, nil, ErrNumSharesBelowThreshold
	}

	poly := samplePolynomial(ec, threshold, secret, rand)

	v := make(Vs, len(poly))
	for i, ai := range poly {
		// v[0] = secret · G is the dealer's contribution to the joint
		// public key — leaking bits of `secret` via timing recovers a
		// share of the joint secret. The other v[i] are commitments
		// to random masking coefficients but go through the same CT
		// path for code uniformity (the perf delta is sub-millisecond
		// over a typical t+1 ≤ 7 invocations).
		v[i] = ctScalarBaseMult(ec, ai)
	}

	shares := make(Shares, num)
	for i := 0; i < num; i++ {
		share := evaluatePolynomial(ec, threshold, poly, ids[i])
		shares[i] = &Share{Threshold: threshold, ID: ids[i], Share: share}
	}
	return v, shares, nil
}

// Verify checks the share against the Feldman VSS commitments to ensure it is consistent.
func (share *Share) Verify(ec elliptic.Curve, threshold int, vs Vs) bool {
	if share.Threshold != threshold || vs == nil || len(vs) != threshold+1 {
		return false
	}
	var err error
	modQ := common.ModInt(ec.Params().N)
	v, t := vs[0], one // YRO : we need to have our accumulator outside of the loop
	for j := 1; j <= threshold; j++ {
		// t = k_i^j
		t = modQ.Mul(t, share.ID)
		// v = v * v_j^t
		vjt := vs[j].SetCurve(ec).ScalarMult(t)
		v, err = v.SetCurve(ec).Add(vjt)
		if err != nil {
			return false
		}
	}
	sigmaGi := crypto.ScalarBaseMult(ec, share.Share)
	return sigmaGi.Equals(v)
}

// ReConstruct recovers the secret from the shares using Lagrange interpolation.
func (shares Shares) ReConstruct(ec elliptic.Curve) (secret *big.Int, err error) {
	if shares == nil || len(shares) == 0 {
		return nil, errors.New("no shares provided")
	}
	if shares[0].Threshold > len(shares) {
		return nil, ErrNumSharesBelowThreshold
	}
	modN := common.ModInt(ec.Params().N)

	// x coords
	xs := make([]*big.Int, 0)
	for _, share := range shares {
		xs = append(xs, share.ID)
	}

	secret = zero
	for i, share := range shares {
		times := one
		for j := 0; j < len(xs); j++ {
			if j == i {
				continue
			}
			sub := modN.Sub(xs[j], share.ID)
			subInv := modN.ModInverse(sub)
			if subInv == nil {
				return nil, fmt.Errorf("modular inverse does not exist (duplicate share IDs at index %d and %d)", i, j)
			}
			div := modN.Mul(xs[j], subInv)
			times = modN.Mul(times, div)
		}

		fTimes := modN.Mul(share.Share, times)
		secret = modN.Add(secret, fTimes)
	}

	return secret, nil
}

func samplePolynomial(ec elliptic.Curve, threshold int, secret *big.Int, rand io.Reader) []*big.Int {
	q := ec.Params().N
	v := make([]*big.Int, threshold+1)
	v[0] = secret
	for i := 1; i <= threshold; i++ {
		ai := common.GetRandomPositiveInt(rand, q)
		v[i] = ai
	}
	return v
}

// ctScalarBaseMult is the curve-aware constant-time-or-best-effort
// scalar-base multiplication used by VSS commitment construction. The
// dealer's secret polynomial coefficients pass through here; routing
// them through Go's standard `crypto.ScalarBaseMult` (which is not
// documented as constant-time on either secp256k1 or Ed25519) was the
// audit finding addressed by this dispatcher.
//
// Routing:
//   - secp256k1: ctmul.ScalarBaseMult (Montgomery ladder with Z-
//     randomization and 64-bit scalar blinding).
//   - Ed25519:   crypto.CTScalarBaseMultEd25519 (edwards25519 fixed-
//     base table).
//   - any other curve: falls back to crypto.ScalarBaseMult. VSS is used
//     today only with these two curves, so the fallback is dead in the
//     current codebase but keeps the function total.
func ctScalarBaseMult(ec elliptic.Curve, k *big.Int) *crypto.ECPoint {
	if ec == secp256k1.S256() {
		return ctmul.ScalarBaseMult(ec, k)
	}
	if ec == edwards25519.Edwards() {
		return crypto.CTScalarBaseMultEd25519(ec, k)
	}
	return crypto.ScalarBaseMult(ec, k)
}

// Evauluates a polynomial with coefficients such that:
// evaluatePolynomial([a, b, c, d], x):
//
//	returns a + bx + cx^2 + dx^3
func evaluatePolynomial(ec elliptic.Curve, threshold int, v []*big.Int, id *big.Int) (result *big.Int) {
	q := ec.Params().N
	modQ := common.ModInt(q)
	result = new(big.Int).Set(v[0])
	X := big.NewInt(int64(1))
	for i := 1; i <= threshold; i++ {
		ai := v[i]
		X = modQ.Mul(X, id)
		aiXi := new(big.Int).Mul(ai, X)
		result = modQ.Add(result, aiXi)
	}
	return
}
