package frost

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"sort"

	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/crypto/group"
)

// NonceCommitment is one signer's pair of nonce commitments (D_i, E_i) per
// RFC 9591 §5.1, generalized over an arbitrary group. D_i is the hiding
// commitment d_i*G; E_i is the binding commitment e_i*G.
//
// For Ed25519 callers that already hold *crypto.ECPoint values, use
// NonceCommitmentFromECPoint to construct without going through bytes.
type NonceCommitment struct {
	Identifier *big.Int
	Hiding     group.Element // D_i = d_i*G
	Binding    group.Element // E_i = e_i*G
}

// NonceCommitmentFromECPoint builds a NonceCommitment from a *crypto.ECPoint
// pair (Ed25519 representation). The points are assumed to be in the
// prime-order subgroup.
func NonceCommitmentFromECPoint(id *big.Int, hiding, binding *crypto.ECPoint) NonceCommitment {
	return NonceCommitment{
		Identifier: id,
		Hiding:     group.AdaptECPoint(hiding),
		Binding:    group.AdaptECPoint(binding),
	}
}

// EncodeCommitmentList serializes a sorted-by-identifier commitment list per
// RFC 9591 §4.3. Identifiers are encoded via cs.Group().EncodeScalar so
// callers don't have to worry about per-ciphersuite scalar widths.
func EncodeCommitmentList(cs Ciphersuite, commitments []NonceCommitment) []byte {
	sorted := make([]NonceCommitment, len(commitments))
	copy(sorted, commitments)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Identifier.Cmp(sorted[j].Identifier) < 0
	})

	g := cs.Group()
	var buf bytes.Buffer
	for _, c := range sorted {
		buf.Write(g.EncodeScalar(c.Identifier))
		buf.Write(c.Hiding.Bytes())
		buf.Write(c.Binding.Bytes())
	}
	return buf.Bytes()
}

// ComputeBindingFactors derives the per-signer binding factor rho_i for every
// signer in commitments. Implements RFC 9591 §4.4.
func ComputeBindingFactors(cs Ciphersuite, msg []byte, commitments []NonceCommitment) map[string]*big.Int {
	encodedMsg := cs.H4(msg)
	encodedCommitments := EncodeCommitmentList(cs, commitments)
	encodedCommitmentHash := cs.H5(encodedCommitments)

	rhoInputPrefix := make([]byte, 0, len(encodedMsg)+len(encodedCommitmentHash))
	rhoInputPrefix = append(rhoInputPrefix, encodedMsg...)
	rhoInputPrefix = append(rhoInputPrefix, encodedCommitmentHash...)

	g := cs.Group()
	out := make(map[string]*big.Int, len(commitments))
	for _, c := range commitments {
		input := append(append([]byte{}, rhoInputPrefix...), g.EncodeScalar(c.Identifier)...)
		out[c.Identifier.String()] = cs.H1(input)
	}
	return out
}

// ComputeGroupCommitment aggregates per-signer commitments into the group
// commitment R = sum_i (D_i + rho_i * E_i) per RFC 9591 §4.5.
func ComputeGroupCommitment(commitments []NonceCommitment, bindingFactors map[string]*big.Int) (group.Element, error) {
	if len(commitments) == 0 {
		return nil, errors.New("frost: empty commitments list")
	}
	var R group.Element
	for _, c := range commitments {
		rho, ok := bindingFactors[c.Identifier.String()]
		if !ok {
			return nil, fmt.Errorf("frost: missing binding factor for identifier %s", c.Identifier)
		}
		term, err := c.Hiding.Add(c.Binding.ScalarMult(rho))
		if err != nil {
			return nil, fmt.Errorf("frost: adding D_i + rho*E_i: %w", err)
		}
		if R == nil {
			R = term
			continue
		}
		R, err = R.Add(term)
		if err != nil {
			return nil, fmt.Errorf("frost: accumulating R: %w", err)
		}
	}
	return R, nil
}

// ComputeGroupChallenge computes c = H2(R_enc || A_enc || msg) where R_enc
// and A_enc are the ciphersuite's canonical encodings of the group commitment
// and the group public key. For Ed25519 the result is byte-identical to the
// Ed25519 challenge per RFC 8032.
func ComputeGroupChallenge(cs Ciphersuite, R, groupPubKey group.Element, msg []byte) *big.Int {
	var input []byte
	input = append(input, R.Bytes()...)
	input = append(input, groupPubKey.Bytes()...)
	input = append(input, msg...)
	return cs.H2(input)
}

// LagrangeCoefficient returns lambda_i for participant identifier id within
// the signing set, computed mod the group order. Uses the standard Shamir
// formula. Panics on duplicate identifiers.
func LagrangeCoefficient(cs Ciphersuite, id *big.Int, signers []*big.Int) *big.Int {
	modQ := common.ModInt(cs.Group().Order())
	lambda := big.NewInt(1)
	for _, xj := range signers {
		if xj.Cmp(id) == 0 {
			continue
		}
		num := xj
		den := new(big.Int).Sub(xj, id)
		denInv := modQ.ModInverse(den)
		if denInv == nil {
			panic("frost: duplicate identifier in signing set")
		}
		lambda = modQ.Mul(lambda, modQ.Mul(num, denInv))
	}
	return lambda
}
