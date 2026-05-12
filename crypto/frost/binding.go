package frost

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"sort"

	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/crypto"
)

// NonceCommitment is one signer's pair of nonce commitments (D_i, E_i) per
// RFC 9591 §5.1. D_i is the hiding commitment d_i*G; E_i is the binding
// commitment e_i*G. Identifier is the signer's scalar identifier (PartyID.Key).
type NonceCommitment struct {
	Identifier *big.Int
	Hiding     *crypto.ECPoint // D_i = d_i*G
	Binding    *crypto.ECPoint // E_i = e_i*G
}

// EncodeCommitmentList serializes a sorted-by-identifier commitment list per
// RFC 9591 §4.3. The output is the concatenation of (identifier || D_i || E_i)
// for each signer, identifiers encoded as 32-byte LE scalars and elements as
// 32-byte canonical Ed25519 encodings.
//
// The list is sorted by identifier before encoding so all signers compute the
// same bytes regardless of receive order.
func EncodeCommitmentList(commitments []NonceCommitment) []byte {
	sorted := make([]NonceCommitment, len(commitments))
	copy(sorted, commitments)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Identifier.Cmp(sorted[j].Identifier) < 0
	})

	var buf bytes.Buffer
	for _, c := range sorted {
		buf.Write(EncodeScalar(c.Identifier))
		buf.Write(EncodeElement(c.Hiding))
		buf.Write(EncodeElement(c.Binding))
	}
	return buf.Bytes()
}

// ComputeBindingFactors derives the per-signer binding factor rho_i for every
// signer in commitments. The list returned is in the same order as the input.
// Implements RFC 9591 §4.4.
func ComputeBindingFactors(msg []byte, commitments []NonceCommitment) map[string]*big.Int {
	encodedMsg := H4(msg)
	encodedCommitments := EncodeCommitmentList(commitments)
	encodedCommitmentHash := H5(encodedCommitments)

	rhoInputPrefix := make([]byte, 0, len(encodedMsg)+len(encodedCommitmentHash))
	rhoInputPrefix = append(rhoInputPrefix, encodedMsg...)
	rhoInputPrefix = append(rhoInputPrefix, encodedCommitmentHash...)

	out := make(map[string]*big.Int, len(commitments))
	for _, c := range commitments {
		input := append(append([]byte{}, rhoInputPrefix...), EncodeScalar(c.Identifier)...)
		out[c.Identifier.String()] = H1(input)
	}
	return out
}

// ComputeGroupCommitment aggregates per-signer commitments into the group
// commitment R = sum_i (D_i + rho_i * E_i) per RFC 9591 §4.5. Returns an error
// if any addition or scalar multiplication produces an invalid point.
func ComputeGroupCommitment(commitments []NonceCommitment, bindingFactors map[string]*big.Int) (*crypto.ECPoint, error) {
	if len(commitments) == 0 {
		return nil, errors.New("frost: empty commitments list")
	}
	var R *crypto.ECPoint
	for _, c := range commitments {
		rho, ok := bindingFactors[c.Identifier.String()]
		if !ok {
			return nil, fmt.Errorf("frost: missing binding factor for identifier %s", c.Identifier)
		}
		// term_i = D_i + rho_i * E_i
		rhoE := c.Binding.ScalarMult(rho)
		term, err := c.Hiding.Add(rhoE)
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

// ComputeGroupChallenge computes c = H2(R_enc || A_enc || msg) where R_enc and
// A_enc are 32-byte canonical Ed25519 encodings. This is byte-identical to the
// Ed25519 challenge per RFC 8032, so the resulting signature verifies under
// any Ed25519 verifier.
func ComputeGroupChallenge(R, groupPubKey *crypto.ECPoint, msg []byte) *big.Int {
	var input []byte
	input = append(input, EncodeElement(R)...)
	input = append(input, EncodeElement(groupPubKey)...)
	input = append(input, msg...)
	return H2(input)
}

// LagrangeCoefficient returns lambda_i for participant identifier id within
// the signing set L, computed mod L (group order). Uses the standard Shamir
// formula lambda_i = prod_{j != i} x_j / (x_j - x_i). All inputs are taken mod
// L. Panics on duplicate identifiers (caller's bug).
func LagrangeCoefficient(id *big.Int, signers []*big.Int) *big.Int {
	modQ := common.ModInt(L)
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
