// Copyright © 2019-2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package modproof

import (
	"fmt"
	"io"
	"math/big"

	"github.com/KarpelesLab/tss-lib/v2/common"
)

const (
	// Iterations is the number of iterations used in the modular proof for soundness.
	Iterations = 80
	// ProofModBytesParts is the number of byte parts in a serialized ProofMod.
	ProofModBytesParts = Iterations*2 + 3
)

var one = big.NewInt(1)

type (
	// ProofMod is a zero-knowledge proof that N is a product of two primes (Paillier-Blum modulus proof).
	ProofMod struct {
		W *big.Int
		X [Iterations]*big.Int
		A *big.Int
		B *big.Int
		Z [Iterations]*big.Int
	}
)

// isQuadraticResidue checks Euler criterion
func isQuadraticResidue(X, N *big.Int) bool {
	return big.Jacobi(X, N) == 1
}

// NewProof generates a new modular proof that N = P*Q where P and Q are safe primes.
func NewProof(Session []byte, N, P, Q *big.Int, rand io.Reader) (*ProofMod, error) {
	Phi := new(big.Int).Mul(new(big.Int).Sub(P, one), new(big.Int).Sub(Q, one))
	// Fig 16.1
	W := common.GetRandomQuadraticNonResidue(rand, N)

	// Fig 16.2
	Y := [Iterations]*big.Int{}
	for i := range Y {
		ei := common.SHA512_256i_TAGGED(Session, append([]*big.Int{W, N}, Y[:i]...)...)
		Y[i] = common.RejectionSample(N, ei)
	}

	// Fig 16.3
	modN, modPhi := common.ModInt(N), common.ModInt(Phi)
	invN := new(big.Int).ModInverse(N, Phi)
	if invN == nil {
		return nil, fmt.Errorf("modular inverse of N mod Phi does not exist")
	}
	X := [Iterations]*big.Int{}
	// Fix bitLen of A and B
	A := new(big.Int).Lsh(one, Iterations)
	B := new(big.Int).Lsh(one, Iterations)
	Z := [Iterations]*big.Int{}

	// for fourth-root
	expo := new(big.Int).Add(Phi, big.NewInt(4))
	expo = new(big.Int).Rsh(expo, 3)
	expo = modPhi.Mul(expo, expo)

	for i := range Y {
		for j := 0; j < 4; j++ {
			a, b := j&1, j&2>>1
			Yi := new(big.Int).SetBytes(Y[i].Bytes())
			if a > 0 {
				Yi = modN.Mul(big.NewInt(-1), Yi)
			}
			if b > 0 {
				Yi = modN.Mul(W, Yi)
			}
			if isQuadraticResidue(Yi, P) && isQuadraticResidue(Yi, Q) {
				Xi := modN.Exp(Yi, expo)
				Zi := modN.Exp(Y[i], invN)
				X[i], Z[i] = Xi, Zi
				A.SetBit(A, i, uint(a))
				B.SetBit(B, i, uint(b))
				break
			}
		}
	}

	// For a non-Blum N (P or Q not ≡ 3 mod 4) one of the 4 (a, b) sign
	// combinations may fail to be a QR mod both P and Q, leaving X[i]/Z[i] nil.
	// Bytes() would then serialize them as empty, shipping a silently-dead
	// proof. Reject such moduli explicitly so callers learn the key material is
	// invalid.
	for i := range Y {
		if X[i] == nil || Z[i] == nil {
			return nil, fmt.Errorf("modproof: NewProof: modulus is not a Blum integer (no QR found at index %d)", i)
		}
	}

	pf := &ProofMod{W: W, X: X, A: A, B: B, Z: Z}
	return pf, nil
}

// NewProofFromBytes reconstructs a ProofMod from a slice of byte slices.
func NewProofFromBytes(bzs [][]byte) (*ProofMod, error) {
	if !common.NonEmptyMultiBytes(bzs, ProofModBytesParts) {
		return nil, fmt.Errorf("expected %d byte parts to construct ProofMod", ProofModBytesParts)
	}
	bis := make([]*big.Int, len(bzs))
	for i := range bis {
		bis[i] = new(big.Int).SetBytes(bzs[i])
	}

	X := [Iterations]*big.Int{}
	copy(X[:], bis[1:(Iterations+1)])

	Z := [Iterations]*big.Int{}
	copy(Z[:], bis[(Iterations+3):])

	return &ProofMod{
		W: bis[0],
		X: X,
		A: bis[Iterations+1],
		B: bis[Iterations+2],
		Z: Z,
	}, nil
}

// Verify checks whether the modular proof is valid for the given modulus N.
func (pf *ProofMod) Verify(Session []byte, N *big.Int) bool {
	if pf == nil || !pf.ValidateBasic() {
		return false
	}
	// TODO: add basic properties checker
	if isQuadraticResidue(pf.W, N) {
		return false
	}
	if pf.W.Sign() != 1 || pf.W.Cmp(N) != -1 {
		return false
	}
	// W must be a unit mod N (gcd(W, N) == 1). Without this check, a W sharing
	// a factor with N has Jacobi(W, N) == 0 and passes the "not a quadratic
	// residue" test above, breaking the soundness assumption that W is a unit /
	// quadratic non-residue.
	if new(big.Int).GCD(nil, nil, pf.W, N).Cmp(one) != 0 {
		return false
	}
	for i := range pf.Z {
		if pf.Z[i].Sign() != 1 || pf.Z[i].Cmp(N) != -1 {
			return false
		}
	}
	for i := range pf.X {
		if pf.X[i].Sign() != 1 || pf.X[i].Cmp(N) != -1 {
			return false
		}
	}
	if pf.A.BitLen() != Iterations+1 {
		return false
	}
	if pf.B.BitLen() != Iterations+1 {
		return false
	}

	modN := common.ModInt(N)
	Y := [Iterations]*big.Int{}
	for i := range Y {
		ei := common.SHA512_256i_TAGGED(Session, append([]*big.Int{pf.W, N}, Y[:i]...)...)
		Y[i] = common.RejectionSample(N, ei)
	}

	// Fig 16. Verification
	{
		if N.Bit(0) == 0 || N.ProbablyPrime(30) {
			return false
		}
	}

	chs := make(chan bool, Iterations*2)
	for i := 0; i < Iterations; i++ {
		go func(i int) {
			left := modN.Exp(pf.Z[i], N)
			if left.Cmp(Y[i]) != 0 {
				chs <- false
				return
			}
			chs <- true
		}(i)

		go func(i int) {
			a := pf.A.Bit(i)
			b := pf.B.Bit(i)
			if a != 0 && a != 1 {
				chs <- false
				return
			}
			if b != 0 && b != 1 {
				chs <- false
				return
			}
			left := modN.Exp(pf.X[i], big.NewInt(4))
			right := Y[i]
			if a > 0 {
				right = modN.Mul(big.NewInt(-1), right)
			}
			if b > 0 {
				right = modN.Mul(pf.W, right)
			}
			if left.Cmp(right) != 0 {
				chs <- false
				return
			}
			chs <- true
		}(i)
	}

	for i := 0; i < Iterations*2; i++ {
		if !<-chs {
			return false
		}
	}

	return true
}

// ValidateBasic checks that all fields of the proof are non-nil.
func (pf *ProofMod) ValidateBasic() bool {
	if pf.W == nil {
		return false
	}
	for i := range pf.X {
		if pf.X[i] == nil {
			return false
		}
	}
	if pf.A == nil {
		return false
	}
	if pf.B == nil {
		return false
	}
	for i := range pf.Z {
		if pf.Z[i] == nil {
			return false
		}
	}
	return true
}

// Bytes serializes the proof into a fixed-size array of byte slices.
func (pf *ProofMod) Bytes() [ProofModBytesParts][]byte {
	bzs := [ProofModBytesParts][]byte{}
	bzs[0] = pf.W.Bytes()
	for i := range pf.X {
		if pf.X[i] != nil {
			bzs[1+i] = pf.X[i].Bytes()
		}
	}
	bzs[Iterations+1] = pf.A.Bytes()
	bzs[Iterations+2] = pf.B.Bytes()
	for i := range pf.Z {
		if pf.Z[i] != nil {
			bzs[Iterations+3+i] = pf.Z[i].Bytes()
		}
	}
	return bzs
}
