// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package schnorr

import (
	"errors"
	"io"
	"math/big"

	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/crypto/ctmul"
)

type (
	// ZKProof is a Schnorr zero-knowledge proof of knowledge of the discrete logarithm.
	ZKProof struct {
		Alpha *crypto.ECPoint
		T     *big.Int
	}

	// ZKVProof is a Schnorr zero-knowledge proof of knowledge of s and l such that V = R^s * g^l.
	ZKVProof struct {
		Alpha *crypto.ECPoint
		T, U  *big.Int
	}
)

// NewZKProof constructs a new Schnorr ZK proof of knowledge of the discrete logarithm (GG18Spec Fig. 16).
//
// CT discipline: `a` (the commitment randomness) and `x` (the secret
// discrete log being proven) are both routed through constant-time
// primitives. The commitment α = a·G uses ctmul (the curve-aware CT
// dispatcher that picks the Montgomery ladder for secp256k1 and the
// edwards25519 fixed-base table for Ed25519), and the response
// t = a + c·x mod q uses CTScalarMulAddModN. The previous form leaked
// bits of `a` via timing on Go's stdlib `ScalarBaseMult` and bits of
// `x` via Go's non-CT `math/big.Int.Mul` — both are usable channels for
// witness extraction when callers (base-OT trapdoor, VSS secret
// coefficient, signing nonce) supply a secret as `x`.
func NewZKProof(Session []byte, x *big.Int, X *crypto.ECPoint, rand io.Reader) (*ZKProof, error) {
	if x == nil || X == nil || !X.ValidateBasic() {
		return nil, errors.New("ZKProof constructor received nil or invalid value(s)")
	}
	ec := X.Curve()
	ecParams := ec.Params()
	q := ecParams.N
	g := crypto.NewECPointNoCurveCheck(ec, ecParams.Gx, ecParams.Gy) // already on the curve.

	a := common.GetRandomPositiveInt(rand, q)
	alpha := ctmul.ScalarBaseMultWithRand(ec, a, rand)

	var c *big.Int
	{
		cHash := common.SHA512_256i_TAGGED(Session, X.X(), X.Y(), g.X(), g.Y(), alpha.X(), alpha.Y())
		c = common.RejectionSample(q, cHash)
	}
	// t = c·x + a mod q via the CT mod-mul-add primitive.
	t := crypto.CTScalarMulAddModN(ec, c, x, a)

	return &ZKProof{Alpha: alpha, T: t}, nil
}

// Verify verifies a Schnorr ZK proof of knowledge of the discrete logarithm (GG18Spec Fig. 16)
func (pf *ZKProof) Verify(Session []byte, X *crypto.ECPoint) bool {
	if pf == nil || !pf.ValidateBasic() || X == nil || !X.ValidateBasic() {
		return false
	}
	ec := X.Curve()
	ecParams := ec.Params()
	q := ecParams.N
	g := crypto.NewECPointNoCurveCheck(ec, ecParams.Gx, ecParams.Gy)

	var c *big.Int
	{
		cHash := common.SHA512_256i_TAGGED(Session, X.X(), X.Y(), g.X(), g.Y(), pf.Alpha.X(), pf.Alpha.Y())
		c = common.RejectionSample(q, cHash)
	}
	tG := crypto.ScalarBaseMult(ec, pf.T)
	Xc := X.ScalarMult(c)
	aXc, err := pf.Alpha.Add(Xc)
	if err != nil {
		return false
	}
	return aXc.X().Cmp(tG.X()) == 0 && aXc.Y().Cmp(tG.Y()) == 0
}

// ValidateBasic checks that all fields of the ZKProof are non-nil and that
// Alpha is a valid curve point. The Alpha.ValidateBasic() call closes a
// panic vector: ZKProof.Verify calls pf.Alpha.X() which would dereference
// a nil coordinate (`big.Int.Set(nil)` panics) if a caller-supplied
// ZKProof has Alpha != nil but with nil coords. ZKVProof.ValidateBasic
// already includes this check; the two now match.
func (pf *ZKProof) ValidateBasic() bool {
	return pf.T != nil && pf.Alpha != nil && pf.Alpha.ValidateBasic()
}

// NewZKProof constructs a new Schnorr ZK proof of knowledge s_i, l_i such that V_i = R^s_i, g^l_i (GG18Spec Fig. 17).
//
// CT discipline mirrors NewZKProof: the commitment randomness `a` and
// `b` are routed through the CT scalar-mult dispatcher (ctmul); the
// responses t = c·s + a and u = c·l + b are computed via
// CTScalarMulAddModN. Note that the `aR` term still uses the generic
// ECPoint.ScalarMult on the caller-supplied point R — on Ed25519 the
// upstream library does not expose a CT variable-base scalar mult, so
// that term remains non-CT for Ed25519 callers. secp256k1 callers
// get CT all the way through.
func NewZKVProof(Session []byte, V, R *crypto.ECPoint, s, l *big.Int, rand io.Reader) (*ZKVProof, error) {
	if V == nil || R == nil || s == nil || l == nil || !V.ValidateBasic() || !R.ValidateBasic() {
		return nil, errors.New("ZKVProof constructor received nil value(s)")
	}
	ec := V.Curve()
	ecParams := ec.Params()
	q := ecParams.N
	g := crypto.NewECPointNoCurveCheck(ec, ecParams.Gx, ecParams.Gy)

	a, b := common.GetRandomPositiveInt(rand, q), common.GetRandomPositiveInt(rand, q)
	aR := ctmul.ScalarMultWithRand(R, a, rand)
	bG := ctmul.ScalarBaseMultWithRand(ec, b, rand)
	alpha, _ := aR.Add(bG) // already on the curve.

	var c *big.Int
	{
		cHash := common.SHA512_256i_TAGGED(Session, V.X(), V.Y(), R.X(), R.Y(), g.X(), g.Y(), alpha.X(), alpha.Y())
		c = common.RejectionSample(q, cHash)
	}
	// t = c·s + a mod q, u = c·l + b mod q — both via the CT primitive.
	t := crypto.CTScalarMulAddModN(ec, c, s, a)
	u := crypto.CTScalarMulAddModN(ec, c, l, b)

	return &ZKVProof{Alpha: alpha, T: t, U: u}, nil
}

// Verify checks whether the ZKVProof is valid for the given V and R points.
func (pf *ZKVProof) Verify(Session []byte, V, R *crypto.ECPoint) bool {
	if pf == nil || !pf.ValidateBasic() || V == nil || !V.ValidateBasic() || R == nil || !R.ValidateBasic() {
		return false
	}
	ec := V.Curve()
	ecParams := ec.Params()
	q := ecParams.N
	g := crypto.NewECPointNoCurveCheck(ec, ecParams.Gx, ecParams.Gy)

	var c *big.Int
	{
		cHash := common.SHA512_256i_TAGGED(Session, V.X(), V.Y(), R.X(), R.Y(), g.X(), g.Y(), pf.Alpha.X(), pf.Alpha.Y())
		c = common.RejectionSample(q, cHash)
	}
	tR := R.ScalarMult(pf.T)
	uG := crypto.ScalarBaseMult(ec, pf.U)
	tRuG, _ := tR.Add(uG) // already on the curve.

	Vc := V.ScalarMult(c)
	aVc, err := pf.Alpha.Add(Vc)
	if err != nil {
		return false
	}
	return tRuG.X().Cmp(aVc.X()) == 0 && tRuG.Y().Cmp(aVc.Y()) == 0
}

// ValidateBasic checks that all fields of the ZKVProof are non-nil and that Alpha is a valid point.
func (pf *ZKVProof) ValidateBasic() bool {
	return pf.Alpha != nil && pf.T != nil && pf.U != nil && pf.Alpha.ValidateBasic()
}
