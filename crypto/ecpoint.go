// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/KarpelesLab/edwards25519"
	"github.com/KarpelesLab/secp256k1"

	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// ECPoint convenience helper
type ECPoint struct {
	curve  elliptic.Curve
	coords [2]*big.Int
}

var (
	eight    = big.NewInt(8)
	eightInv = new(big.Int).ModInverse(eight, edwards25519.Edwards().Params().N)
	oneBig   = big.NewInt(1)
)

// Creates a new ECPoint and checks that the given coordinates are on the elliptic curve.
func NewECPoint(curve elliptic.Curve, X, Y *big.Int) (*ECPoint, error) {
	if !isOnCurve(curve, X, Y) {
		return nil, fmt.Errorf("NewECPoint: the given point is not on the elliptic curve")
	}
	return &ECPoint{curve, [2]*big.Int{X, Y}}, nil
}

// Creates a new ECPoint without checking that the coordinates are on the elliptic curve.
// Only use this function when you are completely sure that the point is already on the curve.
func NewECPointNoCurveCheck(curve elliptic.Curve, X, Y *big.Int) *ECPoint {
	return &ECPoint{curve, [2]*big.Int{X, Y}}
}

// X returns a copy of the point's X coordinate.
func (p *ECPoint) X() *big.Int {
	return new(big.Int).Set(p.coords[0])
}

// Y returns a copy of the point's Y coordinate.
func (p *ECPoint) Y() *big.Int {
	return new(big.Int).Set(p.coords[1])
}

// Add returns the sum of p and p1 on the elliptic curve.
func (p *ECPoint) Add(p1 *ECPoint) (*ECPoint, error) {
	x, y := p.curve.Add(p.X(), p.Y(), p1.X(), p1.Y())
	return NewECPoint(p.curve, x, y)
}

// ScalarMult returns the result of multiplying the point by the scalar k.
func (p *ECPoint) ScalarMult(k *big.Int) *ECPoint {
	x, y := p.curve.ScalarMult(p.X(), p.Y(), k.Bytes())
	newP, err := NewECPoint(p.curve, x, y) // it must be on the curve, no need to check.
	if err != nil {
		panic(fmt.Errorf("scalar mult to an ecpoint %s", err.Error()))
	}
	return newP
}

// ToECDSAPubKey converts the ECPoint to a standard library ECDSA public key.
func (p *ECPoint) ToECDSAPubKey() *ecdsa.PublicKey {
	return &ecdsa.PublicKey{
		Curve: p.curve,
		X:     p.X(),
		Y:     p.Y(),
	}
}

// ToEd25519PubKey returns a [github.com/KarpelesLab/edwards25519.PublicKey] object for this public key
// or nil if this is not a ed25519 key.
func (p *ECPoint) ToEd25519PubKey() *edwards25519.PublicKey {
	return &edwards25519.PublicKey{
		Curve: p.curve,
		X:     p.X(),
		Y:     p.Y(),
	}
}

// ToSecp256k1PubKey returns a [github.com/KarpelesLab/secp256k1.PublicKey] object for this public key
// or nil if this is not a secp256k1 key.
func (p *ECPoint) ToSecp256k1PubKey() *secp256k1.PublicKey {
	if p.curve != secp256k1.S256() {
		// TODO we may want to allow other ways to bring this curve?
		return nil
	}
	x := &secp256k1.FieldVal{}
	y := &secp256k1.FieldVal{}
	x.SetByteSlice(p.X().Bytes())
	y.SetByteSlice(p.Y().Bytes())

	return secp256k1.NewPublicKey(x, y)
}

// IsOnCurve reports whether the point lies on its elliptic curve.
func (p *ECPoint) IsOnCurve() bool {
	return isOnCurve(p.curve, p.coords[0], p.coords[1])
}

// Curve returns the elliptic curve on which the point is defined.
func (p *ECPoint) Curve() elliptic.Curve {
	return p.curve
}

// Equals reports whether p and p2 represent the same point.
func (p *ECPoint) Equals(p2 *ECPoint) bool {
	if p == nil || p2 == nil {
		return false
	}
	return p.X().Cmp(p2.X()) == 0 && p.Y().Cmp(p2.Y()) == 0
}

// SetCurve sets the curve of the point and returns the modified point.
func (p *ECPoint) SetCurve(curve elliptic.Curve) *ECPoint {
	p.curve = curve
	return p
}

// ValidateBasic checks that the point is non-nil, has non-nil coordinates, and lies on its curve.
func (p *ECPoint) ValidateBasic() bool {
	return p != nil && p.coords[0] != nil && p.coords[1] != nil && p.IsOnCurve()
}

// IsIdentity reports whether the point is the group identity (point at
// infinity). Affine representations differ by curve family:
//
//   - Short Weierstrass curves (secp256k1, NIST P-256, …): identity is
//     conventionally (0, 0) and is NOT on the curve, so a point constructed
//     via NewECPoint cannot be the identity. NewECPointNoCurveCheck
//     callers and unmarshalled wire bytes are the only paths that can
//     deposit a (0, 0) into an ECPoint; this helper catches those.
//   - Twisted Edwards curves (Ed25519): identity is (0, 1) and IS on the
//     curve. This helper detects it.
//
// Returns false for a nil receiver.
func (p *ECPoint) IsIdentity() bool {
	if p == nil || p.coords[0] == nil || p.coords[1] == nil {
		return false
	}
	if p.coords[0].Sign() != 0 {
		return false
	}
	// X = 0; identity if Y is also 0 (short-Weierstrass) or 1 (twisted-Edwards).
	if p.coords[1].Sign() == 0 {
		return true
	}
	if p.coords[1].Cmp(oneBig) == 0 {
		return true
	}
	return false
}

// EightInvEight multiplies the point by 8 and then by the modular inverse of 8 (used for cofactor clearing on Ed25519).
func (p *ECPoint) EightInvEight() *ECPoint {
	return p.ScalarMult(eight).ScalarMult(eightInv)
}

// ScalarBaseMult returns k*G where G is the base point of the given curve.
func ScalarBaseMult(curve elliptic.Curve, k *big.Int) *ECPoint {
	x, y := curve.ScalarBaseMult(k.Bytes())
	p, err := NewECPoint(curve, x, y) // it must be on the curve, no need to check.
	if err != nil {
		panic(fmt.Errorf("scalar mult to an ecpoint %s", err.Error()))
	}
	return p
}

func isOnCurve(c elliptic.Curve, x, y *big.Int) bool {
	if x == nil || y == nil {
		return false
	}
	return c.IsOnCurve(x, y)
}

// ----- //

// FlattenECPoints serializes a slice of ECPoints into a flat slice of big.Int coordinates (x1, y1, x2, y2, ...).
func FlattenECPoints(in []*ECPoint) ([]*big.Int, error) {
	if in == nil {
		return nil, errors.New("FlattenECPoints encountered a nil in slice")
	}
	flat := make([]*big.Int, 0, len(in)*2)
	for _, point := range in {
		if point == nil || point.coords[0] == nil || point.coords[1] == nil {
			return nil, errors.New("FlattenECPoints found nil point/coordinate")
		}
		flat = append(flat, point.coords[0])
		flat = append(flat, point.coords[1])
	}
	return flat, nil
}

// UnFlattenECPoints reconstructs a slice of ECPoints from a flat slice of big.Int coordinate pairs.
func UnFlattenECPoints(curve elliptic.Curve, in []*big.Int, noCurveCheck ...bool) ([]*ECPoint, error) {
	if in == nil || len(in)%2 != 0 {
		return nil, errors.New("UnFlattenECPoints expected an in len divisible by 2")
	}
	var err error
	unFlat := make([]*ECPoint, len(in)/2)
	for i, j := 0, 0; i < len(in); i, j = i+2, j+1 {
		if len(noCurveCheck) == 0 || !noCurveCheck[0] {
			unFlat[j], err = NewECPoint(curve, in[i], in[i+1])
			if err != nil {
				return nil, err
			}
		} else {
			unFlat[j] = NewECPointNoCurveCheck(curve, in[i], in[i+1])
		}
	}
	for _, point := range unFlat {
		if point.coords[0] == nil || point.coords[1] == nil {
			return nil, errors.New("UnFlattenECPoints found nil coordinate after unpack")
		}
	}
	return unFlat, nil
}

// ----- //
// Gob helpers for if you choose to encode messages with Gob.

// GobEncode implements the gob.GobEncoder interface for ECPoint.
func (p *ECPoint) GobEncode() ([]byte, error) {
	buf := &bytes.Buffer{}
	x, err := p.coords[0].GobEncode()
	if err != nil {
		return nil, err
	}
	y, err := p.coords[1].GobEncode()
	if err != nil {
		return nil, err
	}

	err = binary.Write(buf, binary.LittleEndian, uint32(len(x)))
	if err != nil {
		return nil, err
	}
	buf.Write(x)
	err = binary.Write(buf, binary.LittleEndian, uint32(len(y)))
	if err != nil {
		return nil, err
	}
	buf.Write(y)

	return buf.Bytes(), nil
}

// GobDecode implements the gob.GobDecoder interface for ECPoint.
func (p *ECPoint) GobDecode(buf []byte) error {
	reader := bytes.NewReader(buf)
	var length uint32
	if err := binary.Read(reader, binary.LittleEndian, &length); err != nil {
		return err
	}
	x := make([]byte, length)
	n, err := reader.Read(x)
	if n != int(length) || err != nil {
		return fmt.Errorf("gob decode failed: %v", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &length); err != nil {
		return err
	}
	y := make([]byte, length)
	n, err = reader.Read(y)
	if n != int(length) || err != nil {
		return fmt.Errorf("gob decode failed: %v", err)
	}

	X := new(big.Int)
	if err := X.GobDecode(x); err != nil {
		return err
	}
	Y := new(big.Int)
	if err := Y.GobDecode(y); err != nil {
		return err
	}
	p.curve = tss.EC()
	p.coords = [2]*big.Int{X, Y}
	if !p.IsOnCurve() {
		return errors.New("ECPoint.UnmarshalJSON: the point is not on the elliptic curve")
	}
	return nil
}

// ----- //

// crypto.ECPoint is not inherently json marshal-able
func (p *ECPoint) MarshalJSON() ([]byte, error) {
	ecName, ok := tss.GetCurveName(p.curve)
	if !ok {
		return nil, fmt.Errorf("cannot find %T name in curve registry, please call tss.RegisterCurve(name, curve) to register it first", p.curve)
	}

	return json.Marshal(&struct {
		Curve  string
		Coords [2]*big.Int
	}{
		Curve:  string(ecName),
		Coords: p.coords,
	})
}

// UnmarshalJSON implements the json.Unmarshaler interface for ECPoint.
func (p *ECPoint) UnmarshalJSON(payload []byte) error {
	aux := &struct {
		Curve  string
		Coords [2]*big.Int
	}{}
	if err := json.Unmarshal(payload, &aux); err != nil {
		return err
	}
	p.coords = [2]*big.Int{aux.Coords[0], aux.Coords[1]}

	if len(aux.Curve) > 0 {
		ec, ok := tss.GetCurveByName(tss.CurveName(aux.Curve))
		if !ok {
			return fmt.Errorf("cannot find curve named with %s in curve registry, please call tss.RegisterCurve(name, curve) to register it first", aux.Curve)
		}
		p.curve = ec
	} else {
		// forward compatible, use global ec as default value
		p.curve = tss.EC()
	}

	if !p.IsOnCurve() {
		return fmt.Errorf("ECPoint.UnmarshalJSON: the point is not on the elliptic curve (%T) ", p.curve)
	}

	return nil
}
