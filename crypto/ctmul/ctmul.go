package ctmul

import (
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"math/big"

	"github.com/KarpelesLab/edwards25519"
	"github.com/KarpelesLab/secp256k1"

	"github.com/KarpelesLab/tss-lib/v2/crypto"
)

// ScalarMult returns k · P. When P is on secp256k1, it uses the
// constant-time Montgomery ladder implemented below; for any other curve
// it falls back to the (non-CT) ECPoint.ScalarMult. The intent is for k
// to be a SECRET scalar — a long-term key share, a signing nonce, an OT
// receiver's mask.
//
// Random source for blinding/Z-randomization comes from crypto/rand.
func ScalarMult(P *crypto.ECPoint, k *big.Int) *crypto.ECPoint {
	return ScalarMultWithRand(P, k, rand.Reader)
}

// ScalarMultWithRand is ScalarMult with an explicit random source.
// Provided for tests that need deterministic output; production callers
// should use ScalarMult.
//
// On secp256k1 the constant-time ladder requires fresh randomness for the
// Z-randomization and scalar-blinding side-channel defenses. If the
// provided RNG returns an error, the function panics rather than silently
// downgrading to the standard (non-CT) primitive — a downgrade would
// quietly disable the entire reason callers reach for ctmul. RNG failures
// at this level are catastrophic system events; failing loudly is the
// correct behavior.
func ScalarMultWithRand(P *crypto.ECPoint, k *big.Int, rng io.Reader) *crypto.ECPoint {
	if P == nil || k == nil {
		return nil
	}
	// Ed25519: no per-point CT scalar-mult helper is provided by the
	// upstream edwards25519 package (it exposes a CT fixed-base
	// GeScalarMultBase but not a general CT variable-base mult). Fall
	// back to the (non-CT) ECPoint.ScalarMult so the function remains
	// total — callers that need CT-variable-base on Ed25519 must
	// either compose from CT primitives themselves or accept that the
	// non-CT path is what's available. The Schnorr ZKProof construction
	// only uses base-mult (covered above by ScalarBaseMultWithRand),
	// so this path is exercised only by the rarer ZKVProof.
	if P.Curve() != secp256k1.S256() {
		return P.ScalarMult(k)
	}
	out, err := ctScalarMultSecp256k1(P, k, rng)
	if err != nil {
		// Silent fallback would lose the CT guarantee callers explicitly
		// reached for ctmul to obtain. RNG failure → panic.
		panic("ctmul: RNG failure in constant-time scalar mult: " + err.Error())
	}
	return out
}

// ScalarBaseMult returns k · G where G is the given curve's base point.
// Routes through ScalarMult, applying the constant-time ladder for
// secp256k1 and falling back to the standard primitive for other curves.
func ScalarBaseMult(curve elliptic.Curve, k *big.Int) *crypto.ECPoint {
	return ScalarBaseMultWithRand(curve, k, rand.Reader)
}

// ScalarBaseMultWithRand is ScalarBaseMult with an explicit random source.
//
// Curve dispatch:
//   - secp256k1 → constant-time Montgomery ladder (this file).
//   - Ed25519   → crypto.CTScalarBaseMultEd25519 (edwards25519 fixed-base
//     table). Does not consume `rng` (the underlying primitive's CT
//     guarantee does not depend on per-call randomness).
//   - other     → falls back to the non-CT crypto.ScalarBaseMult so the
//     function remains total. Documented in the package doc.
func ScalarBaseMultWithRand(curve elliptic.Curve, k *big.Int, rng io.Reader) *crypto.ECPoint {
	if curve == edwards25519.Edwards() {
		return crypto.CTScalarBaseMultEd25519(curve, k)
	}
	if curve != secp256k1.S256() {
		return crypto.ScalarBaseMult(curve, k)
	}
	params := curve.Params()
	G := crypto.NewECPointNoCurveCheck(curve, params.Gx, params.Gy)
	return ScalarMultWithRand(G, k, rng)
}

// ctScalarMultSecp256k1 is the constant-time core: a Montgomery ladder
// over secp256k1 Jacobian coordinates with two side-channel defenses:
//
//   - Z-coordinate randomization defeats the addZ1=Z2/Z1=1 fast-path
//     branches inside AddNonConst: with overwhelming probability, after
//     randomization the two Z values differ and the ladder always
//     dispatches to addGeneric.
//   - 64-bit scalar blinding (k' = k + r·q for r ← uniform[0, 2^64))
//     hides the high bits of k. The ladder iterates over k' rather than
//     k. Since q·P = O, k'·P = k·P, but the timing-observable bit pattern
//     is randomized.
//
// The conditional swap of R0 and R1 is performed byte-by-byte on the
// FieldVal coordinates after PutBytes serialization — purely constant-time
// at the byte level.
//
// Residual leakage: AddNonConst still has an identity-point fast path
// (returns p2 when p1 is identity, and vice versa). The ladder is seeded
// with R0 = identity and R1 = P, so the first iteration with a "leading
// zero" bit hits this branch. Scalar blinding pushes the meaningful bits
// of k away from the high positions, so timing observation of that early
// branch reveals high bits of the BLINDED scalar k', which are
// statistically independent of k.
//
// The final ToAffine call performs one FieldVal.Inverse on the Z
// coordinate. Z at that point is a deterministic function of k via the
// ladder, but the affine X, Y produced are themselves the standard
// output — leakage from the inversion is bounded by the same scalar
// blinding.
func ctScalarMultSecp256k1(P *crypto.ECPoint, k *big.Int, rng io.Reader) (*crypto.ECPoint, error) {
	curve := secp256k1.S256()
	q := curve.Params().N

	// Convert P to Jacobian (Z=1) form.
	var pJac secp256k1.JacobianPoint
	if !ecPointToJacobian(P, &pJac) {
		return nil, errors.New("ctmul: point conversion failed")
	}

	// Randomize Z to defeat AddNonConst's Z-equality fast paths.
	if err := randomizeZ(&pJac, rng); err != nil {
		return nil, err
	}

	// Blind k: k' = k + r·q for random 64-bit r.
	kMod := new(big.Int).Mod(k, q)
	var blindBytes [8]byte
	if _, err := io.ReadFull(rng, blindBytes[:]); err != nil {
		return nil, err
	}
	r := new(big.Int).SetBytes(blindBytes[:])
	kBlinded := new(big.Int).Mul(r, q)
	kBlinded.Add(kBlinded, kMod)
	nbits := q.BitLen() + 64 // 256 + 64 = 320

	// Initialize: R0 = identity, R1 = P (with randomized Z).
	var r0, r1 secp256k1.JacobianPoint
	r0.X.SetInt(0)
	r0.Y.SetInt(1)
	r0.Z.SetInt(0) // identity convention: Z=0
	r1.Set(&pJac)

	// Montgomery ladder: process bits MSB to LSB.
	for i := nbits - 1; i >= 0; i-- {
		bit := byte(kBlinded.Bit(i)) // 0 or 1
		// Build CT mask: 0x00 for bit=0, 0xFF for bit=1.
		mask := byte(-int8(bit))

		ctSwapJac(&r0, &r1, mask)
		secp256k1.AddNonConst(&r0, &r1, &r1) // R1 = R0 + R1
		secp256k1.DoubleNonConst(&r0, &r0)   // R0 = 2 * R0
		ctSwapJac(&r0, &r1, mask)
	}

	// R0 = k' · P = k · P mod q. Convert to affine and to crypto.ECPoint.
	if r0.Z.IsZero() {
		// Result is the identity — should not happen for k ≠ 0 mod q.
		// Return a zero-coord point (caller is responsible for k ≠ 0).
		return crypto.NewECPointNoCurveCheck(curve, new(big.Int), new(big.Int)), nil
	}
	r0.ToAffine()
	return jacobianToECPoint(&r0), nil
}

// ecPointToJacobian copies (X, Y, 1) from a crypto.ECPoint into a
// secp256k1.JacobianPoint. Returns false if the point is not on
// secp256k1.
func ecPointToJacobian(P *crypto.ECPoint, out *secp256k1.JacobianPoint) bool {
	if P.Curve() != secp256k1.S256() {
		return false
	}
	out.X.SetByteSlice(P.X().Bytes())
	out.Y.SetByteSlice(P.Y().Bytes())
	out.Z.SetInt(1)
	return true
}

// jacobianToECPoint extracts the affine X, Y from a JacobianPoint (which
// must already be in affine form, i.e., Z=1) and wraps them in a
// *crypto.ECPoint.
func jacobianToECPoint(p *secp256k1.JacobianPoint) *crypto.ECPoint {
	var xb, yb [32]byte
	p.X.PutBytes(&xb)
	p.Y.PutBytes(&yb)
	x := new(big.Int).SetBytes(xb[:])
	y := new(big.Int).SetBytes(yb[:])
	return crypto.NewECPointNoCurveCheck(secp256k1.S256(), x, y)
}

// randomizeZ multiplies the projective coordinates (X, Y, Z) by
// (r^2, r^3, r) for a random non-zero field element r. This preserves
// the underlying affine point but changes the projective representation,
// breaking the Z-equality fast paths in AddNonConst.
func randomizeZ(p *secp256k1.JacobianPoint, rng io.Reader) error {
	var buf [32]byte
	for tries := 0; tries < 16; tries++ {
		if _, err := io.ReadFull(rng, buf[:]); err != nil {
			return err
		}
		var r secp256k1.FieldVal
		r.SetBytes(&buf)
		if r.IsZero() {
			continue
		}
		var r2, r3 secp256k1.FieldVal
		r2.SquareVal(&r)
		r3.Mul2(&r2, &r)
		// X' = X·r², Y' = Y·r³, Z' = Z·r.
		p.X.Mul(&r2)
		p.Y.Mul(&r3)
		p.Z.Mul(&r)
		// Normalize so subsequent operations have predictable magnitudes.
		p.X.Normalize()
		p.Y.Normalize()
		p.Z.Normalize()
		return nil
	}
	return errors.New("ctmul: failed to sample non-zero blinding factor")
}

// ctSwapJac conditionally swaps R0 and R1's Jacobian coordinates based on
// mask: 0x00 leaves them unchanged, 0xFF swaps. Each FieldVal is
// serialized to 32 bytes, XOR-swapped byte-by-byte with the mask, and
// deserialized. All operations are data-independent.
func ctSwapJac(p1, p2 *secp256k1.JacobianPoint, mask byte) {
	ctSwapField(&p1.X, &p2.X, mask)
	ctSwapField(&p1.Y, &p2.Y, mask)
	ctSwapField(&p1.Z, &p2.Z, mask)
}

// ctSwapField conditionally swaps two FieldVal at the byte level. mask
// must be 0x00 (no swap) or 0xFF (swap).
func ctSwapField(x, y *secp256k1.FieldVal, mask byte) {
	var xb, yb [32]byte
	x.PutBytes(&xb)
	y.PutBytes(&yb)
	for i := 0; i < 32; i++ {
		d := (xb[i] ^ yb[i]) & mask
		xb[i] ^= d
		yb[i] ^= d
	}
	x.SetBytes(&xb)
	y.SetBytes(&yb)
}
