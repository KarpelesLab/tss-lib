// Package ctmul provides constant-time scalar multiplication on
// secp256k1 for use by the DKLs23 implementation (crypto/ot/baseot,
// dklstss). Every secret-scalar operation in the DKLs23 stack should
// route through ScalarMult or ScalarBaseMult here rather than the
// non-constant-time primitives in crypto.ECPoint and the underlying
// secp256k1 dep.
//
// Algorithm — a Montgomery ladder over secp256k1 Jacobian coordinates
// with three side-channel defenses:
//
//  1. Z-coordinate randomization at the start: the input point's
//     projective coordinates (X, Y, Z) are multiplied by (r², r³, r) for a
//     fresh non-zero field element r. This preserves the underlying
//     affine point but defeats the Z-equality fast-path branches in
//     AddNonConst (addZ1AndZ2EqualsOne, addZ1EqualsZ2, addZ2EqualsOne).
//
//  2. 64-bit scalar blinding: the ladder iterates over k' = k + r·q
//     (for a fresh 64-bit r) rather than over k directly. Since q is the
//     curve order, k' · P = k · P. The high bits of k' are statistically
//     independent of the secret k, so any timing leak in the early
//     iterations of the ladder reveals high bits of k', not k.
//
//  3. Constant-time conditional swap: at each ladder step, R0 and R1 are
//     conditionally swapped based on the current scalar bit. The swap is
//     implemented by serializing the (X, Y, Z) FieldVal coordinates to
//     32-byte arrays via PutBytes, XOR-swapping byte-by-byte against a
//     mask of 0x00 or 0xFF, and deserializing via SetBytes. No
//     data-dependent branches; the same number of byte operations runs
//     regardless of the bit value.
//
// The underlying field arithmetic in the secp256k1 dependency
// (FieldVal Add/Mul/Square/Negate) is documented constant time. The
// remaining residual side channel is AddNonConst's identity-point
// fast path (it returns p2 if p1 has Z=0, and vice versa). The ladder
// seeds R0 with the identity, so the first iterations on a leading-zero
// scalar bit exercise this branch — but scalar blinding ensures the
// observable timing pattern at the start of the ladder is independent
// of the secret k.
//
// Tradeoffs: the byte-level cswap and Z randomization make this
// implementation slower than the optimized NAF-based
// ScalarMultNonConst (roughly 3-5×). For threshold-signing workloads
// the cost is dominated by the OT extension layer regardless, so this
// matters little in practice; for primary-signing-key workloads the
// slowdown is the price of avoiding the cache-timing leak.
//
// Only secp256k1 is supported by the CT path; calls on any other
// elliptic.Curve fall back to the standard non-CT primitive (and the
// caller should not rely on CT for them).
package ctmul
