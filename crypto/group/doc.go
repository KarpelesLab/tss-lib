// Package group provides a uniform abstraction over prime-order groups so
// higher-level threshold-signature code can target either a Weierstrass curve
// (via crypto/elliptic.Curve) or a hash-to-element group like Ristretto255.
//
// The intended consumer is package crypto/frost, which needs to operate over
// both Ed25519 (RFC 9591 §6.1) and Ristretto255 (RFC 9591 §6.2). For the
// Ed25519 case, the Ed25519() group adapts crypto.ECPoint to the Element
// interface; for the Ristretto255 case, the Ristretto255() group wraps
// github.com/gtank/ristretto255.
//
// Scalars are uniformly represented as *big.Int reduced modulo the group order
// — both Ed25519 and Ristretto255 share the same scalar field (the Curve25519
// prime-order subgroup), so a *big.Int suffices for both. The Group interface
// provides canonical scalar encoding/decoding when wire-format scalars are
// needed.
package group
