// Package frostristretto255tss is a broker-based implementation of
// FROST(ristretto255, SHA-512) per RFC 9591 §6.2. It provides keygen,
// signing, and resharing protocols that produce signatures in the natural
// Ristretto255 format (32-byte R || 32-byte S).
//
// Ristretto255 signatures from this package are NOT Ed25519-compatible. Use
// package frosttss for Ed25519-compatible output.
//
// The package shares its protocol shape with frosttss but operates over the
// Ristretto255 prime-order group (RFC 9496) rather than Edwards25519. Scalars
// are interchangeable between the two groups (both use Curve25519's scalar
// field), so much of the surface is structurally identical.
//
// Callers construct Parameters with tss.NewParameters(tss.Edwards(), ...).
// The Ed25519 curve is used solely as a scalar-field-compatible placeholder;
// no point operations on the Edwards25519 curve happen inside this package —
// all group operations go through crypto/group.Ristretto255().
package frostristretto255tss
