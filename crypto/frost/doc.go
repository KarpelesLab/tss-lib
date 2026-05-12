// Package frost implements the FROST (Flexible Round-Optimized Schnorr Threshold)
// signature scheme over Edwards25519, producing Ed25519-compatible signatures
// as specified in RFC 9591 §6.1 ("FROST(Ed25519, SHA-512)").
//
// This package provides the transport-agnostic cryptographic primitives:
// ciphersuite hash functions H1..H5, canonical Ed25519 point encoding, the
// FROST binding-factor and group-commitment computation, and helpers used by
// the Pedersen DKG (RFC 9591 Appendix D) and FROST signing (RFC 9591 §5).
//
// The broker-driven protocol layer lives in package frosttss. Phase 1 of the
// FROST integration only supports the Ed25519 ciphersuite; a Group abstraction
// for Ristretto255 is planned for a follow-up phase.
package frost
