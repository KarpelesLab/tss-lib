// Package frosttss is a broker-based implementation of FROST(Ed25519, SHA-512)
// per RFC 9591. It provides keygen, signing, and resharing protocols that
// produce signatures verifiable by any standard Ed25519 verifier.
//
// FROST is a Schnorr-based threshold signature scheme. Compared to the
// GG18-style protocol in eddsatss/, FROST keygen uses a Pedersen DKG (RFC 9591
// Appendix D) and FROST signing uses two preprocessing+signing rounds with a
// binding-factor mechanism that prevents nonce-reuse attacks.
//
// Keys produced by this package are NOT interchangeable with eddsatss.Key.
// Although the on-the-wire Xi value is structurally the same Shamir share, the
// FROST DKG procedure differs from eddsatss keygen (no hash-commitment phase,
// PoK bound only to a_i,0), and signatures use FROST's binding-factor
// aggregation, not the simpler eddsatss aggregation.
//
// References:
//   - RFC 9591: https://www.rfc-editor.org/rfc/rfc9591.html
//   - FROST paper: https://eprint.iacr.org/2020/852
package frosttss
