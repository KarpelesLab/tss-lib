package frost

import (
	"math/big"

	"github.com/KarpelesLab/tss-lib/v2/crypto/group"
)

// Ciphersuite is the per-curve set of hashes and encodings specified by RFC
// 9591 §6. Each ciphersuite is paired with a single group.Group and provides
// the H1..H5 functions used by the FROST protocol.
//
// Two ciphersuites are shipped:
//   - Ed25519Ciphersuite() — FROST(Ed25519, SHA-512), RFC 9591 §6.1. Produces
//     signatures verifiable by any standard Ed25519 verifier.
//   - Ristretto255Ciphersuite() — FROST(ristretto255, SHA-512), RFC 9591 §6.2.
//     Produces signatures in the natural Ristretto255 format (32-byte R || 32-
//     byte S); NOT Ed25519-compatible.
type Ciphersuite interface {
	// Name returns a short identifier ("ed25519", "ristretto255").
	Name() string

	// Group returns the underlying prime-order group implementation.
	Group() group.Group

	// ContextString returns the RFC 9591 ciphersuite-specific domain prefix
	// (e.g. "FROST-ED25519-SHA512-v1"). Mixed into H1, H3, H4, H5.
	ContextString() []byte

	// H1 maps an input to a scalar mod the group order using domain "rho".
	// Used to derive the per-signer binding factor rho_i (RFC 9591 §4.4).
	H1(msg []byte) *big.Int

	// H2 maps an input to a scalar mod the group order. The Ed25519
	// ciphersuite uses bare SHA-512 (no FROST prefix) so signatures verify
	// under Ed25519 verifiers. The Ristretto255 ciphersuite uses domain
	// "chal".
	H2(msg []byte) *big.Int

	// H3 maps an input to a scalar mod the group order using domain "nonce".
	// Used for deterministic nonce generation when callers opt in.
	H3(msg []byte) *big.Int

	// H4 returns a raw 64-byte digest of msg under domain "msg".
	H4(msg []byte) []byte

	// H5 returns a raw 64-byte digest of msg under domain "com".
	H5(msg []byte) []byte
}
