package frost

import (
	"errors"
	"fmt"
	"io"
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

// NonceGenerate implements RFC 9591 §4.1 nonce_generate for the given
// ciphersuite: it returns a scalar k = cs.H3(random_bytes || EncodeScalar(secret)).
//
// Defense purpose: a per-signature random sample is cheap to compute but
// catastrophic if it ever repeats (forked process, VM snapshot+rollback,
// faulty RNG, deterministic test seed). Mixing the long-term secret share
// into the hash ensures that two NonceGenerate calls produce different
// nonces UNLESS both the RNG output and the secret share collide — a
// substantially weaker assumption than "RNG never repeats."
//
// The 32-byte random component is sampled from `rng` (caller-supplied;
// production callers should wire crypto/rand). Returns an error iff the
// caller's rng returns one or secret is nil.
//
// This helper is ciphersuite-aware: the domain string baked into H3 is the
// ciphersuite's ContextString, so a nonce derived for FROST(Ed25519) and a
// nonce derived for FROST(Ristretto255) over the same (rand, secret) pair
// are guaranteed distinct.
func NonceGenerate(cs Ciphersuite, rng io.Reader, secret *big.Int) (*big.Int, error) {
	if cs == nil {
		return nil, errors.New("frost: NonceGenerate requires a non-nil ciphersuite")
	}
	if secret == nil {
		return nil, errors.New("frost: NonceGenerate requires a non-nil secret")
	}
	if rng == nil {
		return nil, errors.New("frost: NonceGenerate requires a non-nil rng")
	}
	var k [32]byte
	if _, err := io.ReadFull(rng, k[:]); err != nil {
		return nil, fmt.Errorf("frost: NonceGenerate rand: %w", err)
	}
	enc := cs.Group().EncodeScalar(secret)
	defer func() {
		// Best-effort zeroize the random bytes and the secret encoding
		// so they do not linger on the goroutine stack longer than
		// strictly necessary. Go's GC may have already relocated copies
		// elsewhere — this is defense in depth, not a guarantee.
		for i := range k {
			k[i] = 0
		}
		for i := range enc {
			enc[i] = 0
		}
	}()
	buf := make([]byte, 0, 64)
	buf = append(buf, k[:]...)
	buf = append(buf, enc...)
	return cs.H3(buf), nil
}
