// Copyright © 2026 KarpelesLab.
//
// Package frostenc provides an X25519 + HKDF-SHA256 + ChaCha20-Poly1305
// authenticated-encryption envelope for FROST DKG (and resharing) P2P
// shares. It exists to close the audit finding "round-2 shares emitted
// in plaintext": without this, a passive eavesdropper on the broker
// transport plus t-1 corrupted parties recovers the master secret.
//
// Threat model:
//   - Each participant samples a fresh ephemeral X25519 keypair PER DKG
//     run. The public component is broadcast in round 1 alongside the
//     polynomial commitments (and bound into the round-1 Schnorr PoK
//     challenge, so an attacker cannot substitute another EphPub
//     post-hoc).
//   - For round 2, sender i and recipient j derive a per-pair shared
//     secret via X25519(priv_i, pub_j) == X25519(priv_j, pub_i). HKDF
//     stretches the shared secret into a per-pair, per-session AEAD key.
//   - ChaCha20-Poly1305 encrypts the share with a fresh 12-byte random
//     nonce prepended to the ciphertext. Associated data binds the
//     ciphertext to (senderPub, recipientPub, sessionID, label) so a
//     replay or cross-session reuse is detectable.
//
// Defensible against:
//   - Passive eavesdropper (cannot decrypt without one of the X25519
//     private keys).
//   - Cross-session replay (associated-data binds the sessionID).
//   - Cross-pair replay (associated-data binds sender and recipient
//     pubs).
//
// NOT defensible against:
//   - An attacker who compromises one of the X25519 private keys
//     (they can decrypt every ciphertext addressed to that party AND
//     impersonate the holder for future runs).
//   - An active broker that drops/reorders ciphertexts (caller's
//     responsibility — the broker contract requires reliable delivery).
//   - Forward secrecy across DKG runs is provided by the EPHEMERAL
//     property: keys are not reused, so compromise of one DKG's
//     transcript leaks at most one DKG's shares.
package frostenc

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// EphemeralKeyBytes is the length in bytes of a Curve25519 private and
// public key (both 32 bytes on Curve25519).
const EphemeralKeyBytes = 32

// SealedNonceBytes is the length in bytes of the random nonce prepended
// to every sealed payload. ChaCha20-Poly1305 nonce size.
const SealedNonceBytes = chacha20poly1305.NonceSize

// keyDerivationInfo is the HKDF info parameter for AEAD key derivation.
// Domain-separates from any other future HKDF use over the same shared
// secret.
var keyDerivationInfo = []byte("frosttss/share-aead-v1")

// NewEphemeralKey samples a fresh Curve25519 keypair from rng. The
// returned private key is in the canonical X25519 form (the clamping
// is performed by curve25519.X25519 internally; we return raw 32 bytes
// here and clamping is applied at use time).
func NewEphemeralKey(rng io.Reader) (priv, pub []byte, err error) {
	if rng == nil {
		return nil, nil, errors.New("frostenc: rng is nil")
	}
	priv = make([]byte, EphemeralKeyBytes)
	if _, err = io.ReadFull(rng, priv); err != nil {
		return nil, nil, fmt.Errorf("frostenc: NewEphemeralKey: %w", err)
	}
	pub, err = curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("frostenc: derive pub: %w", err)
	}
	return priv, pub, nil
}

// SealShare encrypts plaintext under the X25519-derived AEAD key for the
// (senderPriv, recipientPub) pair. The returned ciphertext is
// nonce || encrypted, with nonce length SealedNonceBytes.
//
// associatedData binds the ciphertext to the calling protocol's session.
// Recommended layout: sessionID || senderPub || recipientPub || label
// where label is a short ASCII tag (e.g., "frosttss-keygen-r2").
func SealShare(rng io.Reader, senderPriv, recipientPub, associatedData, plaintext []byte) ([]byte, error) {
	if len(senderPriv) != EphemeralKeyBytes {
		return nil, fmt.Errorf("frostenc: senderPriv must be %d bytes, got %d", EphemeralKeyBytes, len(senderPriv))
	}
	if len(recipientPub) != EphemeralKeyBytes {
		return nil, fmt.Errorf("frostenc: recipientPub must be %d bytes, got %d", EphemeralKeyBytes, len(recipientPub))
	}
	if rng == nil {
		return nil, errors.New("frostenc: rng is nil")
	}
	shared, err := curve25519.X25519(senderPriv, recipientPub)
	if err != nil {
		return nil, fmt.Errorf("frostenc: X25519: %w", err)
	}
	defer func() {
		for i := range shared {
			shared[i] = 0
		}
	}()
	// Reject all-zero shared secret (which X25519 returns when one of
	// the inputs lies in a small subgroup). crypto/curve25519 already
	// returns an error in that case; this is defense in depth.
	allZero := true
	for _, b := range shared {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return nil, errors.New("frostenc: shared secret is all-zero (small-subgroup pub)")
	}

	key := deriveAEADKey(shared, associatedData)
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("frostenc: chacha20poly1305.New: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rng, nonce); err != nil {
		return nil, fmt.Errorf("frostenc: nonce rand: %w", err)
	}
	// Output: nonce || aead.Seal(plaintext, AD).
	out := make([]byte, 0, len(nonce)+len(plaintext)+aead.Overhead())
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, plaintext, associatedData)
	return out, nil
}

// OpenShare decrypts ciphertext produced by SealShare under the X25519-
// derived AEAD key for the (recipientPriv, senderPub) pair. The
// ciphertext is expected to be nonce || encrypted with nonce length
// SealedNonceBytes. associatedData must match the value used at seal.
//
// Returns the plaintext on success, or an error if the X25519 shared
// secret is small-subgroup, the AEAD nonce is malformed, or the AEAD
// tag does not verify (tampered ciphertext or wrong AD).
func OpenShare(recipientPriv, senderPub, associatedData, ciphertext []byte) ([]byte, error) {
	if len(recipientPriv) != EphemeralKeyBytes {
		return nil, fmt.Errorf("frostenc: recipientPriv must be %d bytes, got %d", EphemeralKeyBytes, len(recipientPriv))
	}
	if len(senderPub) != EphemeralKeyBytes {
		return nil, fmt.Errorf("frostenc: senderPub must be %d bytes, got %d", EphemeralKeyBytes, len(senderPub))
	}
	if len(ciphertext) < SealedNonceBytes+chacha20poly1305.Overhead {
		return nil, errors.New("frostenc: ciphertext too short")
	}
	shared, err := curve25519.X25519(recipientPriv, senderPub)
	if err != nil {
		return nil, fmt.Errorf("frostenc: X25519: %w", err)
	}
	defer func() {
		for i := range shared {
			shared[i] = 0
		}
	}()
	allZero := true
	for _, b := range shared {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return nil, errors.New("frostenc: shared secret is all-zero (small-subgroup pub)")
	}
	key := deriveAEADKey(shared, associatedData)
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("frostenc: chacha20poly1305.New: %w", err)
	}
	nonce := ciphertext[:SealedNonceBytes]
	encrypted := ciphertext[SealedNonceBytes:]
	out, err := aead.Open(nil, nonce, encrypted, associatedData)
	if err != nil {
		return nil, fmt.Errorf("frostenc: aead.Open: %w", err)
	}
	return out, nil
}

// deriveAEADKey runs HKDF-SHA256 over the X25519 shared secret with the
// associated data as the HKDF "info" parameter. Returns a 32-byte key
// suitable for ChaCha20-Poly1305.
//
// We use the associated data as info (rather than as the salt) so that
// distinct AD values yield distinct keys — making cross-AD replay
// detectable at the AEAD layer as well as via the AEAD's own AD check.
// (Belt and suspenders.) The salt is empty; HKDF accepts that and the
// IKM (X25519 shared secret) is uniformly random so the salt provides
// no additional entropy.
func deriveAEADKey(sharedSecret, associatedData []byte) []byte {
	// Concat keyDerivationInfo || associatedData as the HKDF info
	// parameter. keyDerivationInfo provides protocol-level domain
	// separation; AD provides per-(sender,recipient,session) binding.
	info := make([]byte, 0, len(keyDerivationInfo)+len(associatedData))
	info = append(info, keyDerivationInfo...)
	info = append(info, associatedData...)

	r := hkdf.New(sha256.New, sharedSecret, nil /*salt*/, info)
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(r, key); err != nil {
		// HKDF.Reader on SHA-256 never returns an error within its
		// max output size of 8160 bytes; reaching here is a runtime
		// invariant violation, so panic is appropriate.
		panic(fmt.Sprintf("frostenc: HKDF read failure: %v", err))
	}
	return key
}
