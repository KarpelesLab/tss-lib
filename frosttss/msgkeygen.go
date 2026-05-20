package frosttss

// keygenRound1msg is broadcast by every party in round 1 of the FROST DKG
// (Komlo–Goldberg, eprint 2020/852; RFC 9591 references the same Pedersen
// DKG outside the body of the RFC). It carries the participant's Feldman
// commitments (phi_{i,0}..phi_{i,t}), a fresh 16-byte session nonce, and a
// Schnorr proof of knowledge of a_{i,0} — the constant coefficient (= the
// participant's secret) — bound to phi_{i,0}.
//
// SessionNonce is sampled fresh from the local CSPRNG and is mixed into the
// PoK challenge alongside the FROST context string and the party identifier.
// This breaks any PoK-replay-across-keygen-runs attempt: a corrupted broker
// re-injecting an old (per-party) round-1 message into a new DKG run cannot
// produce a valid PoK on the same phi_{i,0} because the verifier uses the
// re-injected SessionNonce in the challenge.
//
// Commitments are encoded as canonical 32-byte Ed25519 points, in coefficient
// order. SchnorrProofAlphaX/Y are also each 32 bytes; SchnorrProofT is a
// scalar in [0, L) encoded big-endian. The Schnorr PoK uses
// crypto/schnorr.NewZKProof with the per-party session built by
// buildKeygenSession (see frosttss/keygen.go).
type keygenRound1msg struct {
	PolyCommitments    [][]byte `json:"poly_commitments"`
	SessionNonce       []byte   `json:"session_nonce"`
	EphPub             []byte   `json:"eph_pub"` // 32-byte X25519 public key for the encrypted round-2 P2P shares.
	SchnorrProofAlphaX []byte   `json:"schnorr_proof_alpha_x"`
	SchnorrProofAlphaY []byte   `json:"schnorr_proof_alpha_y"`
	SchnorrProofT      []byte   `json:"schnorr_proof_t"`
}

// keygenSessionNonceLen is the length in bytes of the per-party fresh
// session nonce included in keygenRound1msg. 16 bytes = 128 bits of
// entropy, far past birthday-collision risk for any realistic DKG count.
const keygenSessionNonceLen = 16

// keygenCommitmentBytes is the canonical encoded length of a single
// Ed25519 group element on the wire. Used as a length cap when decoding
// untrusted round-1 messages.
const keygenCommitmentBytes = 32

// keygenScalarBytes is the canonical encoded length of an Ed25519 scalar
// (mod L). Used as a length cap when decoding untrusted round-1 / round-2
// messages.
const keygenScalarBytes = 32

// keygenRound2msg is sent point-to-point in round 2 of the FROST DKG. Each
// participant sends every other participant their evaluation of the local
// polynomial at the recipient's identifier: f_i(x_j) mod L.
//
// As of the encrypted-shares hardening commit, the share is no longer
// emitted in plaintext: it is sealed under an X25519+HKDF+ChaCha20-Poly1305
// envelope keyed by the sender's and recipient's ephemeral X25519 keys
// (broadcast in round 1). Ciphertext is nonce || aead.Seal(...).
//
// Associated data: keygenRound2AD(sessionTag, senderPub, recipientPub) —
// see keygen.go.
type keygenRound2msg struct {
	Ciphertext []byte `json:"ciphertext"`
}
