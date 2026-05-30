package frostristretto255tss

// keygenRound1msg is broadcast by every party in round 1 of the FROST DKG.
// PolyCommitments holds each coefficient's commitment phi_{i,j} = a_{i,j}*G,
// encoded as 32-byte canonical Ristretto255 points in coefficient order.
//
// SessionNonce is a fresh per-keygen 16-byte CSPRNG value, mixed into the
// Schnorr PoK challenge (via buildKeygenSession) alongside the FROST context
// string and the party identifier. This breaks PoK-replay-across-keygen-runs:
// a corrupted broker re-injecting an old per-party round-1 message into a new
// DKG run cannot produce a valid PoK on the same phi_{i,0} because the
// verifier folds the (replayed) SessionNonce into the challenge, and no fresh
// run re-derives the same nonce. Mirrors frosttss/msgkeygen.go.
//
// EphPub is a fresh per-keygen X25519 public key (32 bytes). It is broadcast
// in round 1 so every other party can derive a per-pair AEAD key for the
// encrypted round-2 P2P share envelope (see crypto/frostenc). Without it,
// round-2 shares would be sent in cleartext and a passive eavesdropper plus
// t-1 corrupted parties could recover the master secret.
//
// The Schnorr PoK proves knowledge of a_{i,0} bound to phi_{i,0}. The proof's
// announcement R is encoded as a 32-byte Ristretto255 element; t is a 32-byte
// little-endian scalar.
type keygenRound1msg struct {
	PolyCommitments [][]byte `json:"poly_commitments"`
	SessionNonce    []byte   `json:"session_nonce"`
	EphPub          []byte   `json:"eph_pub"`
	SchnorrR        []byte   `json:"schnorr_r"`
	SchnorrT        []byte   `json:"schnorr_t"`
}

// keygenSessionNonceLen is the length in bytes of the per-party fresh session
// nonce included in keygenRound1msg. 16 bytes = 128 bits of entropy, far past
// birthday-collision risk for any realistic DKG count.
const keygenSessionNonceLen = 16

// keygenCommitmentBytes is the canonical encoded length of a single
// Ristretto255 group element on the wire. Used as a length cap when decoding
// untrusted round-1 messages.
const keygenCommitmentBytes = 32

// keygenScalarBytes is the canonical encoded length of a Ristretto255 scalar
// (mod L). Used as a length cap when decoding untrusted messages.
const keygenScalarBytes = 32

// keygenRound2msg sends the P2P VSS share f_i(x_j).
//
// As of the encrypted-shares hardening, the share is no longer emitted in
// plaintext: it is sealed under an X25519+HKDF+ChaCha20-Poly1305 envelope
// (see crypto/frostenc) keyed by the sender's and recipient's ephemeral
// X25519 keys broadcast in round 1. Ciphertext is nonce || aead.Seal(...).
//
// Associated data: keygenRound2AD(senderSessionNonce, senderPub, recipientPub)
// — see keygen.go.
type keygenRound2msg struct {
	Ciphertext []byte `json:"ciphertext"`
}
