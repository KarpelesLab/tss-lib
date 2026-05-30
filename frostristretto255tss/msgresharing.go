package frostristretto255tss

// resharingRound1msg is broadcast by every old-committee participant to all
// new-committee participants. It carries the master GroupPublicKey (so new
// parties can detect inconsistency), the dealer's claimed constant term
// vi[0] = wi*G with a Schnorr PoK of knowledge of wi (so a coalition of
// colluding old parties cannot covertly rebalance their individual wi
// contributions while keeping the aggregate equal to the master pubkey), a
// fresh per-reshare session nonce folded into the PoK challenge, and a hash
// commitment to the re-share-VSS polynomial. Decommitment is sent in round 3.
//
// The receiver verifies vi[0]/PoK in round 2 (round2New); a dealer whose Vi0
// is identity or whose PoK fails is rejected. Cross-check at finalize
// (round4New): the round-1 Vi0 must equal the round-3 decommit's vi[0]. A
// mismatch is dealer equivocation between rounds. Mirrors
// frosttss/msgresharing.go.
type resharingRound1msg struct {
	GroupPublicKey []byte `json:"group_public_key"` // 32-byte canonical Ristretto255
	Vi0            []byte `json:"vi0"`              // 32-byte canonical Ristretto255, vi[0] = wi*G
	SessionNonce   []byte `json:"session_nonce"`    // 16 bytes; fresh per reshare run
	SchnorrR       []byte `json:"schnorr_r"`        // 32-byte Ristretto255 announcement
	SchnorrT       []byte `json:"schnorr_t"`        // 32-byte LE scalar
	VCommitment    []byte `json:"v_commitment"`     // SHA-512 hash commitment over the VSS poly
}

// resharingSessionNonceLen is the length in bytes of the per-dealer fresh
// session nonce included in resharingRound1msg. Matches keygen.
const resharingSessionNonceLen = 16

// resharingRound2msg is sent by every new-committee participant back to the old
// committee after consistent receipt of round-1 messages. It carries the new
// party's fresh ephemeral X25519 public key and session nonce so old dealers
// can seal the round-3-1 P2P share under the crypto/frostenc envelope.
type resharingRound2msg struct {
	EphPub       []byte `json:"eph_pub"`       // 32-byte X25519 public key
	SessionNonce []byte `json:"session_nonce"` // 16 bytes; fresh per reshare run
}

// resharingRound3msg1 is the P2P re-share VSS share f_i(x_j) from an old
// participant to a new participant. As of the encrypted-shares hardening it is
// sealed under the crypto/frostenc envelope (X25519 + HKDF + ChaCha20-Poly1305)
// keyed by the old dealer's ephemeral key and the new party's EphPub from
// round 2. Ciphertext is nonce || aead.Seal(...).
type resharingRound3msg1 struct {
	EphPub     []byte `json:"eph_pub"`    // old dealer's 32-byte X25519 public key
	Ciphertext []byte `json:"ciphertext"` // sealed share scalar
}

// resharingRound3msg2 broadcasts the decommitment for the re-share-VSS
// polynomial (each Feldman commitment as a 32-byte canonical Ristretto255).
type resharingRound3msg2 struct {
	VDecommitment [][]byte `json:"v_decommitment"`
}

// resharingRound4msg is an empty ACK once a new-committee party derives its
// new share.
type resharingRound4msg struct{}
