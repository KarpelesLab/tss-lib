package frosttss

// Resharing messages mirror the eddsatss resharing protocol shape but encode
// commitments as canonical 32-byte Ed25519 points to stay consistent with the
// rest of the frosttss wire format.

// resharingRound1msg is broadcast by every old-committee participant to all
// new-committee participants. It carries the master GroupPublicKey (so new
// parties can detect inconsistency), the dealer's claimed constant term
// vi[0] = wi*G with a Schnorr PoK of knowledge of wi (so a coalition of
// colluding old parties cannot covertly rebalance their individual wi
// contributions while keeping the aggregate equal to the master pubkey),
// and a hash commitment to the re-share-VSS polynomial. Decommitment is
// sent in round 3.
//
// The Schnorr PoK challenge binds the per-keygen-style session bytes
// (FROST context, "reshare-wi-pok", oldPartyKey, SessionNonce) to the
// witness wi via crypto/schnorr.NewZKProof. The receiver verifies in
// round 2 (round2New); a dealer whose Vi0 is identity or whose PoK fails
// is rejected with the dealer's PartyID in Culprits().
//
// Cross-check at finalize (round4New): the round-1 Vi0 must equal the
// round-3 decommit's vi[0]. A mismatch indicates equivocation between
// rounds.
type resharingRound1msg struct {
	GroupPublicKey     []byte `json:"group_public_key"`      // 32-byte canonical Ed25519
	Vi0                []byte `json:"vi0"`                   // 32-byte canonical Ed25519, vi[0] = wi*G
	SessionNonce       []byte `json:"session_nonce"`         // 16 bytes; fresh per reshare run
	SchnorrProofAlphaX []byte `json:"schnorr_proof_alpha_x"` // <= 32 bytes
	SchnorrProofAlphaY []byte `json:"schnorr_proof_alpha_y"` // <= 32 bytes
	SchnorrProofT      []byte `json:"schnorr_proof_t"`       // <= 32 bytes
	VCommitment        []byte `json:"v_commitment"`          // hash commitment over flat poly coords
}

// resharingSessionNonceLen is the length in bytes of the per-dealer fresh
// session nonce included in resharingRound1msg. Matches keygen.
const resharingSessionNonceLen = 16

// resharingRound2msg is an empty ACK sent by every new-committee participant
// back to the old committee after consistent receipt of round-1 messages.
type resharingRound2msg struct{}

// resharingRound3msg1 is sent P2P from each old participant to each new
// participant: the VSS share f_i(x_j) evaluated at the new participant's
// identifier.
type resharingRound3msg1 struct {
	Share []byte `json:"share"`
}

// resharingRound3msg2 is broadcast from each old participant to all new
// participants: the decommitment for the re-share-VSS polynomial.
type resharingRound3msg2 struct {
	VDecommitment [][]byte `json:"v_decommitment"`
}

// resharingRound4msg is an empty ACK sent by every new-committee participant
// to all other old+new participants once it has successfully derived its new
// share, allowing old committee parties to safely zero their old shares.
type resharingRound4msg struct{}
