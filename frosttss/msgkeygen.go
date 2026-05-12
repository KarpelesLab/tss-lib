package frosttss

// keygenRound1msg is broadcast by every party in round 1 of the FROST DKG
// (RFC 9591 Appendix D). It carries the participant's Feldman commitments
// (phi_{i,0}..phi_{i,t}) and a Schnorr proof of knowledge of a_{i,0} — the
// constant coefficient (= the participant's secret) — bound to phi_{i,0}.
//
// Commitments are encoded as canonical 32-byte Ed25519 points, in coefficient
// order. The Schnorr PoK uses crypto/schnorr.NewZKProof with a per-party
// session context — see frosttss/keygen.go for the exact context bytes.
type keygenRound1msg struct {
	PolyCommitments    [][]byte `json:"poly_commitments"`
	SchnorrProofAlphaX []byte   `json:"schnorr_proof_alpha_x"`
	SchnorrProofAlphaY []byte   `json:"schnorr_proof_alpha_y"`
	SchnorrProofT      []byte   `json:"schnorr_proof_t"`
}

// keygenRound2msg is sent point-to-point in round 2 of the FROST DKG. Each
// participant sends every other participant their evaluation of the local
// polynomial at the recipient's identifier: Share = f_i(x_j) mod L.
type keygenRound2msg struct {
	Share []byte `json:"share"`
}
