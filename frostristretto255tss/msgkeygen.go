package frostristretto255tss

// keygenRound1msg is broadcast by every party in round 1 of the FROST DKG.
// PolyCommitments holds each coefficient's commitment phi_{i,j} = a_{i,j}*G,
// encoded as 32-byte canonical Ristretto255 points in coefficient order.
//
// The Schnorr PoK proves knowledge of a_{i,0} bound to phi_{i,0}. The proof's
// announcement R is encoded as a 32-byte Ristretto255 element; t is a 32-byte
// little-endian scalar.
type keygenRound1msg struct {
	PolyCommitments [][]byte `json:"poly_commitments"`
	SchnorrR        []byte   `json:"schnorr_r"`
	SchnorrT        []byte   `json:"schnorr_t"`
}

// keygenRound2msg sends the P2P VSS share f_i(x_j) as a 32-byte LE scalar.
type keygenRound2msg struct {
	Share []byte `json:"share"`
}
