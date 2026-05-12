package frostristretto255tss

// resharingRound1msg broadcasts the master GroupPublicKey (32-byte
// Ristretto255) and a hash commitment over the re-share-VSS polynomial.
type resharingRound1msg struct {
	GroupPublicKey []byte `json:"group_public_key"`
	VCommitment    []byte `json:"v_commitment"`
}

// resharingRound2msg is an empty ACK from new committee to old.
type resharingRound2msg struct{}

// resharingRound3msg1 P2P share to a new committee party (32-byte LE scalar).
type resharingRound3msg1 struct {
	Share []byte `json:"share"`
}

// resharingRound3msg2 broadcasts the decommitment for the re-share-VSS
// polynomial (each Feldman commitment as a 32-byte canonical Ristretto255).
type resharingRound3msg2 struct {
	VDecommitment [][]byte `json:"v_decommitment"`
}

// resharingRound4msg is an empty ACK once new committee derives its share.
type resharingRound4msg struct{}
