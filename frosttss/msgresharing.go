package frosttss

// Resharing messages mirror the eddsatss resharing protocol shape but encode
// commitments as canonical 32-byte Ed25519 points to stay consistent with the
// rest of the frosttss wire format.

// resharingRound1msg is broadcast by every old-committee participant to all
// new-committee participants. It carries the master GroupPublicKey (so new
// parties can detect inconsistency) and a hash commitment to the
// re-share-VSS polynomial. Decommitment is sent in round 3.
type resharingRound1msg struct {
	GroupPublicKey []byte `json:"group_public_key"` // 32-byte canonical Ed25519
	VCommitment    []byte `json:"v_commitment"`     // hash commitment over flat poly coords
}

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
