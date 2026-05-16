package dklstss

// Wire-message Go structs for DKLs23 keygen. Each round's payload is a
// plain struct serialized as JSON inside a tss.JsonMessage envelope, in
// the same convention used by ecdsatss/eddsatss/frosttss. The protocol
// message-type strings ("dkls:keygen:roundN") select the receiver-side
// dispatcher.
//
// Note: the synchronous Keygen() entry point does not currently exchange
// wire messages — all parties live in-process. These types define the
// round-by-round wire format that a future broker-driven Party state
// machine will produce and consume. They are exported (capitalized
// fields) so a transport layer can serialize them without reflection
// gymnastics.

// KeygenRound1Broadcast carries one dealer's Feldman commitments to its
// degree-T polynomial: V_0..V_T (in that order). V_0 = u_i · G is the
// commitment to this party's contribution to the joint secret.
//
// Each entry is a 33-byte compressed-point encoding.
type KeygenRound1Broadcast struct {
	VSSCommitments [][]byte `json:"vss_commitments"`
}

// KeygenRound1Unicast carries the secret share f_i(id_j) sent unicast
// from dealer i to recipient j. Big-endian encoding of the scalar mod q.
type KeygenRound1Unicast struct {
	Share []byte `json:"share"`
}

// KeygenOTSetupSenderMsg is the base-OT sender's commitment S = y·G and
// the Schnorr proof of knowledge of y. Used in both directions of OT
// extension setup; reused between every pair of parties twice (once per
// direction).
type KeygenOTSetupSenderMsg struct {
	S          []byte `json:"s"`            // 33-byte compressed point
	PokAlphaX  []byte `json:"pok_alpha_x"`  // big-endian
	PokAlphaY  []byte `json:"pok_alpha_y"`  // big-endian
	PokT       []byte `json:"pok_t"`        // big-endian scalar
}

// KeygenOTSetupReceiverMsg is the base-OT receiver's reply: Kappa
// compressed-point encodings R_i = x_i·G + b_i·S for i ∈ [Kappa].
type KeygenOTSetupReceiverMsg struct {
	R [][]byte `json:"r"`
}

// Message-type strings used by the future broker-driven Party. Listed
// here for documentation; the actual dispatcher will JsonWrap each
// payload with one of these tags.
const (
	KeygenMsgTypeRound1Broadcast    = "dkls:keygen:round1bc"
	KeygenMsgTypeRound1Unicast      = "dkls:keygen:round1uc"
	KeygenMsgTypeOTSetupSender      = "dkls:keygen:otsetup:sender"
	KeygenMsgTypeOTSetupReceiver    = "dkls:keygen:otsetup:receiver"
)
