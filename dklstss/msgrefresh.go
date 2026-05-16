package dklstss

// Wire-message Go structs for DKLs23 proactive refresh.

// RefreshRound1Broadcast carries one dealer's Feldman commitments to
// its zero-constant-term polynomial: V_1..V_T (no V_0 since the
// constant term is 0).
type RefreshRound1Broadcast struct {
	VSSCommitments [][]byte `json:"vss_commitments"`
}

// RefreshRound1Unicast is the per-recipient share f_i(id_j) from
// dealer i to recipient j. f_i has zero constant term.
type RefreshRound1Unicast struct {
	Share []byte `json:"share"`
}

// Re-OT-setup phase reuses KeygenOTSetupSenderMsg and
// KeygenOTSetupReceiverMsg from msgkeygen.go — the wire format of
// base-OT setup is the same whether triggered by DKG or refresh; the
// dispatcher tag is what differs.

// Message-type strings.
const (
	RefreshMsgTypeRound1Broadcast = "dkls:refresh:round1bc"
	RefreshMsgTypeRound1Unicast   = "dkls:refresh:round1uc"
	RefreshMsgTypeOTSetupSender   = "dkls:refresh:otsetup:sender"
	RefreshMsgTypeOTSetupReceiver = "dkls:refresh:otsetup:receiver"
)
