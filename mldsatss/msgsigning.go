package mldsatss

// Wire messages for threshold ML-DSA-44 signing. Each message is JSON-marshalled
// and routed via tss.MessageBroker under a fixed type name.

// Message type strings routed through tss.MessageBroker.
const (
	MsgTypeR1_44 = "mldsa44:sign:round1"
	MsgTypeR2_44 = "mldsa44:sign:round2"
	MsgTypeR3_44 = "mldsa44:sign:round3"
)

// signRound1msg44 is the hash commitment to a party's K parallel
// (w₀ … w_{K−1}) vectors.
type signRound1msg44 struct {
	Commit []byte `json:"commit"` // 32 bytes (SHAKE256 of tr || id || packed w's)
}

// signRound2msg44 reveals the raw packed w's whose hash was committed in Round 1.
type signRound2msg44 struct {
	Wbuf []byte `json:"wbuf"` // ThParams.K × K44 × mldsa.PackPolyQSize bytes
}

// signRound3msg44 is the per-party response — packed z_i for i ∈ [0, K).
//
// The z polynomials are packed with mldsa.PackZ17 / unpacked with
// mldsa.UnpackZ17, which use mldsa.EncodingSize18 (an 18-bit-per-coefficient
// encoding for γ₁ = 2^17). Despite the "Z17" in the helper names, the
// on-wire size per coefficient is 18 bits, hence EncodingSize18.
type signRound3msg44 struct {
	Resp []byte `json:"resp"` // ThParams.K × L44 × mldsa.EncodingSize18 bytes
}
