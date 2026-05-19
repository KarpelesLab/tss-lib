package dklstss

// Wire-message Go structs for DKLs23 signing. Same convention as
// msgkeygen.go: plain Go structs serialized as JSON via tss.JsonWrap.

// SignRound1msg is the broadcast nonce commitment K_i = k_i · G from
// signer i. 33-byte compressed-point encoding.
type SignRound1msg struct {
	Ki []byte `json:"k_i"`
}

// SignMulAliceMsg is one direction of a ΠMul invocation: Alice's OT
// extension envelope. Sent P2P from one signer to one peer.
type SignMulAliceMsg struct {
	L uint32   `json:"l"`       // L=256 for secp256k1 ΠMul
	U [][]byte `json:"u"`       // Kappa rows, each L/8 bytes
	X []byte   `json:"x_check"` // SigmaBytes bits packed
	T []byte   `json:"t_check"` // Sigma · DeltaBytes flat-packed
}

// SignMulBobMsg is Bob's reply to one ΠMul invocation: ScalarBits
// correction values, each a big-endian scalar in [0, q).
type SignMulBobMsg struct {
	Corrections [][]byte `json:"corrections"`
}

// SignCheckedMulBobMsg is the malicious-secure variant carrying both
// parallel ΠMul corrections and the cross-run consistency value Z.
type SignCheckedMulBobMsg struct {
	Msg1 *SignMulBobMsg `json:"msg1"`
	Msg2 *SignMulBobMsg `json:"msg2"`
	Z    []byte         `json:"z"` // big-endian scalar
}

// SignRound3msg is the broadcast reveal of each signer's φ_i = k_i·ρ_i
// share and ŝ_i = ρ_i·H(m) + r·σ_i share. The aggregator computes
// φ = Σ φ_i, ŝ = Σ ŝ_i, then s = ŝ · φ^{-1} mod q.
type SignRound3msg struct {
	Phi  []byte `json:"phi"`
	Shat []byte `json:"shat"`
}

// Message-type strings.
const (
	SignMsgTypeRound1        = "dkls:sign:round1"
	SignMsgTypeMulAlice      = "dkls:sign:mul:alice"
	SignMsgTypeMulBob        = "dkls:sign:mul:bob"
	SignMsgTypeCheckedMulBob = "dkls:sign:checkedmul:bob"
	SignMsgTypeRound3        = "dkls:sign:round3"
)
