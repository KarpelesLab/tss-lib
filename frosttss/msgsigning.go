package frosttss

// signRound1msg is broadcast by every signer in FROST signing round 1
// (preprocessing). It carries the signer's nonce commitments D_i = d_i*G and
// E_i = e_i*G, encoded as 32-byte canonical Ed25519 points.
type signRound1msg struct {
	Hiding  []byte `json:"hiding"`  // D_i
	Binding []byte `json:"binding"` // E_i
}

// signRound2msg is broadcast by every signer in FROST signing round 2 (sign).
// It carries the partial signature scalar z_i, encoded as 32-byte LE.
type signRound2msg struct {
	Z []byte `json:"z"`
}
