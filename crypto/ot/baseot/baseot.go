package baseot

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/crypto/ctmul"
	"github.com/KarpelesLab/tss-lib/v2/crypto/schnorr"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// KeyLen is the per-instance output key length in bytes. 32 bytes is
// sufficient for κ=128-bit security with a sha-512/256 derivation; the
// SoftSpokenOT extension layer treats each output as a PRG seed.
const KeyLen = 32

var (
	tagKey = []byte("DKLS23-baseot-key-v1")
	tagPoK = []byte("DKLS23-baseot-pok-v1")
)

// Sender holds Chou-Orlandi sender state across the two rounds. After
// Finalize is called, the secret scalar y is zeroized.
type Sender struct {
	sid []byte
	n   int
	y   *big.Int        // secret trapdoor; nil after Finalize
	S   *crypto.ECPoint // S = y·G (public)
}

// Receiver holds Chou-Orlandi receiver state across the two rounds. After
// Finalize is called, the per-instance scalars are zeroized.
type Receiver struct {
	sid  []byte
	n    int
	bits []byte     // packed choice bits, ceil(n/8) bytes
	x    []*big.Int // per-instance secret randomness; nil after Finalize
	S    *crypto.ECPoint
}

// SenderMsg1 is the sender's first-round message.
type SenderMsg1 struct {
	S   *crypto.ECPoint  // sender commitment S = y·G
	PoK *schnorr.ZKProof // Schnorr proof of knowledge of y for S
}

// ReceiverMsg1 is the receiver's first-round message: n response points
// R_i = x_i·G + c_i·S where c_i is the receiver's i-th choice bit.
type ReceiverMsg1 struct {
	R []*crypto.ECPoint
}

// NewSender creates a fresh sender state and produces the first-round
// message. n is the number of OT instances in this batch.
func NewSender(sid []byte, n int, rand io.Reader) (*Sender, *SenderMsg1, error) {
	if n <= 0 {
		return nil, nil, errors.New("baseot: NewSender requires n > 0")
	}
	if len(sid) == 0 {
		return nil, nil, errors.New("baseot: NewSender requires non-empty sid")
	}
	ec := tss.S256()
	q := ec.Params().N
	y := common.GetRandomPositiveInt(rand, q)

	// y is the sender's secret trapdoor — leaking it lets an attacker
	// recover both OT outputs (m_0 and m_1). Route y · G through the
	// constant-time scalar mult.
	S := ctmul.ScalarBaseMultWithRand(ec, y, rand)

	pok, err := schnorr.NewZKProof(pokSession(sid), y, S, rand)
	if err != nil {
		return nil, nil, fmt.Errorf("baseot: NewSender PoK: %w", err)
	}

	return &Sender{
		sid: append([]byte(nil), sid...),
		n:   n,
		y:   y,
		S:   S,
	}, &SenderMsg1{S: S, PoK: pok}, nil
}

// NewReceiver verifies the sender's first message and produces the
// receiver's response. bits must contain at least ceil(n/8) bytes; the i-th
// choice bit is (bits[i/8] >> (i%8)) & 1.
func NewReceiver(sid []byte, n int, bits []byte, msg *SenderMsg1, rand io.Reader) (*Receiver, *ReceiverMsg1, error) {
	if n <= 0 {
		return nil, nil, errors.New("baseot: NewReceiver requires n > 0")
	}
	if len(bits)*8 < n {
		return nil, nil, fmt.Errorf("baseot: NewReceiver bits buffer holds %d bits, need at least %d", len(bits)*8, n)
	}
	if msg == nil || msg.S == nil || msg.PoK == nil {
		return nil, nil, errors.New("baseot: NewReceiver got nil or incomplete sender message")
	}
	if !msg.S.ValidateBasic() {
		return nil, nil, errors.New("baseot: NewReceiver sender S is not a valid curve point")
	}
	if msg.S.Curve() != tss.S256() {
		return nil, nil, errors.New("baseot: NewReceiver sender S is on the wrong curve")
	}
	if !msg.PoK.Verify(pokSession(sid), msg.S) {
		return nil, nil, errors.New("baseot: NewReceiver Schnorr PoK on S failed verification")
	}

	ec := tss.S256()
	q := ec.Params().N
	x := make([]*big.Int, n)
	R := make([]*crypto.ECPoint, n)
	bitsCopy := append([]byte(nil), bits...)

	for i := 0; i < n; i++ {
		x[i] = common.GetRandomPositiveInt(rand, q)
		c := (bitsCopy[i/8] >> (uint(i) & 7)) & 1

		// x[i] is the receiver's per-instance secret; route x[i]·G
		// through the constant-time ladder so its bits don't leak via
		// scalar-mult timing.
		Ra := ctmul.ScalarBaseMult(ec, x[i])
		Rb, err := Ra.Add(msg.S)
		if err != nil {
			return nil, nil, fmt.Errorf("baseot: NewReceiver Add: %w", err)
		}
		// CT-select between Ra (c=0) and Rb (c=1). c is a bit of Δ
		// (the OT-Ext-Sender's long-term secret), so the selection
		// branch must not depend on its value at the byte level. We
		// XOR-blend the affine coordinates under a 0x00/0xFF mask;
		// neither branch is skipped.
		R[i] = ctSelectPoint(ec, c == 1, Ra, Rb)
	}
	_ = q

	return &Receiver{
		sid:  append([]byte(nil), sid...),
		n:    n,
		bits: bitsCopy,
		x:    x,
		S:    msg.S,
	}, &ReceiverMsg1{R: R}, nil
}

// ctSelectPoint returns b ? rb : ra in constant time at the
// byte-encoding level. The two candidate points must both be on the
// same curve (the caller arranges this — Ra, Rb = x·G, x·G + S share
// the curve trivially).
//
// math/big's arithmetic is not itself constant time, so this defence
// is "remove the data-dependent branch in the selection," not "make
// every step independent of secret bits." It is the contract layer
// the rest of the OT extension stack assumes.
func ctSelectPoint(curve elliptic.Curve, b bool, ra, rb *crypto.ECPoint) *crypto.ECPoint {
	var mask byte
	if b {
		mask = 0xFF
	}
	const coordBytes = 32 // secp256k1 field width
	var xa, ya, xb, yb [coordBytes]byte
	ra.X().FillBytes(xa[:])
	ra.Y().FillBytes(ya[:])
	rb.X().FillBytes(xb[:])
	rb.Y().FillBytes(yb[:])

	var xpick, ypick [coordBytes]byte
	for i := 0; i < coordBytes; i++ {
		xpick[i] = xa[i] ^ (mask & (xa[i] ^ xb[i]))
		ypick[i] = ya[i] ^ (mask & (ya[i] ^ yb[i]))
	}
	// Both candidate points are on-curve, so the selected (x, y) is
	// always one of them — skip the curve check to keep the helper
	// data-independent in the fast path.
	return crypto.NewECPointNoCurveCheck(curve,
		new(big.Int).SetBytes(xpick[:]),
		new(big.Int).SetBytes(ypick[:]))
}

// Finalize computes the sender's two output keys (k_{i,0}, k_{i,1}) for
// each instance i. After return, the sender's secret scalar y is zeroized
// and the Sender must not be used again.
func (s *Sender) Finalize(msg *ReceiverMsg1) (k0, k1 [][KeyLen]byte, err error) {
	if s == nil || s.y == nil {
		return nil, nil, errors.New("baseot: Sender.Finalize already consumed or not initialized")
	}
	if msg == nil || len(msg.R) != s.n {
		return nil, nil, fmt.Errorf("baseot: Sender.Finalize expected %d receiver responses, got %d", s.n, lenSafe(msg))
	}

	// yS = y·S = y²·G. Used in k_1 derivation: y·(R_i − S) = y·R_i − yS.
	// y is the sender's secret trapdoor; route through the CT scalar mult.
	yS := ctmul.ScalarMult(s.S, s.y)
	negYS := negPoint(yS)

	k0 = make([][KeyLen]byte, s.n)
	k1 = make([][KeyLen]byte, s.n)
	for i := 0; i < s.n; i++ {
		R := msg.R[i]
		if R == nil || !R.ValidateBasic() {
			return nil, nil, fmt.Errorf("baseot: Sender.Finalize R[%d] is not a valid curve point", i)
		}
		if R.Curve() != tss.S256() {
			return nil, nil, fmt.Errorf("baseot: Sender.Finalize R[%d] is on the wrong curve", i)
		}
		// y is secret. Each y·R_i lives in the key-derivation hash, so
		// timing leakage of y is a path to recovering both OT outputs.
		yR := ctmul.ScalarMult(R, s.y)
		k0[i] = deriveKey(s.sid, i, 0, yR)
		yRMinusYS, addErr := yR.Add(negYS)
		if addErr != nil {
			return nil, nil, fmt.Errorf("baseot: Sender.Finalize subtract: %w", addErr)
		}
		k1[i] = deriveKey(s.sid, i, 1, yRMinusYS)
	}

	s.y.SetInt64(0)
	s.y = nil
	return k0, k1, nil
}

// Finalize computes the receiver's chosen-key outputs k_{i, b_i} for each
// instance. After return, the receiver's per-instance scalars are zeroized
// and the Receiver must not be used again.
func (r *Receiver) Finalize() ([][KeyLen]byte, error) {
	if r == nil || r.x == nil {
		return nil, errors.New("baseot: Receiver.Finalize already consumed or not initialized")
	}
	keys := make([][KeyLen]byte, r.n)
	for i := 0; i < r.n; i++ {
		c := (r.bits[i/8] >> (uint(i) & 7)) & 1
		// x[i] is the receiver's per-instance secret scalar; route
		// x[i]·S through the constant-time ladder so the secret bits
		// do not leak via scalar-mult timing.
		xS := ctmul.ScalarMult(r.S, r.x[i])
		keys[i] = deriveKey(r.sid, i, int(c), xS)
	}
	for i := range r.x {
		if r.x[i] != nil {
			r.x[i].SetInt64(0)
			r.x[i] = nil
		}
	}
	r.x = nil
	return keys, nil
}

// N returns the number of OT instances configured for this sender/receiver.
func (s *Sender) N() int   { return s.n }
func (r *Receiver) N() int { return r.n }

// pokSession returns the domain-separated session label for the sender's
// Schnorr proof of knowledge.
func pokSession(sid []byte) []byte {
	out := make([]byte, 0, len(tagPoK)+len(sid))
	out = append(out, tagPoK...)
	out = append(out, sid...)
	return out
}

// deriveKey returns the tagged hash of (sid, instance, bit, P.X, P.Y),
// truncated/left-padded to KeyLen bytes.
func deriveKey(sid []byte, instance, bit int, P *crypto.ECPoint) [KeyLen]byte {
	tag := make([]byte, 0, len(tagKey)+len(sid))
	tag = append(tag, tagKey...)
	tag = append(tag, sid...)
	h := common.SHA512_256i_TAGGED(tag,
		new(big.Int).SetInt64(int64(instance)),
		new(big.Int).SetInt64(int64(bit)),
		P.X(),
		P.Y(),
	)
	var out [KeyLen]byte
	bz := h.Bytes()
	if len(bz) >= KeyLen {
		copy(out[:], bz[len(bz)-KeyLen:])
	} else {
		copy(out[KeyLen-len(bz):], bz)
	}
	return out
}

// negPoint returns the additive inverse of P on its curve: (X, -Y mod p).
func negPoint(P *crypto.ECPoint) *crypto.ECPoint {
	ec := P.Curve()
	p := ec.Params().P
	negY := new(big.Int).Neg(P.Y())
	negY.Mod(negY, p)
	return crypto.NewECPointNoCurveCheck(ec, P.X(), negY)
}

// lenSafe returns len(msg.R) or -1 if msg is nil; used only for error formatting.
func lenSafe(msg *ReceiverMsg1) int {
	if msg == nil {
		return -1
	}
	return len(msg.R)
}
