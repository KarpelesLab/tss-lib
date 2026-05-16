package otext

import (
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
)

// SigmaBytes is the byte length of the receiver's x vector in the
// consistency check. Sigma bits packed little-endian.
const SigmaBytes = Sigma / 8

// ExtendMsg1 is the message ExtReceiver sends to ExtSender during
// extension. It carries the IKNP correction rows U and the KOS-style
// consistency-check fields X, T which are verified by the sender before
// the OT extension outputs may be consumed by any higher-level protocol.
//
// Wire size: Kappa * (L/8) + SigmaBytes + Sigma * DeltaBytes bytes.
// For Kappa=128, Sigma=80, DeltaBytes=16: 16L + 10 + 1280 bytes.
type ExtendMsg1 struct {
	L int
	U [][]byte                // length Kappa; each row L/8 bytes
	X [SigmaBytes]byte        // σ bits packed
	T [Sigma][DeltaBytes]byte // σ rows of κ bits each
}

// hashRow is the random-oracle output of the protocol: it maps a κ-bit
// column vector v to a KeyLen-byte key, with sid and row-index domain
// separation. Both the receiver (with v = T-column[i]) and the sender
// (with v = q-column[i] or q-column[i] ⊕ Δ) call this with matching
// (sid, i) for the receiver-chosen output to align with sender's m_{c_i}.
//
// We bypass common.SHA512_256i_TAGGED here because that helper interprets
// inputs as big.Ints (which strips leading zero bytes); the OT row v is a
// fixed-width bit string whose value depends on every byte including
// leading zeros, so we hash it byte-exact.
func hashRow(sid []byte, i int, v []byte) [KeyLen]byte {
	h := sha512.New512_256()

	// Domain separation tag.
	tag := sha512.Sum512_256([]byte("DKLS23-otext-row-v1"))
	h.Write(tag[:])
	h.Write(tag[:])

	var buf8 [8]byte

	binary.LittleEndian.PutUint64(buf8[:], uint64(len(sid)))
	h.Write(buf8[:])
	h.Write(sid)

	binary.LittleEndian.PutUint64(buf8[:], uint64(i))
	h.Write(buf8[:])

	binary.LittleEndian.PutUint64(buf8[:], uint64(len(v)))
	h.Write(buf8[:])
	h.Write(v)

	var out [KeyLen]byte
	copy(out[:], h.Sum(nil))
	return out
}

// deriveChallenges produces the σ Fiat-Shamir challenge vectors χ_h ∈
// {0,1}^L used by the consistency check. The challenge is bound to
// (sid, L, U) via a tagged SHA-512/256 hash, expanded with AES-CTR.
func deriveChallenges(sid []byte, u [][]byte, l int) [][]byte {
	hh := sha512.New512_256()
	tag := sha512.Sum512_256([]byte("DKLS23-otext-coin-v1"))
	hh.Write(tag[:])
	hh.Write(tag[:])

	var buf8 [8]byte
	binary.LittleEndian.PutUint64(buf8[:], uint64(len(sid)))
	hh.Write(buf8[:])
	hh.Write(sid)

	binary.LittleEndian.PutUint64(buf8[:], uint64(l))
	hh.Write(buf8[:])

	binary.LittleEndian.PutUint64(buf8[:], uint64(len(u)))
	hh.Write(buf8[:])

	for j := range u {
		binary.LittleEndian.PutUint64(buf8[:], uint64(len(u[j])))
		hh.Write(buf8[:])
		hh.Write(u[j])
	}

	var seed [SeedLen]byte
	copy(seed[:], hh.Sum(nil))

	lb := l / 8
	// Tagged with a literal "challenges" label so this expansion is
	// domain-separated from the t0/t1 expansions in Extend below — both
	// take the same sid but a different seed (the FS coin-seed vs the
	// base-OT seeds), and the tag makes the separation explicit.
	expand := prgExpand(seed, []byte("DKLS23-otext-challenges-v1"), Sigma*lb)
	chi := make([][]byte, Sigma)
	for h := 0; h < Sigma; h++ {
		chi[h] = expand[h*lb : (h+1)*lb]
	}
	return chi
}

// Extend runs the OT extension RECEIVER protocol.
//
// c packs L choice bits in little-endian-within-byte order (the i-th bit
// is (c[i/8] >> (i%8)) & 1). L must be a positive multiple of 8 and the
// length of c in bits must be at least L.
//
// Returns the message to send to ExtSender and the receiver's L output
// keys, where keys[i] equals the sender's m_{c_i}[i]. The returned
// ExtendMsg1 includes the KOS consistency-check fields.
func (r *ExtReceiver) Extend(sid []byte, c []byte, l int) (*ExtendMsg1, [][KeyLen]byte, error) {
	if err := validateExtendInputs(l); err != nil {
		return nil, nil, err
	}
	if len(c)*8 < l {
		return nil, nil, fmt.Errorf("otext: choice buffer holds %d bits, need at least %d", len(c)*8, l)
	}
	lb := l / 8

	// Expand each seed pair to an L-bit PRG output. The sid argument
	// keys the per-call PRG derivation so that two Extend invocations
	// against the SAME (seeds0, seeds1) but different sid produce
	// independent t0/t1 — without this, the wire message
	// u_j = t0[j] ⊕ t1[j] ⊕ c would reuse the t0⊕t1 mask across calls
	// and leak the XOR of the receiver's choice bits to the sender.
	t0 := make([][]byte, Kappa)
	t1 := make([][]byte, Kappa)
	for j := 0; j < Kappa; j++ {
		t0[j] = prgExpand(r.seeds0[j], sid, lb)
		t1[j] = prgExpand(r.seeds1[j], sid, lb)
	}

	// For each j: u_j = t_{j,0} XOR t_{j,1} XOR c (truncated to L bits).
	u := make([][]byte, Kappa)
	for j := 0; j < Kappa; j++ {
		u[j] = make([]byte, lb)
		for b := 0; b < lb; b++ {
			u[j][b] = t0[j][b] ^ t1[j][b] ^ c[b]
		}
	}

	// Transpose t0 from a (κ × L) bit matrix to (L × κ).
	v := transposeBits(t0, Kappa, l)

	// Derive σ Fiat-Shamir challenges χ_h ∈ {0,1}^L from (sid, L, U).
	chi := deriveChallenges(sid, u, l)

	// Compute consistency-check outputs.
	//   x_h = XOR over i in [L] of (c[i] AND χ_h[i])           // 1 bit
	//   T_h = XOR over i in [L] of (v[i] AND χ_h[i])           // κ bits
	var xCheck [SigmaBytes]byte
	var tCheck [Sigma][DeltaBytes]byte
	for h := 0; h < Sigma; h++ {
		var xbit byte
		for byteIdx := 0; byteIdx < lb; byteIdx++ {
			selected := chi[h][byteIdx] & c[byteIdx]
			// XOR-popcount of the selected bits into xbit.
			xbit ^= popcountByte(selected) & 1
			// XOR-sum v[i] for every i where χ_h[i] = 1.
			chiByte := chi[h][byteIdx]
			if chiByte == 0 {
				continue
			}
			base := byteIdx * 8
			for bit := 0; bit < 8; bit++ {
				if (chiByte>>uint(bit))&1 == 1 {
					i := base + bit
					if i >= l {
						break
					}
					for b := 0; b < DeltaBytes; b++ {
						tCheck[h][b] ^= v[i][b]
					}
				}
			}
		}
		if xbit == 1 {
			xCheck[h/8] |= 1 << (uint(h) & 7)
		}
	}

	// Receiver's output: H(sid, i, v[i]) for each row i.
	keys := make([][KeyLen]byte, l)
	for i := 0; i < l; i++ {
		keys[i] = hashRow(sid, i, v[i])
	}

	return &ExtendMsg1{L: l, U: u, X: xCheck, T: tCheck}, keys, nil
}

// Extend runs the OT extension SENDER protocol given the receiver's
// message. Returns m0, m1: two slices of length L where m_b[i] is the
// sender's i-th output for choice bit b. The receiver's output equals
// m_{c_i}[i].
//
// The KOS consistency check is verified before the outputs are returned;
// if the check fails the function returns ErrCheckFailed and produces no
// OT outputs.
func (s *ExtSender) Extend(sid []byte, msg *ExtendMsg1) (m0, m1 [][KeyLen]byte, err error) {
	if msg == nil {
		return nil, nil, errors.New("otext: Extend got nil message")
	}
	if err := validateExtendInputs(msg.L); err != nil {
		return nil, nil, err
	}
	if len(msg.U) != Kappa {
		return nil, nil, fmt.Errorf("otext: U has length %d, expected %d", len(msg.U), Kappa)
	}
	l := msg.L
	lb := l / 8
	for j := 0; j < Kappa; j++ {
		if len(msg.U[j]) != lb {
			return nil, nil, fmt.Errorf("otext: U[%d] length %d, expected %d", j, len(msg.U[j]), lb)
		}
	}

	// For each j: q_j = PRG(seed_{j,Δ_j}, sid) XOR (Δ_j · u_j). The sid
	// must match the value the receiver passed to its own prgExpand so
	// the sender's expansion lines up with t_{Δ_j}[j]; this is the
	// per-call PRG keying that prevents seed reuse across Extend calls.
	q := make([][]byte, Kappa)
	for j := 0; j < Kappa; j++ {
		deltaBit := (s.delta[j/8] >> (uint(j) & 7)) & 1
		expansion := prgExpand(s.seeds[j], sid, lb)
		if deltaBit == 1 {
			q[j] = make([]byte, lb)
			for b := 0; b < lb; b++ {
				q[j][b] = expansion[b] ^ msg.U[j][b]
			}
		} else {
			q[j] = expansion
		}
	}

	// Transpose q from (κ × L) to (L × κ).
	qT := transposeBits(q, Kappa, l)

	// Re-derive challenges (FS, must match receiver).
	chi := deriveChallenges(sid, msg.U, l)

	// Verify the consistency check: for each h in [σ],
	//   T'_h := XOR over i in [L] of (q-column[i] AND χ_h[i])
	//   verify T'_h == msg.T[h] XOR (msg.X bit h) · Δ
	for h := 0; h < Sigma; h++ {
		var tPrime [DeltaBytes]byte
		for byteIdx := 0; byteIdx < lb; byteIdx++ {
			chiByte := chi[h][byteIdx]
			if chiByte == 0 {
				continue
			}
			base := byteIdx * 8
			for bit := 0; bit < 8; bit++ {
				if (chiByte>>uint(bit))&1 == 1 {
					i := base + bit
					if i >= l {
						break
					}
					for b := 0; b < DeltaBytes; b++ {
						tPrime[b] ^= qT[i][b]
					}
				}
			}
		}

		xBit := (msg.X[h/8] >> (uint(h) & 7)) & 1
		var expected [DeltaBytes]byte
		for b := 0; b < DeltaBytes; b++ {
			expected[b] = msg.T[h][b]
			if xBit == 1 {
				expected[b] ^= s.delta[b]
			}
		}
		if expected != tPrime {
			return nil, nil, fmt.Errorf("otext: consistency check failed at h=%d", h)
		}
	}

	m0 = make([][KeyLen]byte, l)
	m1 = make([][KeyLen]byte, l)
	for i := 0; i < l; i++ {
		m0[i] = hashRow(sid, i, qT[i])
		// m_1[i] = H(qT[i] XOR Δ).
		xored := make([]byte, DeltaBytes)
		for b := 0; b < DeltaBytes; b++ {
			xored[b] = qT[i][b] ^ s.delta[b]
		}
		m1[i] = hashRow(sid, i, xored)
	}

	return m0, m1, nil
}

// popcountByte returns the parity-relevant popcount of a byte (low bit
// gives parity). Used only in the consistency-check loop; for small inputs
// a table or direct popcount is fine.
func popcountByte(b byte) byte {
	b = b - ((b >> 1) & 0x55)
	b = (b & 0x33) + ((b >> 2) & 0x33)
	return (b + (b >> 4)) & 0x0F
}
