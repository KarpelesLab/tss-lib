package mldsatss

import (
	"errors"

	"github.com/KarpelesLab/mldsa"
)

// PublicKey is a threshold ML-DSA-44 public key. It is byte-identical to a
// stock FIPS 204 public key and can be used with mldsa.PublicKey44.Verify.
type PublicKey = mldsa.PublicKey44

// Share44 is one (s1, s2) share held by a party for a specific honest-signer
// subset. The share's identity is the subset mask under which it was drawn.
type Share44 struct {
	S1  [mldsa.L44]mldsa.RingElement // plain domain
	S2  [mldsa.K44]mldsa.RingElement
	S1h [mldsa.L44]mldsa.NttElement // cached NTT(S1)
	S2h [mldsa.K44]mldsa.NttElement // cached NTT(S2)
}

// Key44 is one party's full secret-key material for threshold ML-DSA-44.
// It contains all shares whose honest-signer mask includes this party's Id,
// plus the public t1 vector needed for signature assembly.
type Key44 struct {
	Id     uint8                                   `json:"id"`
	Rho    [32]byte                                `json:"rho"`
	Tr     [64]byte                                `json:"tr"`
	T1     [mldsa.K44]mldsa.RingElement            `json:"t1"`
	Shares map[uint8]*Share44                      `json:"shares"`
	A      [mldsa.K44 * mldsa.L44]mldsa.NttElement `json:"-"` // reconstructed from Rho
}

// ensureMatrix populates k.A from k.Rho if it has not been cached yet.
func (k *Key44) ensureMatrix() {
	// Detect empty matrix via first row's first coefficient
	// (the all-zero NTT polynomial is a vanishingly unlikely ExpandA output).
	var zero mldsa.NttElement
	if k.A[0] == zero {
		for i := 0; i < mldsa.K44; i++ {
			for j := 0; j < mldsa.L44; j++ {
				k.A[i*mldsa.L44+j] = mldsa.SampleA(k.Rho[:], i, j)
			}
		}
	}
}

// A returns the cached public matrix, expanding from Rho on first access.
func (k *Key44) Matrix() *[mldsa.K44 * mldsa.L44]mldsa.NttElement {
	k.ensureMatrix()
	return &k.A
}

// Share returns the share indexed by mask, or nil if this party does not hold it.
func (k *Key44) Share(mask uint8) *Share44 {
	if k.Shares == nil {
		return nil
	}
	return k.Shares[mask]
}

// AddShare inserts or replaces a share. If s1h/s2h are zero-valued the NTT
// caches are recomputed from S1/S2 here.
func (k *Key44) AddShare(mask uint8, s *Share44) {
	if k.Shares == nil {
		k.Shares = make(map[uint8]*Share44)
	}
	// Populate NTT caches if they look empty.
	var zeroNtt mldsa.NttElement
	if s.S1h[0] == zeroNtt {
		for i := 0; i < mldsa.L44; i++ {
			s.S1h[i] = mldsa.NTT(s.S1[i])
		}
	}
	if s.S2h[0] == zeroNtt {
		for i := 0; i < mldsa.K44; i++ {
			s.S2h[i] = mldsa.NTT(s.S2[i])
		}
	}
	k.Shares[mask] = s
}

// Validate checks that k is well-formed.
func (k *Key44) Validate() error {
	if k.Shares == nil || len(k.Shares) == 0 {
		return errors.New("mldsatss: key has no shares")
	}
	for mask := range k.Shares {
		if mask&(1<<k.Id) == 0 {
			return errors.New("mldsatss: key holds a share whose mask does not include its own Id")
		}
	}
	return nil
}

// Destroy best-effort wipes every secret share held by this key (both the
// plain and NTT-domain s1/s2 polynomials) and clears the share map. The
// public fields (Rho, Tr, T1, A) are left intact. Like the package's other
// zeroization, this is best-effort: Go's GC may already have copied the
// secret elsewhere. After Destroy, the key can no longer participate in
// signing (Validate will fail with "key has no shares").
func (k *Key44) Destroy() {
	for _, sh := range k.Shares {
		if sh == nil {
			continue
		}
		for i := range sh.S1 {
			for j := range sh.S1[i] {
				sh.S1[i][j] = 0
			}
		}
		for i := range sh.S2 {
			for j := range sh.S2[i] {
				sh.S2[i][j] = 0
			}
		}
		for i := range sh.S1h {
			for j := range sh.S1h[i] {
				sh.S1h[i][j] = 0
			}
		}
		for i := range sh.S2h {
			for j := range sh.S2h[i] {
				sh.S2h[i][j] = 0
			}
		}
	}
	k.Shares = nil
}

// recoverShare reconstructs this party's contribution (s1, s2 in NTT form) to
// the aggregated secret for the signing set described by act. It follows the
// sharing-pattern reconstruction used in the reference implementation.
func (k *Key44) recoverShare(act uint8, params *ThresholdParams44) (s1h [mldsa.L44]mldsa.NttElement, s2h [mldsa.K44]mldsa.NttElement, err error) {
	// Trivial cases: t == 1 (not allowed here) or t == n (each party holds
	// exactly one share, the full-signer mask).
	if params.T == params.N {
		for _, sh := range k.Shares {
			s1h = sh.S1h
			s2h = sh.S2h
			return
		}
		return s1h, s2h, errors.New("mldsatss: recoverShare(t==n): no shares")
	}

	pattern := getSharingPattern(params.T, params.N)
	if pattern == nil {
		return s1h, s2h, errors.New("mldsatss: no sharing pattern for (t,n)")
	}

	// perm[0..T-1] = ids in act (sorted low-to-high),
	// perm[T..N-1] = ids not in act (sorted low-to-high).
	var perm [MaxParties]uint8
	i1, i2 := uint8(0), params.T
	currenti := -1
	for j := uint8(0); j < params.N; j++ {
		if j == k.Id {
			currenti = int(i1)
		}
		if act&(1<<j) != 0 {
			perm[i1] = j
			i1++
		} else {
			perm[i2] = j
			i2++
		}
	}
	if currenti < 0 || currenti >= int(params.T) {
		return s1h, s2h, errors.New("mldsatss: this key is not in the signing set")
	}
	patternForMe := pattern[currenti]

	for _, u := range patternForMe {
		// Translate the abstract mask u (over permuted positions) to the real
		// mask u_ (over party Ids) using perm.
		var uReal uint8
		for i := uint8(0); i < params.N; i++ {
			if u&(1<<i) != 0 {
				uReal |= 1 << perm[i]
			}
		}
		share := k.Shares[uReal]
		if share == nil {
			return s1h, s2h, errors.New("mldsatss: missing share in sharing pattern")
		}
		for j := 0; j < mldsa.L44; j++ {
			s1h[j] = mldsa.PolyAdd(s1h[j], share.S1h[j])
		}
		for j := 0; j < mldsa.K44; j++ {
			s2h[j] = mldsa.PolyAdd(s2h[j], share.S2h[j])
		}
	}
	return s1h, s2h, nil
}
