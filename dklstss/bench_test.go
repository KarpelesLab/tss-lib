package dklstss

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

// BenchmarkKeygen measures distributed-key-generation cost at representative
// (n, t) sizes. Both VSS rounds and the O(n²) pairwise OT setup are
// included.
func BenchmarkKeygen(b *testing.B) {
	cases := []struct{ n, t int }{
		{2, 1}, // 2-of-2
		{3, 1}, // 2-of-3
		{5, 2}, // 3-of-5
	}
	for _, tc := range cases {
		name := nameFor(tc.n, tc.t)
		b.Run(name, func(b *testing.B) {
			ids := genPartyIDs(tc.n)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := Keygen(tc.n, tc.t, ids, rand.Reader)
				if err != nil {
					b.Fatalf("Keygen: %v", err)
				}
			}
		})
	}
}

// BenchmarkSign measures combined-signing throughput.
func BenchmarkSign(b *testing.B) {
	cases := []struct {
		n, t   int
		subset []int
	}{
		{2, 1, []int{0, 1}},
		{3, 1, []int{0, 1}},
		{5, 2, []int{0, 1, 2}},
	}
	for _, tc := range cases {
		keys, err := Keygen(tc.n, tc.t, genPartyIDs(tc.n), rand.Reader)
		if err != nil {
			b.Fatalf("setup keygen: %v", err)
		}
		digest := sha256.Sum256([]byte("bench-sign"))
		b.Run(nameFor(tc.n, tc.t), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := Sign(keys, tc.subset, digest[:], rand.Reader)
				if err != nil {
					b.Fatalf("Sign: %v", err)
				}
			}
		})
	}
}

// BenchmarkPresignThenSign measures offline+online split costs separately.
func BenchmarkPresignThenSign(b *testing.B) {
	keys, err := Keygen(3, 1, genPartyIDs(3), rand.Reader)
	if err != nil {
		b.Fatalf("setup: %v", err)
	}
	b.Run("Presign-3-of-3", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := Presign(keys, []int{0, 1}, rand.Reader); err != nil {
				b.Fatalf("Presign: %v", err)
			}
		}
	})

	// Pre-generate presigns to amortize Presign cost in SignWithPresign.
	presigns := make([]*PresignOutput, 0, 1024)
	b.Run("SignWithPresign-3-of-3", func(b *testing.B) {
		for len(presigns) < b.N {
			p, err := Presign(keys, []int{0, 1}, rand.Reader)
			if err != nil {
				b.Fatalf("setup presign: %v", err)
			}
			presigns = append(presigns, p)
		}
		digest := sha256.Sum256([]byte("bench-online"))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := SignWithPresign(presigns[i], digest[:], nil); err != nil {
				b.Fatalf("SignWithPresign: %v", err)
			}
		}
	})
}

// BenchmarkRefresh measures proactive refresh cost.
func BenchmarkRefresh(b *testing.B) {
	cases := []struct{ n, t int }{
		{2, 1},
		{3, 1},
		{5, 2},
	}
	for _, tc := range cases {
		keys, err := Keygen(tc.n, tc.t, genPartyIDs(tc.n), rand.Reader)
		if err != nil {
			b.Fatalf("setup: %v", err)
		}
		b.Run(nameFor(tc.n, tc.t), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := Refresh(keys, rand.Reader); err != nil {
					b.Fatalf("Refresh: %v", err)
				}
			}
		})
	}
}

// BenchmarkDeriveAndSign measures HD-derive-then-sign throughput.
func BenchmarkDeriveAndSign(b *testing.B) {
	keys, err := Keygen(3, 1, genPartyIDs(3), rand.Reader)
	if err != nil {
		b.Fatalf("setup: %v", err)
	}
	path := []uint32{44, 0, 0, 0, 7}
	digest := sha256.Sum256([]byte("bench-hd"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := DeriveAndSign(keys, []int{0, 1}, path, digest[:], rand.Reader); err != nil {
			b.Fatalf("DeriveAndSign: %v", err)
		}
	}
}

func nameFor(n, t int) string {
	return string(rune('0'+t+1)) + "-of-" + string(rune('0'+n))
}
