package ctmul

import (
	"crypto/rand"
	"math"
	"math/big"
	"runtime"
	"sort"
	"testing"
	"time"

	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// TestTimingNoSignificantBias is a dudect-style statistical timing test.
// Two scalar populations are compared:
//
//	A: scalars with a small fixed pattern (e.g. all zero except the high
//	   byte set to a small value)
//	B: scalars uniformly random in [1, q)
//
// If ScalarMult leaks bits of k through timing, the means of the two
// populations' per-call timings will differ; a Welch's t-test on the
// trimmed means (10% / 90% trim) should not produce a |t| above the
// configured threshold.
//
// This is best-effort: a real CT verification needs hardware-level
// timing instrumentation (e.g., dudect on bare metal) or formal
// verification. The test runs short by default and skips itself in
// short-mode; bump SAMPLES and rerun with `-test.timeout=10m` for a
// more sensitive check.
//
// The test is also tolerant: failing once does NOT prove leakage (could
// be noise from other processes), but passing many times provides
// reasonable assurance.
func TestTimingNoSignificantBias(t *testing.T) {
	if testing.Short() {
		t.Skip("-short: timing test disabled")
	}
	runtime.GC()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	const samples = 4000
	const trimFrac = 0.10

	ec := tss.S256()
	q := ec.Params().N

	// Fixed point.
	P := crypto.ScalarBaseMult(ec, big.NewInt(7))

	// Two scalar populations.
	popA := make([]*big.Int, samples)
	popB := make([]*big.Int, samples)
	for i := 0; i < samples; i++ {
		// A: small scalar (high bits cleared).
		popA[i] = big.NewInt(int64(i) + 1)
		// B: uniform random in [1, q).
		k := new(big.Int)
		bz := make([]byte, 32)
		_, _ = rand.Read(bz)
		k.SetBytes(bz)
		k.Mod(k, q)
		if k.Sign() == 0 {
			k.SetInt64(1)
		}
		popB[i] = k
	}

	// Warm up.
	for i := 0; i < 64; i++ {
		_ = ScalarMult(P, popB[i%len(popB)])
	}
	runtime.GC()

	// Measure timings.
	timeOne := func(k *big.Int) time.Duration {
		start := time.Now()
		_ = ScalarMult(P, k)
		return time.Since(start)
	}
	timesA := make([]float64, samples)
	timesB := make([]float64, samples)
	// Interleave the two populations to minimize systematic bias.
	for i := 0; i < samples; i++ {
		timesA[i] = float64(timeOne(popA[i]))
		timesB[i] = float64(timeOne(popB[i]))
	}

	meanA, varA := trimmedMeanVar(timesA, trimFrac)
	meanB, varB := trimmedMeanVar(timesB, trimFrac)
	tStat := welchT(meanA, varA, len(timesA), meanB, varB, len(timesB))

	t.Logf("trimmed mean A = %.1f ns (var %.1f), B = %.1f ns (var %.1f), t = %.3f",
		meanA, varA, meanB, varB, tStat)

	// |t| > 4.5 corresponds to roughly p < 1e-5; very unlikely under
	// the null hypothesis of equal means in a single test. The
	// threshold is intentionally loose to avoid CI flakes on noisy
	// machines (CPU governor changes, GC, neighbor processes).
	const tThreshold = 4.5
	if math.Abs(tStat) > tThreshold {
		t.Errorf("|t| = %.3f exceeds threshold %.1f — possible timing leak (rerun to confirm; if persistent, investigate)",
			math.Abs(tStat), tThreshold)
	}
}

// trimmedMeanVar returns the mean and variance of the slice after
// removing the lowest and highest trimFrac of samples. Robust to
// occasional GC-induced spikes.
func trimmedMeanVar(xs []float64, trimFrac float64) (mean, variance float64) {
	if len(xs) == 0 {
		return 0, 0
	}
	sorted := append([]float64(nil), xs...)
	sort.Float64s(sorted)
	lo := int(float64(len(sorted)) * trimFrac)
	hi := len(sorted) - lo
	trimmed := sorted[lo:hi]
	var sum float64
	for _, v := range trimmed {
		sum += v
	}
	mean = sum / float64(len(trimmed))
	var ss float64
	for _, v := range trimmed {
		d := v - mean
		ss += d * d
	}
	variance = ss / float64(len(trimmed)-1)
	return
}

// welchT computes Welch's t statistic for two samples with possibly
// unequal variances.
func welchT(meanA, varA float64, nA int, meanB, varB float64, nB int) float64 {
	denom := math.Sqrt(varA/float64(nA) + varB/float64(nB))
	if denom == 0 {
		return 0
	}
	return (meanA - meanB) / denom
}
