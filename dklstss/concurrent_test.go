package dklstss

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConcurrentSign verifies that multiple signing operations against
// the same Key slice run in parallel without races and all produce
// signatures that verify under the (unchanged) joint public key.
//
// Threading model claim: a Key produced by Keygen() is read-only after
// Keygen returns. Sign/Presign/SignWithPresign do not mutate the Key or
// any OT-extension setup state; they only consume RNG and write to
// local accumulators. As a result, multiple goroutines may concurrently
// invoke Sign() on the same []*Key.
//
// Refresh DOES produce a new []*Key (with rotated state). Callers must
// not call Refresh concurrently with Sign on the same slice; they must
// instead atomically swap the slice reference under their own
// synchronization.
func TestConcurrentSign(t *testing.T) {
	keys, err := Keygen(3, 1, genPartyIDs(3), rand.Reader)
	require.NoError(t, err)
	pub := &ecdsa.PublicKey{
		Curve: keys[0].ECDSAPub.Curve(),
		X:     keys[0].ECDSAPub.X(),
		Y:     keys[0].ECDSAPub.Y(),
	}

	const goroutines = 8
	const perGoroutine = 4
	var wg sync.WaitGroup
	errs := make(chan error, goroutines*perGoroutine)
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		g := g
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				msg := sha256.Sum256([]byte{byte(g), byte(i)})
				subset := []int{0, 1}
				if (g+i)%2 == 1 {
					subset = []int{1, 2}
				}
				sig, err := Sign(keys, subset, msg[:], rand.Reader)
				if err != nil {
					errs <- err
					return
				}
				if !ecdsa.Verify(pub, msg[:], sig.R, sig.S) {
					errs <- assertionError("signature did not verify")
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Errorf("concurrent signing failed: %v", e)
	}
}

// TestConcurrentPresignThenSign verifies parallel pre-signing + signing
// across many goroutines.
func TestConcurrentPresignThenSign(t *testing.T) {
	keys, err := Keygen(4, 2, genPartyIDs(4), rand.Reader)
	require.NoError(t, err)
	pub := &ecdsa.PublicKey{
		Curve: keys[0].ECDSAPub.Curve(),
		X:     keys[0].ECDSAPub.X(),
		Y:     keys[0].ECDSAPub.Y(),
	}

	const goroutines = 8
	var wg sync.WaitGroup
	failures := make(chan error, goroutines)
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		g := g
		go func() {
			defer wg.Done()
			subsets := [][]int{{0, 1, 2}, {1, 2, 3}, {0, 2, 3}}
			subset := subsets[g%len(subsets)]

			pre, err := Presign(keys, subset, rand.Reader)
			if err != nil {
				failures <- err
				return
			}
			msg := sha256.Sum256([]byte{byte(g)})
			sig, err := SignWithPresign(pre, msg[:], nil)
			if err != nil {
				failures <- err
				return
			}
			if !ecdsa.Verify(pub, msg[:], sig.R, sig.S) {
				failures <- assertionError("signature did not verify")
				return
			}
		}()
	}
	wg.Wait()
	close(failures)
	for e := range failures {
		t.Errorf("concurrent presign+sign failed: %v", e)
	}
}

// TestConcurrentDeriveAndSign verifies parallel HD-derive+sign.
func TestConcurrentDeriveAndSign(t *testing.T) {
	keys, err := Keygen(3, 1, genPartyIDs(3), rand.Reader)
	require.NoError(t, err)

	const goroutines = 8
	var wg sync.WaitGroup
	failures := make(chan error, goroutines)
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		g := g
		go func() {
			defer wg.Done()
			path := []uint32{uint32(g), uint32(g) ^ 7}
			msg := sha256.Sum256([]byte{byte(g)})
			sig, child, err := DeriveAndSign(keys, []int{0, 1}, path, msg[:], rand.Reader)
			if err != nil {
				failures <- err
				return
			}
			pub := &ecdsa.PublicKey{
				Curve: child.Curve(),
				X:     child.X(),
				Y:     child.Y(),
			}
			if !ecdsa.Verify(pub, msg[:], sig.R, sig.S) {
				failures <- assertionError("HD signature did not verify")
			}
		}()
	}
	wg.Wait()
	close(failures)
	for e := range failures {
		t.Errorf("concurrent HD sign failed: %v", e)
	}
}

func assertionError(msg string) error {
	return assertErr{msg: msg}
}

type assertErr struct{ msg string }

func (e assertErr) Error() string { return e.msg }

var _ = assert.NoError
