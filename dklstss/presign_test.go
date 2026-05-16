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

// TestPresignAndSign verifies the offline → online split produces the
// same kind of signature Sign would produce.
func TestPresignAndSign(t *testing.T) {
	keys, err := Keygen(3, 1, genPartyIDs(3), rand.Reader)
	require.NoError(t, err)

	presign, err := Presign(keys, []int{0, 1}, rand.Reader)
	require.NoError(t, err)
	require.NotNil(t, presign)
	require.False(t, presign.Consumed())

	msg := sha256.Sum256([]byte("presign+sign"))
	sig, err := SignWithPresign(presign, msg[:], nil)
	require.NoError(t, err)
	require.True(t, presign.Consumed())

	pub := &ecdsa.PublicKey{
		Curve: keys[0].ECDSAPub.Curve(),
		X:     keys[0].ECDSAPub.X(),
		Y:     keys[0].ECDSAPub.Y(),
	}
	assert.True(t, ecdsa.Verify(pub, msg[:], sig.R, sig.S))
}

// TestPresignSingleUseEnforced verifies that consuming a presign twice
// fails the second time with ErrPresignAlreadyConsumed.
func TestPresignSingleUseEnforced(t *testing.T) {
	keys, err := Keygen(2, 1, genPartyIDs(2), rand.Reader)
	require.NoError(t, err)
	presign, err := Presign(keys, []int{0, 1}, rand.Reader)
	require.NoError(t, err)

	msg := sha256.Sum256([]byte("first call"))
	sig, err := SignWithPresign(presign, msg[:], nil)
	require.NoError(t, err)
	require.NotNil(t, sig)

	// Second call must fail.
	sig2, err := SignWithPresign(presign, msg[:], nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPresignAlreadyConsumed)
	assert.Nil(t, sig2)

	// Even with a different message.
	msg2 := sha256.Sum256([]byte("second message"))
	sig3, err := SignWithPresign(presign, msg2[:], nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPresignAlreadyConsumed)
	assert.Nil(t, sig3)
}

// TestPresignConcurrentUse verifies the atomic CAS protects against
// concurrent SignWithPresign calls: exactly one wins, others get the
// already-consumed error.
func TestPresignConcurrentUse(t *testing.T) {
	keys, err := Keygen(2, 1, genPartyIDs(2), rand.Reader)
	require.NoError(t, err)
	presign, err := Presign(keys, []int{0, 1}, rand.Reader)
	require.NoError(t, err)

	const goroutines = 16
	msg := sha256.Sum256([]byte("race"))

	var wg sync.WaitGroup
	results := make([]error, goroutines)
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			_, results[i] = SignWithPresign(presign, msg[:], nil)
		}()
	}
	wg.Wait()

	successes := 0
	for _, err := range results {
		if err == nil {
			successes++
		} else {
			assert.ErrorIs(t, err, ErrPresignAlreadyConsumed)
		}
	}
	assert.Equal(t, 1, successes, "exactly one concurrent caller should succeed")
}

// TestPresignHDDerivation verifies HD tweak can be applied to a presign
// output at sign time.
func TestPresignHDDerivation(t *testing.T) {
	keys, err := Keygen(3, 1, genPartyIDs(3), rand.Reader)
	require.NoError(t, err)
	presign, err := Presign(keys, []int{0, 1}, rand.Reader)
	require.NoError(t, err)

	path := []uint32{0, 1, 2}
	tweak, childPub, err := DeriveChild(keys[0], path)
	require.NoError(t, err)

	msg := sha256.Sum256([]byte("presign+hd"))
	sig, err := SignWithPresign(presign, msg[:], tweak)
	require.NoError(t, err)

	pub := &ecdsa.PublicKey{
		Curve: childPub.Curve(),
		X:     childPub.X(),
		Y:     childPub.Y(),
	}
	assert.True(t, ecdsa.Verify(pub, msg[:], sig.R, sig.S), "HD-tweaked signature should verify under child pubkey")

	// Should NOT verify under parent.
	parent := &ecdsa.PublicKey{
		Curve: keys[0].ECDSAPub.Curve(),
		X:     keys[0].ECDSAPub.X(),
		Y:     keys[0].ECDSAPub.Y(),
	}
	assert.False(t, ecdsa.Verify(parent, msg[:], sig.R, sig.S))
}

// TestPresignRHashStable verifies RHash is deterministic.
func TestPresignRHashStable(t *testing.T) {
	keys, err := Keygen(2, 1, genPartyIDs(2), rand.Reader)
	require.NoError(t, err)
	p, err := Presign(keys, []int{0, 1}, rand.Reader)
	require.NoError(t, err)
	h1 := p.RHash()
	h2 := p.RHash()
	assert.Equal(t, h1, h2, "RHash should be deterministic")
	assert.Len(t, h1, 32)
}

// TestPresignErrorPaths covers malformed-input rejections.
func TestPresignErrorPaths(t *testing.T) {
	keys, err := Keygen(3, 1, genPartyIDs(3), rand.Reader)
	require.NoError(t, err)

	_, err = Presign(nil, []int{0, 1}, rand.Reader)
	require.Error(t, err)

	_, err = Presign(keys, []int{0}, rand.Reader) // wrong count
	require.Error(t, err)

	_, err = Presign(keys, []int{0, 99}, rand.Reader) // out of range
	require.Error(t, err)

	_, err = Presign(keys, []int{0, 0}, rand.Reader) // dup
	require.Error(t, err)

	p, err := Presign(keys, []int{0, 1}, rand.Reader)
	require.NoError(t, err)

	_, err = SignWithPresign(nil, []byte("x"), nil)
	require.Error(t, err)

	_, err = SignWithPresign(p, nil, nil)
	require.Error(t, err)
}
