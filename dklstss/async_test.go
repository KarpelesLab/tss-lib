package dklstss

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAsyncKeygen exercises the channel-based wrapper.
func TestAsyncKeygen(t *testing.T) {
	ctx := context.Background()
	a := NewAsyncKeygen(ctx, 2, 1, genPartyIDs(2), rand.Reader)
	select {
	case keys := <-a.Done:
		require.Len(t, keys, 2)
		assert.NotNil(t, keys[0].ECDSAPub)
	case err := <-a.Err:
		t.Fatalf("keygen failed: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("keygen timed out")
	}
}

// TestAsyncSigning exercises async sign.
func TestAsyncSigning(t *testing.T) {
	keys, err := Keygen(2, 1, genPartyIDs(2), rand.Reader)
	require.NoError(t, err)
	digest := sha256.Sum256([]byte("async sign"))

	ctx := context.Background()
	a := NewAsyncSigning(ctx, keys, []int{0, 1}, digest[:], rand.Reader)
	select {
	case sig := <-a.Done:
		require.NotNil(t, sig)
		pub := &ecdsa.PublicKey{
			Curve: keys[0].ECDSAPub.Curve(),
			X:     keys[0].ECDSAPub.X(),
			Y:     keys[0].ECDSAPub.Y(),
		}
		assert.True(t, ecdsa.Verify(pub, digest[:], sig.R, sig.S))
	case err := <-a.Err:
		t.Fatalf("async sign failed: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("async sign timed out")
	}
}

// TestAsyncPresignAndRefresh exercises the remaining async wrappers in
// one go.
func TestAsyncPresignAndRefresh(t *testing.T) {
	keys, err := Keygen(3, 1, genPartyIDs(3), rand.Reader)
	require.NoError(t, err)

	ctx := context.Background()

	// Presign.
	ap := NewAsyncPresign(ctx, keys, []int{0, 2}, rand.Reader)
	var presign *PresignOutput
	select {
	case presign = <-ap.Done:
	case err := <-ap.Err:
		t.Fatalf("async presign failed: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("async presign timed out")
	}
	require.NotNil(t, presign)

	// Refresh.
	ar := NewAsyncRefresh(ctx, keys, rand.Reader)
	select {
	case refreshed := <-ar.Done:
		require.Len(t, refreshed, 3)
		assert.True(t, refreshed[0].ECDSAPub.Equals(keys[0].ECDSAPub))
	case err := <-ar.Err:
		t.Fatalf("async refresh failed: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("async refresh timed out")
	}
}
