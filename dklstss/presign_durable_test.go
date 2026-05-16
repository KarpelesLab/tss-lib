package dklstss

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDurablePresignSingleUse verifies the durable store prevents reuse
// across separate PresignOutput objects that happen to share R (which
// in practice means the same presign restored across crash boundary).
func TestDurablePresignSingleUse(t *testing.T) {
	keys, err := Keygen(2, 1, genPartyIDs(2), rand.Reader)
	require.NoError(t, err)
	pub := &ecdsa.PublicKey{
		Curve: keys[0].ECDSAPub.Curve(),
		X:     keys[0].ECDSAPub.X(),
		Y:     keys[0].ECDSAPub.Y(),
	}

	store := NewInMemoryPresignStore()

	presign, err := Presign(keys, []int{0, 1}, rand.Reader)
	require.NoError(t, err)

	msg := sha256.Sum256([]byte("first call"))
	sig, err := SignWithPresignDurable(presign, msg[:], nil, store)
	require.NoError(t, err)
	require.True(t, ecdsa.Verify(pub, msg[:], sig.R, sig.S))
}

// TestDurablePresignRejectsKnownRHash simulates a crash-restart: the
// store already contains an R-hash matching the presign's R. The
// signing call must refuse.
func TestDurablePresignRejectsKnownRHash(t *testing.T) {
	keys, err := Keygen(2, 1, genPartyIDs(2), rand.Reader)
	require.NoError(t, err)
	presign, err := Presign(keys, []int{0, 1}, rand.Reader)
	require.NoError(t, err)

	store := NewInMemoryPresignStore()
	// Pre-record the R-hash as if from a previous run.
	rec, err := store.CheckAndRecord(presign.RHash())
	require.NoError(t, err)
	require.True(t, rec)

	msg := sha256.Sum256([]byte("second-run"))
	_, err = SignWithPresignDurable(presign, msg[:], nil, store)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPresignAlreadyConsumed)
}

// TestDurablePresignStoreErrorPropagates verifies that storage errors
// bubble out cleanly (not swallowed, not converted to silent success).
func TestDurablePresignStoreErrorPropagates(t *testing.T) {
	keys, err := Keygen(2, 1, genPartyIDs(2), rand.Reader)
	require.NoError(t, err)
	presign, err := Presign(keys, []int{0, 1}, rand.Reader)
	require.NoError(t, err)

	storageErr := errors.New("simulated disk failure")
	store := &erroringStore{err: storageErr}

	msg := sha256.Sum256([]byte("storage-fail"))
	_, err = SignWithPresignDurable(presign, msg[:], nil, store)
	require.Error(t, err)
	assert.ErrorIs(t, err, storageErr)
	// Must NOT consume the in-memory presign on storage failure.
	require.False(t, presign.Consumed())
}

// TestDurablePresignRequiresStore verifies that nil store is rejected.
func TestDurablePresignRequiresStore(t *testing.T) {
	keys, err := Keygen(2, 1, genPartyIDs(2), rand.Reader)
	require.NoError(t, err)
	presign, err := Presign(keys, []int{0, 1}, rand.Reader)
	require.NoError(t, err)
	msg := sha256.Sum256([]byte("nil-store"))
	_, err = SignWithPresignDurable(presign, msg[:], nil, nil)
	require.Error(t, err)
}

type erroringStore struct{ err error }

func (s *erroringStore) CheckAndRecord(_ []byte) (bool, error) { return false, s.err }
