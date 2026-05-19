package dklstss

import (
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSendOnceDeliversFirstOnly verifies that the first call to
// sendOnce wins and subsequent calls are no-ops. Multiple concurrent
// callers must not block once the channel buffer is full.
func TestSendOnceDeliversFirstOnly(t *testing.T) {
	ch := make(chan error, 1)
	var once sync.Once

	// First call delivers.
	sendOnce(&once, ch, errors.New("first"))
	got := <-ch
	require.EqualError(t, got, "first")

	// Subsequent calls must not block even though the buffer was filled
	// once. The Once gate guarantees only the first call performs a send.
	for i := 0; i < 10; i++ {
		sendOnce(&once, ch, errors.New("ignored"))
	}
	// Channel must still be empty (buffer drained at line 19).
	select {
	case unexpected := <-ch:
		t.Fatalf("expected no further messages, got %v", unexpected)
	default:
	}
}

// TestSendOnceConcurrent verifies thread-safety: many goroutines all
// trying to deliver, exactly one succeeds, none block.
func TestSendOnceConcurrent(t *testing.T) {
	ch := make(chan int, 1)
	var once sync.Once
	const n = 100

	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(v int) {
			defer wg.Done()
			sendOnce(&once, ch, v)
		}(i)
	}
	wg.Wait() // all goroutines must return; none block

	v := <-ch
	require.Truef(t, v >= 0 && v < n, "got %d, expected one of the sent values", v)
	// No further sends.
	select {
	case more := <-ch:
		t.Fatalf("expected no further messages, got %d", more)
	default:
	}
}
