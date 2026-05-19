package frostristretto255tss

import "sync"

// sendOnce delivers v on ch iff this is the first call for the given
// once. Multi-writer error paths cannot block on the size-1 buffer of
// the Done/Err channels exposed by per-party state machines (ctx
// cancellation observed in nested callbacks, duplicate broker
// deliveries, etc.). The public API (`<-party.Done` / `<-party.Err`)
// is unchanged; only internal sends route through sendOnce.
func sendOnce[T any](once *sync.Once, ch chan<- T, v T) {
	once.Do(func() {
		ch <- v
	})
}
