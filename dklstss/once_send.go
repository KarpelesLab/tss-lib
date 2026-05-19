package dklstss

import "sync"

// sendOnce delivers v on ch iff this is the first successful call for
// the given once. Subsequent calls are no-ops; the value is dropped.
// Use a per-channel sync.Once paired with each size-1 buffered Done /
// Err channel: callers see the standard `<-party.Done` / `<-party.Err`
// API, but internal multi-writer paths cannot block on a full buffer.
//
// Background. Every *Party type in this package exposes size-1
// buffered Done and Err channels. Several round handlers can race to
// write to these — for example, ctx cancellation observed in two
// nested callbacks, a broker dispatching the same message twice, or
// two distinct error paths during finalization. With a plain channel,
// the second send blocks forever on the full buffer, leaving a
// goroutine pinned inside the broker callback queue.
func sendOnce[T any](once *sync.Once, ch chan<- T, v T) {
	once.Do(func() {
		ch <- v
	})
}
