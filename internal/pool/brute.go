// Package pool provides an unbounded, cancellable brute-force worker pool.
//
// Unlike the finite-slice worker pools in the process and bruteforce packages,
// BruteCounter dispenses a monotonically increasing stream of indices
// (0, 1, 2, ...) across its workers, which is what a proof-of-work search needs:
// the candidate space is not known ahead of time.
package pool

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
)

// BruteCounter runs workers goroutines, each repeatedly taking the next index
// from a shared atomic counter and calling test(state, index). Every worker gets
// its own state from newState, so test never needs to be goroutine-safe (each
// worker can own a hasher and scratch buffers). The first index for which test
// returns true is returned with found=true, and all workers stop. If ctx is
// cancelled (deadline or caller) before any hit, it returns found=false.
//
// workers <= 0 defaults to runtime.NumCPU().
func BruteCounter[S any](ctx context.Context, workers int, newState func() S, test func(st S, i uint64) bool) (uint64, bool) {
	if workers < 1 {
		workers = runtime.NumCPU()
	}

	var (
		counter atomic.Uint64
		result  atomic.Uint64
		found   atomic.Bool
		stop    atomic.Bool
		once    sync.Once
		wg      sync.WaitGroup
	)

	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			st := newState()
			for {
				i := counter.Add(1) - 1
				// Check for cancellation and a sibling's hit every so often so the
				// hot path stays a plain counter increment.
				if i&0x3ff == 0 {
					if stop.Load() {
						return
					}
					select {
					case <-ctx.Done():
						return
					default:
					}
				}
				if test(st, i) {
					once.Do(func() {
						result.Store(i)
						found.Store(true)
					})
					stop.Store(true)
					return
				}
			}
		}()
	}
	wg.Wait()

	return result.Load(), found.Load()
}
