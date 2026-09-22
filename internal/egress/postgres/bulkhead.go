package postgres

import (
	"context"
	"sync"
)

// Bulkhead manages per-target concurrency isolation and bounded queuing.
type Bulkhead struct {
	mu            sync.Mutex
	activeSlots   chan struct{}
	queueCapacity chan struct{}
}

// NewBulkhead creates a bulkhead with maximum concurrent executions and queue depth.
func NewBulkhead(maxConcurrent, maxQueue int) *Bulkhead {
	if maxConcurrent <= 0 {
		maxConcurrent = 50
	}
	if maxQueue <= 0 {
		maxQueue = 100
	}

	return &Bulkhead{
		activeSlots:   make(chan struct{}, maxConcurrent),
		queueCapacity: make(chan struct{}, maxQueue),
	}
}

// Acquire requests an execution slot from the bulkhead.
// It returns a release function to be deferred, or an error if the bulkhead is saturated or context expires.
func (b *Bulkhead) Acquire(ctx context.Context) (func(), error) {
	// 1. Fast path: try to acquire active slot immediately
	select {
	case b.activeSlots <- struct{}{}:
		return b.releaseSlot, nil
	default:
	}

	// 2. Queue admission: check if queue has capacity
	select {
	case b.queueCapacity <- struct{}{}:
		// Successfully admitted to queue, now wait for an active slot
		defer func() {
			// Leave queue once handled or abandoned
			<-b.queueCapacity
		}()
	default:
		// Queue full: reject immediately
		return nil, ErrBulkheadExhausted
	}

	// 3. Wait for an active slot or context expiration
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case b.activeSlots <- struct{}{}:
		return b.releaseSlot, nil
	}
}

func (b *Bulkhead) releaseSlot() {
	<-b.activeSlots
}

// CurrentActive returns the number of active queries executing.
func (b *Bulkhead) CurrentActive() int {
	return len(b.activeSlots)
}

// CurrentQueued returns the number of queries currently queued.
func (b *Bulkhead) CurrentQueued() int {
	return len(b.queueCapacity)
}
