package limits

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"
)

// PeerCountProvider returns the number of active, live gateway peers.
// Will be implemented later by internal/peers.
type PeerCountProvider interface {
	LivePeerCount(ctx context.Context) int
}

// StaticPeerCount provides a fixed peer count.
type StaticPeerCount struct {
	Count int
}

func (s StaticPeerCount) LivePeerCount(_ context.Context) int {
	if s.Count <= 0 {
		return 1
	}
	return s.Count
}

// CounterStore manages token reservations, reconciliations, and request rate counters.
type CounterStore interface {
	// Reserve atomically checks if amount can be accommodated within the limit for the given window, and reserves it.
	Reserve(ctx context.Context, key string, amount int64, limit int64, window Window) (*ReservationResult, error)

	// Reconcile applies the delta (actual - reserved) to the counter.
	Reconcile(ctx context.Context, key string, delta int64, window Window) error

	// AllowRate checks and consumes a token from the request-rate token bucket.
	AllowRate(ctx context.Context, key string, rate float64, burst int64) (bool, time.Duration, error)

	// Sync performs background synchronization across peers or backing storage.
	Sync(ctx context.Context) error

	// Close shuts down background synchronization tasks.
	Close() error
}

// LocalCounterStore maintains in-memory token counters and rate limiters with dynamic peer quota share.
type LocalCounterStore struct {
	mu           sync.RWMutex
	counters     map[string]*windowCounter
	buckets      map[string]*TokenBucket
	peerProvider PeerCountProvider
	syncPeriod   time.Duration
	stopChan     chan struct{}
	closeOnce    sync.Once
	wg           sync.WaitGroup
}

type windowCounter struct {
	mu        sync.Mutex
	used      int64
	expiresAt time.Time
}

// NewLocalCounterStore creates a new LocalCounterStore.
func NewLocalCounterStore(peerProvider PeerCountProvider, syncPeriod time.Duration) *LocalCounterStore {
	if peerProvider == nil {
		peerProvider = StaticPeerCount{Count: 1}
	}
	if syncPeriod <= 0 {
		syncPeriod = 30 * time.Second
	}

	store := &LocalCounterStore{
		counters:     make(map[string]*windowCounter),
		buckets:      make(map[string]*TokenBucket),
		peerProvider: peerProvider,
		syncPeriod:   syncPeriod,
		stopChan:     make(chan struct{}),
	}

	store.wg.Add(1)
	go store.backgroundSync()

	return store
}

// Reserve atomically reserves amount tokens against the local quota share.
func (s *LocalCounterStore) Reserve(ctx context.Context, key string, amount int64, limit int64, window Window) (*ReservationResult, error) {
	// Compute dynamic local quota share: total / live_peer_count
	peerCount := s.peerProvider.LivePeerCount(ctx)
	if peerCount <= 0 {
		peerCount = 1
	}
	localLimit := int64(math.Ceil(float64(limit) / float64(peerCount)))

	wc := s.getOrCreateCounter(key, window)

	wc.mu.Lock()
	defer wc.mu.Unlock()

	now := time.Now()
	// If bucket has expired, reset
	if now.After(wc.expiresAt) {
		wc.used = 0
		wc.expiresAt = now.Add(window.Duration())
	}

	remaining := localLimit - wc.used
	if remaining < amount {
		retryAfter := time.Until(wc.expiresAt)
		if retryAfter < 1*time.Second {
			retryAfter = 1 * time.Second
		}

		return &ReservationResult{
			Allowed:    false,
			Reason:     fmt.Sprintf("token budget exceeded for window %q (local quota %d/%d, needed %d)", window, wc.used, localLimit, amount),
			Window:     window,
			Limit:      limit,
			Remaining:  max(0, remaining),
			RetryAfter: retryAfter,
		}, nil
	}

	// Atomically reserve
	wc.used += amount
	return &ReservationResult{
		Allowed:   true,
		Window:    window,
		Limit:     limit,
		Remaining: localLimit - wc.used,
	}, nil
}

// Reconcile applies the delta (actual - reserved) to the counter.
func (s *LocalCounterStore) Reconcile(_ context.Context, key string, delta int64, window Window) error {
	s.mu.RLock()
	wc, ok := s.counters[key]
	s.mu.RUnlock()
	if !ok {
		// Counter not found; create and record delta if positive
		wc = s.getOrCreateCounter(key, window)
	}

	wc.mu.Lock()
	defer wc.mu.Unlock()

	wc.used += delta
	if wc.used < 0 {
		wc.used = 0
	}
	return nil
}

// AllowRate checks the token bucket for the given key.
func (s *LocalCounterStore) AllowRate(_ context.Context, key string, rate float64, burst int64) (bool, time.Duration, error) {
	s.mu.RLock()
	tb, ok := s.buckets[key]
	s.mu.RUnlock()

	if !ok {
		s.mu.Lock()
		tb, ok = s.buckets[key]
		if !ok {
			tb = NewTokenBucket(rate, burst)
			s.buckets[key] = tb
		}
		s.mu.Unlock()
	}

	allowed, retryAfter := tb.Allow()
	return allowed, retryAfter, nil
}

func (s *LocalCounterStore) getOrCreateCounter(key string, window Window) *windowCounter {
	s.mu.RLock()
	wc, ok := s.counters[key]
	s.mu.RUnlock()
	if ok {
		return wc
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	wc, ok = s.counters[key]
	if ok {
		return wc
	}

	wc = &windowCounter{
		expiresAt: time.Now().Add(window.Duration()),
	}
	s.counters[key] = wc
	return wc
}

func (s *LocalCounterStore) backgroundSync() {
	defer s.wg.Done()
	ticker := time.NewTicker(s.syncPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopChan:
			return
		case <-ticker.C:
			_ = s.Sync(context.Background())
		}
	}
}

// Sync cleans up expired counters and synchronizes usage state.
func (s *LocalCounterStore) Sync(_ context.Context) error {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	for k, wc := range s.counters {
		wc.mu.Lock()
		if now.After(wc.expiresAt) {
			delete(s.counters, k)
		}
		wc.mu.Unlock()
	}
	return nil
}

// Close gracefully stops the sync worker.
func (s *LocalCounterStore) Close() error {
	s.closeOnce.Do(func() {
		close(s.stopChan)
		s.wg.Wait()
	})
	return nil
}

// --- Optional Redis Implementation ---

// RedisClient defines minimal operations required for Redis backing.
type RedisClient interface {
	IncrBy(ctx context.Context, key string, amount int64) (int64, error)
	PExpire(ctx context.Context, key string, ttl time.Duration) error
	Get(ctx context.Context, key string) (int64, error)
}

// RedisCounterStore implements CounterStore against an external Redis instance.
type RedisCounterStore struct {
	client RedisClient
	local  *LocalCounterStore // fallback for rate limiting
}

// NewRedisCounterStore creates a Redis-backed counter store.
func NewRedisCounterStore(client RedisClient, peerProvider PeerCountProvider) *RedisCounterStore {
	return &RedisCounterStore{
		client: client,
		local:  NewLocalCounterStore(peerProvider, 1*time.Minute),
	}
}

func (r *RedisCounterStore) Reserve(ctx context.Context, key string, amount int64, limit int64, window Window) (*ReservationResult, error) {
	if r.client == nil {
		return r.local.Reserve(ctx, key, amount, limit, window)
	}

	newVal, err := r.client.IncrBy(ctx, key, amount)
	if err != nil {
		// Fail-open or fallback to local
		return r.local.Reserve(ctx, key, amount, limit, window)
	}

	if newVal == amount {
		_ = r.client.PExpire(ctx, key, window.Duration())
	}

	if newVal > limit {
		// Rollback excess
		_, _ = r.client.IncrBy(ctx, key, -amount)
		return &ReservationResult{
			Allowed:    false,
			Reason:     fmt.Sprintf("redis token budget exceeded for window %q (current %d, limit %d)", window, newVal, limit),
			Window:     window,
			Limit:      limit,
			Remaining:  0,
			RetryAfter: 10 * time.Second,
		}, nil
	}

	return &ReservationResult{
		Allowed:   true,
		Window:    window,
		Limit:     limit,
		Remaining: limit - newVal,
	}, nil
}

func (r *RedisCounterStore) Reconcile(ctx context.Context, key string, delta int64, window Window) error {
	if r.client == nil {
		return r.local.Reconcile(ctx, key, delta, window)
	}
	_, err := r.client.IncrBy(ctx, key, delta)
	return err
}

func (r *RedisCounterStore) AllowRate(ctx context.Context, key string, rate float64, burst int64) (bool, time.Duration, error) {
	return r.local.AllowRate(ctx, key, rate, burst)
}

func (r *RedisCounterStore) Sync(ctx context.Context) error {
	return r.local.Sync(ctx)
}

func (r *RedisCounterStore) Close() error {
	return r.local.Close()
}
