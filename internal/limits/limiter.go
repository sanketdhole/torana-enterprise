package limits

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// LimiterConfig configures rate limiting and token budget rules.
type LimiterConfig struct {
	Store          CounterStore
	DefaultBudget  *BudgetRule
	DefaultRate    *RateLimitRule
	BudgetsByKey   map[string]*BudgetRule    // Keyed by Team / Model / Route
	RatesByKey     map[string]*RateLimitRule // Keyed by Team / Identity / Route
	ReservationTTL time.Duration
}

// Limiter manages two-stage accounting and request rate enforcement.
type Limiter struct {
	store          CounterStore
	defaultBudget  *BudgetRule
	defaultRate    *RateLimitRule
	budgetsByKey   map[string]*BudgetRule
	ratesByKey     map[string]*RateLimitRule
	mu             sync.RWMutex
	reservations   map[string]*Reservation
	reservationTTL time.Duration
	stopChan       chan struct{}
	wg             sync.WaitGroup
}

// NewLimiter creates a new Limiter.
func NewLimiter(cfg LimiterConfig) *Limiter {
	store := cfg.Store
	if store == nil {
		store = NewLocalCounterStore(nil, 30*time.Second)
	}

	ttl := cfg.ReservationTTL
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}

	l := &Limiter{
		store:          store,
		defaultBudget:  cfg.DefaultBudget,
		defaultRate:    cfg.DefaultRate,
		budgetsByKey:   cfg.BudgetsByKey,
		ratesByKey:     cfg.RatesByKey,
		reservations:   make(map[string]*Reservation),
		reservationTTL: ttl,
		stopChan:       make(chan struct{}),
	}

	l.wg.Add(1)
	go l.staleReservationCleaner()

	return l
}

// PreCheck performs Stage 1: checks the token bucket request rate and reserves estimated tokens across active windows.
func (l *Limiter) PreCheck(ctx context.Context, keys DimensionKeys, estimatedTokens int64) (*Reservation, *RateLimitError) {
	// 1. Request-rate limit check (Token Bucket)
	rateRule := l.resolveRateRule(keys)
	if rateRule != nil && rateRule.Rate > 0 {
		rateKey := keys.RateLimitKey()
		allowed, retryAfter, err := l.store.AllowRate(ctx, rateKey, rateRule.Rate, rateRule.Burst)
		if err != nil || !allowed {
			seconds := int(retryAfter.Seconds())
			if seconds < 1 {
				seconds = 1
			}
			return nil, &RateLimitError{
				Error:      "rate_limit_exceeded",
				Code:       "REQUEST_RATE_LIMIT_EXCEEDED",
				Reason:     fmt.Sprintf("request rate limit exceeded (burst %d, rate %.1f/s)", rateRule.Burst, rateRule.Rate),
				RetryAfter: seconds,
			}
		}
	}

	// 2. Token budget check and reservation across windows
	budgetRule := l.resolveBudgetRule(keys)
	if budgetRule != nil && len(budgetRule.Limits) > 0 && estimatedTokens > 0 {
		var reservedWindows []Window
		now := time.Now()

		for _, window := range []Window{WindowMinute, WindowDay, WindowMonth} {
			limit, exists := budgetRule.Limits[window]
			if !exists || limit <= 0 {
				continue
			}

			key := keys.BuildKey("tokens", window, now)
			res, err := l.store.Reserve(ctx, key, estimatedTokens, limit, window)
			if err != nil || !res.Allowed {
				// Rollback already reserved windows in this call
				for _, rw := range reservedWindows {
					rKey := keys.BuildKey("tokens", rw, now)
					_ = l.store.Reconcile(ctx, rKey, -estimatedTokens, rw)
				}

				retrySeconds := 1
				if res != nil && res.RetryAfter > 0 {
					retrySeconds = int(res.RetryAfter.Seconds())
					if retrySeconds < 1 {
						retrySeconds = 1
					}
				}

				reason := "token budget exceeded"
				if res != nil && res.Reason != "" {
					reason = res.Reason
				}

				return nil, &RateLimitError{
					Error:      "token_budget_exceeded",
					Code:       "TOKEN_BUDGET_EXCEEDED",
					Reason:     reason,
					Window:     string(window),
					RetryAfter: retrySeconds,
					Limit:      limit,
					Remaining:  0,
				}
			}

			reservedWindows = append(reservedWindows, window)
		}

		// Reservation successful: record state
		reservationID := generateReservationID()
		r := &Reservation{
			ID:             reservationID,
			Keys:           keys,
			ReservedTokens: estimatedTokens,
			Windows:        reservedWindows,
			CreatedAt:      now,
		}

		l.mu.Lock()
		l.reservations[reservationID] = r
		l.mu.Unlock()

		return r, nil
	}

	// No token budgets configured: return empty unmetered reservation
	return &Reservation{
		ID: generateReservationID(),
	}, nil
}

// Reconcile performs Stage 2: adjusts counters with (actualTokens - reservedTokens).
func (l *Limiter) Reconcile(ctx context.Context, reservationID string, actualTokens int64) error {
	l.mu.Lock()
	r, found := l.reservations[reservationID]
	if found {
		delete(l.reservations, reservationID)
	}
	l.mu.Unlock()

	if !found || r == nil {
		return ErrReservationNotFound
	}

	if len(r.Windows) == 0 {
		return nil
	}

	delta := actualTokens - r.ReservedTokens
	now := r.CreatedAt

	for _, window := range r.Windows {
		key := r.Keys.BuildKey("tokens", window, now)
		_ = l.store.Reconcile(ctx, key, delta, window)
	}

	return nil
}

func (l *Limiter) resolveBudgetRule(keys DimensionKeys) *BudgetRule {
	if l.budgetsByKey != nil {
		// Specific model budget
		if b, ok := l.budgetsByKey[keys.Model]; ok {
			return b
		}
		// Specific team budget
		if b, ok := l.budgetsByKey[keys.Team]; ok {
			return b
		}
		// Specific route budget
		if b, ok := l.budgetsByKey[keys.Route]; ok {
			return b
		}
	}
	return l.defaultBudget
}

func (l *Limiter) resolveRateRule(keys DimensionKeys) *RateLimitRule {
	if l.ratesByKey != nil {
		if r, ok := l.ratesByKey[keys.Team]; ok {
			return r
		}
		if r, ok := l.ratesByKey[keys.Identity]; ok {
			return r
		}
		if r, ok := l.ratesByKey[keys.Route]; ok {
			return r
		}
	}
	return l.defaultRate
}

func (l *Limiter) staleReservationCleaner() {
	defer l.wg.Done()
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-l.stopChan:
			return
		case <-ticker.C:
			now := time.Now()
			l.mu.Lock()
			for id, r := range l.reservations {
				if now.Sub(r.CreatedAt) > l.reservationTTL {
					delete(l.reservations, id)
				}
			}
			l.mu.Unlock()
		}
	}
}

// Close cleans up limiter resources.
func (l *Limiter) Close() error {
	close(l.stopChan)
	l.wg.Wait()
	if l.store != nil {
		return l.store.Close()
	}
	return nil
}

func generateReservationID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
