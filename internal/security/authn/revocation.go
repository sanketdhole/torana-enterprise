package authn

import (
	"sync"

	controlplanev1 "github.com/phaselume/torana/api/proto/controlplane/v1"
)

// RevocationList manages revoked tokens and credentials with O(1) lock-optimized lookup.
type RevocationList struct {
	mu          sync.RWMutex
	tokens      map[string]struct{}
	keys        map[string]struct{}
	subscribers map[chan struct{}]struct{}
}

// NewRevocationList creates an empty thread-safe revocation list.
func NewRevocationList() *RevocationList {
	return &RevocationList{
		tokens:      make(map[string]struct{}),
		keys:        make(map[string]struct{}),
		subscribers: make(map[chan struct{}]struct{}),
	}
}

func (r *RevocationList) notifySubscribersLocked() {
	for ch := range r.subscribers {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// ApplyRevocation merges revocation instructions from control plane messages in O(N).
func (r *RevocationList) ApplyRevocation(rev *controlplanev1.Revocation) {
	if rev == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, tok := range rev.RevokedTokens {
		if tok != "" {
			r.tokens[tok] = struct{}{}
		}
	}
	for _, k := range rev.RevokedKeys {
		if k != "" {
			r.keys[k] = struct{}{}
		}
	}
	r.notifySubscribersLocked()
}

// RevokeToken registers an individual token identifier (e.g. jti, hash) as revoked.
func (r *RevocationList) RevokeToken(tokenID string) {
	if tokenID == "" {
		return
	}
	r.mu.Lock()
	r.tokens[tokenID] = struct{}{}
	r.notifySubscribersLocked()
	r.mu.Unlock()
}

// RevokeKey registers an API key identifier, prefix, or hash as revoked.
func (r *RevocationList) RevokeKey(keyID string) {
	if keyID == "" {
		return
	}
	r.mu.Lock()
	r.keys[keyID] = struct{}{}
	r.notifySubscribersLocked()
	r.mu.Unlock()
}

// IsTokenRevoked checks if a token ID or hash is revoked in O(1) time.
func (r *RevocationList) IsTokenRevoked(tokenID string) bool {
	if tokenID == "" {
		return false
	}
	r.mu.RLock()
	_, revoked := r.tokens[tokenID]
	r.mu.RUnlock()
	return revoked
}

// IsKeyRevoked checks if an API key identifier or hash is revoked in O(1) time.
func (r *RevocationList) IsKeyRevoked(keyID string) bool {
	if keyID == "" {
		return false
	}
	r.mu.RLock()
	_, revoked := r.keys[keyID]
	r.mu.RUnlock()
	return revoked
}

// IsRevoked checks whether the given ID matches any revoked token or key in O(1).
func (r *RevocationList) IsRevoked(id string) bool {
	if id == "" {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if _, ok := r.tokens[id]; ok {
		return true
	}
	_, ok := r.keys[id]
	return ok
}

// Count returns the number of revoked tokens and keys.
func (r *RevocationList) Count() (tokens int, keys int) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.tokens), len(r.keys)
}

// Subscribe registers a listener channel notified on any revocation update.
// Returns the event channel and an unsubscribe cleanup function.
func (r *RevocationList) Subscribe() (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	r.mu.Lock()
	if r.subscribers == nil {
		r.subscribers = make(map[chan struct{}]struct{})
	}
	r.subscribers[ch] = struct{}{}
	r.mu.Unlock()

	unsubscribe := func() {
		r.mu.Lock()
		delete(r.subscribers, ch)
		r.mu.Unlock()
	}
	return ch, unsubscribe
}

