package mcp

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Session represents a mapped client-to-upstream MCP session.
type Session struct {
	ClientSessionID   string
	UpstreamSessionID string
	CreatedAt         time.Time
	LastActive        time.Time
	mu                sync.Mutex
	inFlight          map[string]context.CancelFunc
}

// RegisterCancel registers a cancel function for an in-flight request ID.
func (s *Session) RegisterCancel(reqID string, cancel context.CancelFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inFlight == nil {
		s.inFlight = make(map[string]context.CancelFunc)
	}
	s.inFlight[reqID] = cancel
}

// UnregisterCancel removes an in-flight request ID once completed.
func (s *Session) UnregisterCancel(reqID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.inFlight, reqID)
}

// CancelRequest cancels an in-flight request by ID if present.
func (s *Session) CancelRequest(reqID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cancel, ok := s.inFlight[reqID]; ok {
		cancel()
		delete(s.inFlight, reqID)
		return true
	}
	return false
}

// SessionManager manages mappings between downstream client sessions and upstream server sessions.
type SessionManager struct {
	mu       sync.RWMutex
	sessions map[string]*Session // keyed by ClientSessionID
	ttl      time.Duration
}

// NewSessionManager creates a new session manager with configurable idle TTL.
func NewSessionManager(ttl time.Duration) *SessionManager {
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	return &SessionManager{
		sessions: make(map[string]*Session),
		ttl:      ttl,
	}
}

// GetOrCreate retrieves an existing session or generates a new mapping.
func (m *SessionManager) GetOrCreate(clientSessionID string, upstreamSessionID string) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()

	if clientSessionID == "" {
		clientSessionID = fmt.Sprintf("mcp-client-%d", time.Now().UnixNano())
	}
	if upstreamSessionID == "" {
		upstreamSessionID = fmt.Sprintf("mcp-up-%d", time.Now().UnixNano())
	}

	if sess, ok := m.sessions[clientSessionID]; ok {
		sess.LastActive = time.Now()
		if upstreamSessionID != "" && sess.UpstreamSessionID == "" {
			sess.UpstreamSessionID = upstreamSessionID
		}
		return sess
	}

	sess := &Session{
		ClientSessionID:   clientSessionID,
		UpstreamSessionID: upstreamSessionID,
		CreatedAt:         time.Now(),
		LastActive:        time.Now(),
		inFlight:          make(map[string]context.CancelFunc),
	}
	m.sessions[clientSessionID] = sess
	return sess
}

// Get retrieves an existing session by client session ID.
func (m *SessionManager) Get(clientSessionID string) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	sess, ok := m.sessions[clientSessionID]
	if ok {
		sess.LastActive = time.Now()
	}
	return sess, ok
}

// Delete removes a session.
func (m *SessionManager) Delete(clientSessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, clientSessionID)
}

// CleanupExpired purges sessions that have exceeded the idle TTL.
func (m *SessionManager) CleanupExpired() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	purged := 0
	for k, s := range m.sessions {
		if now.Sub(s.LastActive) > m.ttl {
			delete(m.sessions, k)
			purged++
		}
	}
	return purged
}
