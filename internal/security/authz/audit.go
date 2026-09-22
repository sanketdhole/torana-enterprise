package authz

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
)

// AuditSink receives decision log entries exported asynchronously.
type AuditSink interface {
	WriteDecision(ctx context.Context, entry DecisionLog) error
}

// MemoryAuditSink stores decision logs in an in-memory thread-safe slice (useful for testing).
type MemoryAuditSink struct {
	mu      sync.RWMutex
	entries []DecisionLog
}

// NewMemoryAuditSink creates a new MemoryAuditSink.
func NewMemoryAuditSink() *MemoryAuditSink {
	return &MemoryAuditSink{
		entries: make([]DecisionLog, 0),
	}
}

// WriteDecision appends a decision log entry.
func (s *MemoryAuditSink) WriteDecision(_ context.Context, entry DecisionLog) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, entry)
	return nil
}

// Entries returns a copy of recorded decision logs.
func (s *MemoryAuditSink) Entries() []DecisionLog {
	s.mu.RLock()
	defer s.mu.RUnlock()
	copied := make([]DecisionLog, len(s.entries))
	copy(copied, s.entries)
	return copied
}

// Clear clears all stored logs.
func (s *MemoryAuditSink) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = s.entries[:0]
}

// LoggingAuditSink logs decisions via slog.
type LoggingAuditSink struct {
	logger *slog.Logger
}

// NewLoggingAuditSink creates a logger-based audit sink.
func NewLoggingAuditSink(logger *slog.Logger) *LoggingAuditSink {
	return &LoggingAuditSink{logger: logger}
}

// WriteDecision outputs a decision log as structured log.
func (s *LoggingAuditSink) WriteDecision(_ context.Context, entry DecisionLog) error {
	s.logger.Info("authz decision audit",
		"rule_id", entry.RuleID,
		"effect", string(entry.Effect),
		"reason", entry.Reason,
		"latency_ns", entry.Latency.Nanoseconds(),
		"subject", entry.Subject,
		"tenant", entry.Tenant,
		"resource_type", string(entry.ResourceType),
		"resource_id", entry.ResourceID,
		"action", entry.Action,
	)
	return nil
}

// AuditBuffer provides a bounded, non-blocking asynchronous queue for decision logs.
type AuditBuffer struct {
	queue        chan DecisionLog
	sink         AuditSink
	droppedCount atomic.Uint64
	emittedCount atomic.Uint64
	wg           sync.WaitGroup
	cancel       context.CancelFunc
}

// NewAuditBuffer creates an audit buffer.
func NewAuditBuffer(capacity int, sink AuditSink) *AuditBuffer {
	if capacity <= 0 {
		capacity = 10000
	}
	return &AuditBuffer{
		queue: make(chan DecisionLog, capacity),
		sink:  sink,
	}
}

// Start launches the background consumer worker.
func (b *AuditBuffer) Start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	b.cancel = cancel

	b.wg.Add(1)
	go b.worker(ctx)
}

// Emit enqueues a decision log entry without blocking.
// If the buffer is saturated, the entry is dropped and the counter incremented.
func (b *AuditBuffer) Emit(entry DecisionLog) bool {
	select {
	case b.queue <- entry:
		b.emittedCount.Add(1)
		return true
	default:
		b.droppedCount.Add(1)
		return false
	}
}

// DroppedCount returns the count of dropped entries.
func (b *AuditBuffer) DroppedCount() uint64 {
	return b.droppedCount.Load()
}

// EmittedCount returns the count of successfully queued entries.
func (b *AuditBuffer) EmittedCount() uint64 {
	return b.emittedCount.Load()
}

// Stop flushes remaining items and stops the background worker.
func (b *AuditBuffer) Stop() {
	if b.cancel != nil {
		b.cancel()
	}
	b.wg.Wait()
}

func (b *AuditBuffer) worker(ctx context.Context) {
	defer b.wg.Done()
	for {
		select {
		case <-ctx.Done():
			// Drain remaining in non-blocking fashion
			for {
				select {
				case entry := <-b.queue:
					if b.sink != nil {
						_ = b.sink.WriteDecision(context.Background(), entry)
					}
				default:
					return
				}
			}
		case entry := <-b.queue:
			if b.sink != nil {
				_ = b.sink.WriteDecision(ctx, entry)
			}
		}
	}
}
