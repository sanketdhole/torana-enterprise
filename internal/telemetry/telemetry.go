package telemetry

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Event contains sanitized metadata regarding a processed request.
// CUSTOMER PAYLOADS (PROMPTS/COMPLETIONS) ARE STRICTLY EXCLUDED.
type Event struct {
	Timestamp    time.Time         `json:"timestamp"`
	RouteID      string            `json:"route_id"`
	UpstreamID   string            `json:"upstream_id"`
	Method       string            `json:"method"`
	Path         string            `json:"path"`
	StatusCode   int               `json:"status_code"`
	DurationMs   int64             `json:"duration_ms"`
	PromptTokens int               `json:"prompt_tokens,omitempty"`
	ComplTokens  int               `json:"completion_tokens,omitempty"`
	TotalTokens  int               `json:"total_tokens,omitempty"`
	Model        string            `json:"model,omitempty"`
	TenantID     string            `json:"tenant_id,omitempty"`
	Error        string            `json:"error,omitempty"`
	CustomMeta   map[string]string `json:"custom_meta,omitempty"`
}

// Sink receives batches of telemetry events for export to the platform control plane.
type Sink interface {
	SendBatch(ctx context.Context, events []Event) error
}

// LoggingSink outputs sanitized telemetry metadata events to structured slog.
type LoggingSink struct {
	logger *slog.Logger
}

// NewLoggingSink creates a sink that logs metadata.
func NewLoggingSink(logger *slog.Logger) *LoggingSink {
	return &LoggingSink{logger: logger}
}

// SendBatch logs each metadata event.
func (s *LoggingSink) SendBatch(_ context.Context, events []Event) error {
	for _, e := range events {
		s.logger.Info("telemetry metadata event",
			"route_id", e.RouteID,
			"upstream_id", e.UpstreamID,
			"status", e.StatusCode,
			"duration_ms", e.DurationMs,
			"total_tokens", e.TotalTokens,
			"model", e.Model,
			"tenant_id", e.TenantID,
		)
	}
	return nil
}

// Emitter maintains a bounded, non-blocking telemetry event queue.
type Emitter struct {
	queue        chan Event
	sink         Sink
	logger       *slog.Logger
	droppedCount atomic.Uint64
	emittedCount atomic.Uint64
	batchSize    int
	flushPeriod  time.Duration
	wg           sync.WaitGroup
	cancel       context.CancelFunc
}

// NewEmitter constructs a new bounded telemetry emitter.
func NewEmitter(queueSize int, sink Sink, logger *slog.Logger) *Emitter {
	if queueSize <= 0 {
		queueSize = 10000
	}
	return &Emitter{
		queue:       make(chan Event, queueSize),
		sink:        sink,
		logger:      logger,
		batchSize:   100,
		flushPeriod: 500 * time.Millisecond,
	}
}

// Start spawns the background drain worker.
func (e *Emitter) Start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	e.cancel = cancel

	e.wg.Add(1)
	go e.worker(ctx)
}

// Emit enqueues an event without blocking the hot path.
// If the bounded queue is full, the event is dropped and the drop counter incremented.
func (e *Emitter) Emit(event Event) bool {
	select {
	case e.queue <- event:
		e.emittedCount.Add(1)
		return true
	default:
		e.droppedCount.Add(1)
		return false
	}
}

// DroppedCount returns the number of events dropped due to buffer saturation.
func (e *Emitter) DroppedCount() uint64 {
	return e.droppedCount.Load()
}

// EmittedCount returns total successfully enqueued events.
func (e *Emitter) EmittedCount() uint64 {
	return e.emittedCount.Load()
}

func (e *Emitter) worker(ctx context.Context) {
	defer e.wg.Done()

	ticker := time.NewTicker(e.flushPeriod)
	defer ticker.Stop()

	batch := make([]Event, 0, e.batchSize)

	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := e.sink.SendBatch(ctx, batch); err != nil {
			e.logger.Error("failed to send telemetry batch to platform", "error", err, "size", len(batch))
		}
		batch = make([]Event, 0, e.batchSize)
	}

	for {
		select {
		case <-ctx.Done():
			// Drain remaining items in queue before exiting
			for {
				select {
				case ev := <-e.queue:
					batch = append(batch, ev)
					if len(batch) >= e.batchSize {
						flush()
					}
				default:
					flush()
					return
				}
			}

		case ev := <-e.queue:
			batch = append(batch, ev)
			if len(batch) >= e.batchSize {
				flush()
			}

		case <-ticker.C:
			flush()
		}
	}
}

// Stop gracefully stops the worker and drains the queue.
func (e *Emitter) Stop(drainTimeout time.Duration) {
	if e.cancel != nil {
		e.cancel()
	}

	done := make(chan struct{})
	go func() {
		e.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(drainTimeout):
		e.logger.Warn("telemetry drain timed out")
	}
}
