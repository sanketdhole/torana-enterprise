package observe_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phaselume/torana/internal/observe"
)

// ---------------------------------------------------------------------------
// stalledSink is a Sink whose SendBatch blocks forever (until Close).
// Used to prove the request path never blocks on observability.
// ---------------------------------------------------------------------------
type stalledSink struct {
	mu       sync.Mutex
	ch       chan struct{}
	received [][]observe.AuditEvent
}

func newStalledSink() *stalledSink {
	return &stalledSink{ch: make(chan struct{})}
}

func (s *stalledSink) SendBatch(_ context.Context, events []observe.AuditEvent) error {
	s.mu.Lock()
	s.received = append(s.received, events)
	s.mu.Unlock()
	<-s.ch // block forever until Close
	return nil
}

func (s *stalledSink) Close() error {
	select {
	case <-s.ch:
	default:
		close(s.ch)
	}
	return nil
}

// ---------------------------------------------------------------------------
// collectingSink gathers all shipped events for test assertions.
// ---------------------------------------------------------------------------
type collectingSink struct {
	mu     *sync.Mutex
	events *[]observe.AuditEvent
}

func (c *collectingSink) SendBatch(_ context.Context, events []observe.AuditEvent) error {
	c.mu.Lock()
	*c.events = append(*c.events, events...)
	c.mu.Unlock()
	return nil
}

func (c *collectingSink) Close() error { return nil }

// ---------------------------------------------------------------------------
// TestRequestPathNeverBlocksOnStalledSink
//
// Guarantees that Capture() (the only call on the hot request path) completes
// within 1 ms even when the downstream sink is permanently stalled.
// ---------------------------------------------------------------------------
func TestRequestPathNeverBlocksOnStalledSink(t *testing.T) {
	stalled := newStalledSink()

	shipper, err := observe.NewShipper(observe.ShipperConfig{
		PlatformSink:  stalled,
		RingSize:      64,
		FlushInterval: 10 * time.Millisecond,
		BatchSize:     8,
	})
	if err != nil {
		t.Fatalf("NewShipper: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	shipper.Start(ctx)

	// Fire 200 events — far more than the ring buffer can hold.
	const numEvents = 200
	for i := 0; i < numEvents; i++ {
		start := time.Now()
		shipper.Capture(observe.AuditEvent{
			Timestamp: time.Now(),
			RequestID: "req-hot-path",
			RouteID:   "test-route",
			Phase:     "request_headers",
		})
		elapsed := time.Since(start)

		// The hard guarantee: Capture must never block.
		if elapsed > 1*time.Millisecond {
			t.Fatalf("Capture() blocked for %v on event %d — must be < 1ms", elapsed, i)
		}
	}

	// Some events should have been dropped (ring saturation).
	dropped := shipper.RingBuffer().DroppedCount()
	enqueued := shipper.RingBuffer().EnqueuedCount()
	t.Logf("enqueued=%d  dropped=%d  total=%d", enqueued, dropped, enqueued+dropped)

	if enqueued+dropped != numEvents {
		t.Errorf("enqueued+dropped = %d; want %d", enqueued+dropped, numEvents)
	}

	// Clean up: unblock the stalled sink and stop the shipper.
	_ = stalled.Close()
	shipper.Stop(1 * time.Second)
}

// ---------------------------------------------------------------------------
// TestRingBufferOverflow verifies that the ring buffer drops oldest events
// when full and never blocks the producer.
// ---------------------------------------------------------------------------
func TestRingBufferOverflow(t *testing.T) {
	rb := observe.NewRingBuffer(64) // capacity rounds to 64

	// Fill to capacity.
	for i := 0; i < 64; i++ {
		if !rb.Enqueue(observe.AuditEvent{RequestID: "fill"}) {
			t.Fatalf("failed to enqueue at index %d", i)
		}
	}

	// Next enqueue should be dropped.
	if rb.Enqueue(observe.AuditEvent{RequestID: "overflow"}) {
		t.Fatal("expected enqueue to fail on full buffer")
	}
	if rb.DroppedCount() != 1 {
		t.Fatalf("DroppedCount = %d; want 1", rb.DroppedCount())
	}

	// Dequeue all.
	count := 0
	for {
		_, ok := rb.Dequeue()
		if !ok {
			break
		}
		count++
	}
	if count != 64 {
		t.Fatalf("dequeued %d events; want 64", count)
	}
}

// ---------------------------------------------------------------------------
// TestObserveRequestNonBlocking exercises the full Provider.ObserveRequest
// path with a stalled sink to confirm end-to-end non-blocking behaviour.
// ---------------------------------------------------------------------------
func TestObserveRequestNonBlocking(t *testing.T) {
	stalled := newStalledSink()

	shipper, err := observe.NewShipper(observe.ShipperConfig{
		PlatformSink:  stalled,
		RingSize:      128,
		FlushInterval: 50 * time.Millisecond,
		BatchSize:     16,
	})
	if err != nil {
		t.Fatalf("NewShipper: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	shipper.Start(ctx)

	provider := &observe.Provider{
		Logger:  slog.Default(),
		Shipper: shipper,
	}

	// Run 50 observed requests — none should block.
	for i := 0; i < 50; i++ {
		done := make(chan struct{})
		go func() {
			_ = provider.ObserveRequest(ctx, "plugin-a", "request_headers", "/api/v1/chat", false, nil, func(ctx context.Context) error {
				return nil
			})
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(100 * time.Millisecond):
			t.Fatalf("ObserveRequest blocked on iteration %d", i)
		}
	}

	_ = stalled.Close()
	shipper.Stop(1 * time.Second)
}

// ---------------------------------------------------------------------------
// TestGracefulShipperShutdown verifies the shipper drains buffered events on
// shutdown even after the context is cancelled.
// ---------------------------------------------------------------------------
func TestGracefulShipperShutdown(t *testing.T) {
	var mu sync.Mutex
	var shipped []observe.AuditEvent

	cSink := &collectingSink{mu: &mu, events: &shipped}

	shipper, err := observe.NewShipper(observe.ShipperConfig{
		CustomerSinks: []observe.Sink{cSink},
		RingSize:      256,
		FlushInterval: 1 * time.Hour, // won't tick — we rely on shutdown drain
		BatchSize:     256,
	})
	if err != nil {
		t.Fatalf("NewShipper: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	shipper.Start(ctx)

	// Enqueue 10 events.
	for i := 0; i < 10; i++ {
		shipper.Capture(observe.AuditEvent{RequestID: "drain-test", RouteID: "r1"})
	}

	// Cancel context and stop — shipper should drain.
	cancel()
	shipper.Stop(2 * time.Second)

	mu.Lock()
	got := len(shipped)
	mu.Unlock()

	if got != 10 {
		t.Errorf("shipped %d events on shutdown; want 10", got)
	}
}

// ---------------------------------------------------------------------------
// TestPlatformSinkNeverReceivesPayload verifies the hard security invariant:
// payload data is stripped before being sent to the platform sink.
// ---------------------------------------------------------------------------
func TestPlatformSinkNeverReceivesPayload(t *testing.T) {
	var mu sync.Mutex
	var platformEvents []observe.AuditEvent
	platformSink := &collectingSink{mu: &mu, events: &platformEvents}

	var customerEvents []observe.AuditEvent
	customerSink := &collectingSink{mu: &mu, events: &customerEvents}

	shipper, err := observe.NewShipper(observe.ShipperConfig{
		PlatformSink:  platformSink,
		CustomerSinks: []observe.Sink{customerSink},
		RingSize:      64,
		FlushInterval: 10 * time.Millisecond,
		BatchSize:     64,
	})
	if err != nil {
		t.Fatalf("NewShipper: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	shipper.Start(ctx)

	// Capture event WITH payload.
	shipper.Capture(observe.AuditEvent{
		RequestID: "payload-test",
		Payload:   []byte(`{"prompt":"secret user data"}`),
	})

	// Wait for flush.
	time.Sleep(50 * time.Millisecond)

	cancel()
	shipper.Stop(1 * time.Second)

	mu.Lock()
	defer mu.Unlock()

	// Platform sink must have nil payload.
	for _, ev := range platformEvents {
		if ev.Payload != nil {
			t.Errorf("platform sink received payload: %s", string(ev.Payload))
		}
	}

	// Customer sink must have the payload.
	found := false
	for _, ev := range customerEvents {
		if ev.Payload != nil {
			found = true
		}
	}
	if !found && len(customerEvents) > 0 {
		t.Error("customer sink did not receive payload")
	}
}

// ---------------------------------------------------------------------------
// TestRedactingLogger verifies that sensitive fields are replaced with
// "[REDACTED]" in the JSON log output.
// ---------------------------------------------------------------------------
func TestRedactingLogger(t *testing.T) {
	var buf bytes.Buffer
	h := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	logger := observe.NewLoggerWithHandler(h)

	logger.Info("auth attempt",
		"user", "alice",
		"authorization", "Bearer super-secret-token",
		"token", "tok_12345",
		"path", "/api/v1/chat",
	)

	output := buf.String()

	// Parse JSON line.
	var entry map[string]any
	if err := json.Unmarshal([]byte(output), &entry); err != nil {
		t.Fatalf("failed to parse log JSON: %v\nraw: %s", err, output)
	}

	if v, ok := entry["authorization"]; ok {
		if v != "[REDACTED]" {
			t.Errorf("authorization = %q; want [REDACTED]", v)
		}
	} else {
		t.Error("authorization key missing from log output")
	}

	if v, ok := entry["token"]; ok {
		if v != "[REDACTED]" {
			t.Errorf("token = %q; want [REDACTED]", v)
		}
	} else {
		t.Error("token key missing from log output")
	}

	// Non-sensitive fields should remain.
	if v, ok := entry["user"]; !ok || v != "alice" {
		t.Errorf("user = %v; want alice", v)
	}
	if v, ok := entry["path"]; !ok || v != "/api/v1/chat" {
		t.Errorf("path = %v; want /api/v1/chat", v)
	}

	// Confirm the raw output doesn't contain the secret.
	if strings.Contains(output, "super-secret-token") {
		t.Error("raw log output contains un-redacted secret")
	}
}

// ---------------------------------------------------------------------------
// TestStdoutSink verifies the stdout sink serialises events as NDJSON.
// ---------------------------------------------------------------------------
func TestStdoutSink(t *testing.T) {
	var buf bytes.Buffer
	sink := observe.NewStdoutSink(&buf)

	err := sink.SendBatch(context.Background(), []observe.AuditEvent{
		{RequestID: "r1", RouteID: "route-a"},
		{RequestID: "r2", RouteID: "route-b"},
	})
	if err != nil {
		t.Fatalf("SendBatch: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines; want 2", len(lines))
	}

	var ev observe.AuditEvent
	if err := json.Unmarshal([]byte(lines[0]), &ev); err != nil {
		t.Fatalf("unmarshal line 0: %v", err)
	}
	if ev.RequestID != "r1" {
		t.Errorf("line 0 request_id = %q; want r1", ev.RequestID)
	}
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

func BenchmarkCapture(b *testing.B) {
	shipper, _ := observe.NewShipper(observe.ShipperConfig{
		RingSize:      65536,
		FlushInterval: 1 * time.Hour,
		BatchSize:     256,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	shipper.Start(ctx)
	defer shipper.Stop(1 * time.Second)

	ev := observe.AuditEvent{
		RequestID: "bench",
		RouteID:   "bench-route",
		Phase:     "request_headers",
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			shipper.Capture(ev)
		}
	})
}

func BenchmarkRingBuffer_EnqueueDequeue(b *testing.B) {
	rb := observe.NewRingBuffer(65536)

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rb.Enqueue(observe.AuditEvent{RequestID: "bench"})
			rb.Dequeue()
		}
	})
}
