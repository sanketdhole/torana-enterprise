package telemetry_test

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/phaselume/torana/internal/telemetry"
)

type memorySink struct {
	mu     sync.Mutex
	events []telemetry.Event
}

func (m *memorySink) SendBatch(_ context.Context, batch []telemetry.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, batch...)
	return nil
}

func (m *memorySink) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.events)
}

func TestEmitter_BoundedQueueAndDrain(t *testing.T) {
	sink := &memorySink{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	emitter := telemetry.NewEmitter(100, sink, logger)
	ctx := context.Background()
	emitter.Start(ctx)

	// Emit 50 events
	for i := 0; i < 50; i++ {
		ok := emitter.Emit(telemetry.Event{
			RouteID:    "route-chat",
			UpstreamID: "llm-openai",
			StatusCode: 200,
			DurationMs: 15,
		})
		if !ok {
			t.Fatalf("expected event %d to be emitted successfully", i)
		}
	}

	emitter.Stop(2 * time.Second)

	if sink.count() != 50 {
		t.Fatalf("expected 50 drained events in sink, got %d", sink.count())
	}
	if emitter.DroppedCount() != 0 {
		t.Errorf("expected 0 dropped events, got %d", emitter.DroppedCount())
	}
}

func TestEmitter_BufferSaturationDrops(t *testing.T) {
	sink := &memorySink{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Tiny queue size of 2, worker not started so channel stays full
	emitter := telemetry.NewEmitter(2, sink, logger)

	ok1 := emitter.Emit(telemetry.Event{RouteID: "r1"})
	ok2 := emitter.Emit(telemetry.Event{RouteID: "r2"})
	ok3 := emitter.Emit(telemetry.Event{RouteID: "r3"}) // Should drop

	if !ok1 || !ok2 {
		t.Errorf("expected first two emits to succeed, got %v, %v", ok1, ok2)
	}
	if ok3 {
		t.Errorf("expected third emit to fail due to buffer saturation")
	}

	if emitter.DroppedCount() != 1 {
		t.Errorf("expected 1 dropped event, got %d", emitter.DroppedCount())
	}
}

func BenchmarkEmitter_Emit(b *testing.B) {
	sink := &memorySink{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	emitter := telemetry.NewEmitter(100000, sink, logger)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	emitter.Start(ctx)

	event := telemetry.Event{
		RouteID:    "route-chat",
		UpstreamID: "llm-openai",
		StatusCode: 200,
		DurationMs: 12,
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			emitter.Emit(event)
		}
	})
}
