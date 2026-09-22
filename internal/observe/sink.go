package observe

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
)

// Sink receives batches of audit events for delivery to an external system.
type Sink interface {
	// SendBatch delivers a batch of events. Implementations must be safe for
	// concurrent calls.
	SendBatch(ctx context.Context, events []AuditEvent) error
	// Close releases any resources held by the sink.
	Close() error
}

// --- StdoutSink --------------------------------------------------------------

// StdoutSink writes newline-delimited JSON events to an io.Writer (defaults to os.Stdout).
type StdoutSink struct {
	mu  sync.Mutex
	w   io.Writer
	enc *json.Encoder
}

// NewStdoutSink creates a sink that outputs JSON to the given writer.
// Pass nil to write to os.Stdout.
func NewStdoutSink(w io.Writer) *StdoutSink {
	if w == nil {
		w = os.Stdout
	}
	return &StdoutSink{w: w, enc: json.NewEncoder(w)}
}

func (s *StdoutSink) SendBatch(_ context.Context, events []AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ev := range events {
		if err := s.enc.Encode(ev); err != nil {
			return fmt.Errorf("stdout sink write: %w", err)
		}
	}
	return nil
}

func (s *StdoutSink) Close() error { return nil }

// --- KafkaSink (placeholder) -------------------------------------------------

// KafkaSink is a placeholder for a Kafka-backed audit sink.
// A production implementation would use a Kafka producer client.
type KafkaSink struct {
	Brokers []string
	Topic   string
}

func NewKafkaSink(brokers []string, topic string) *KafkaSink {
	return &KafkaSink{Brokers: brokers, Topic: topic}
}

func (k *KafkaSink) SendBatch(_ context.Context, events []AuditEvent) error {
	// TODO: implement Kafka produce for each event
	_ = events
	return nil
}

func (k *KafkaSink) Close() error { return nil }

// --- S3Sink (placeholder) ----------------------------------------------------

// S3Sink is a placeholder for an S3-backed audit sink.
type S3Sink struct {
	Bucket string
	Prefix string
}

func NewS3Sink(bucket, prefix string) *S3Sink {
	return &S3Sink{Bucket: bucket, Prefix: prefix}
}

func (s *S3Sink) SendBatch(_ context.Context, events []AuditEvent) error {
	// TODO: implement S3 PutObject with NDJSON payload
	_ = events
	return nil
}

func (s *S3Sink) Close() error { return nil }
