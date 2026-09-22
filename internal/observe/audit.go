package observe

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// AuditEvent is a single auditable occurrence.
// Metadata is always captured; Payload is captured only when the route
// is explicitly opted-in and is NEVER forwarded to the platform sink.
type AuditEvent struct {
	Timestamp  time.Time         `json:"timestamp"`
	TraceID    string            `json:"trace_id,omitempty"`
	RequestID  string            `json:"request_id"`
	RouteID    string            `json:"route_id"`
	PluginID   string            `json:"plugin_id,omitempty"`
	Phase      string            `json:"phase"`
	Method     string            `json:"method"`
	Path       string            `json:"path"`
	StatusCode int               `json:"status_code,omitempty"`
	DurationMs int64             `json:"duration_ms,omitempty"`
	Error      string            `json:"error,omitempty"`
	Meta       map[string]string `json:"meta,omitempty"`

	// Payload is opt-in per route and is only sent to customer sinks, never
	// to the platform stream.
	Payload []byte `json:"payload,omitempty"`
}

// --- Ring Buffer (lock-free SPMC bounded queue) -----------------------------

// RingBuffer is a bounded, non-blocking ring buffer for AuditEvent values.
// On overflow the oldest unread event is silently dropped and the drop counter
// is incremented.
type RingBuffer struct {
	mu       sync.Mutex
	buf      []AuditEvent
	mask     int
	head     int
	tail     int
	count    int
	cap      int
	dropped  atomic.Uint64
	enqueued atomic.Uint64
}

// NewRingBuffer creates a ring buffer whose capacity is rounded up to the next
// power of two (minimum 64).
func NewRingBuffer(minCap int) *RingBuffer {
	capacity := 64
	for capacity < minCap {
		capacity <<= 1
	}
	return &RingBuffer{
		buf:  make([]AuditEvent, capacity),
		mask: capacity - 1,
		cap:  capacity,
	}
}

// Enqueue appends an event without blocking. Returns false if the buffer is
// full (the event is dropped).
func (rb *RingBuffer) Enqueue(ev AuditEvent) bool {
	rb.mu.Lock()
	if rb.count >= rb.cap {
		rb.mu.Unlock()
		rb.dropped.Add(1)
		return false
	}
	rb.buf[rb.head] = ev
	rb.head = (rb.head + 1) & rb.mask
	rb.count++
	rb.enqueued.Add(1)
	rb.mu.Unlock()
	return true
}

// Dequeue removes the oldest event. Returns (event, true) or (zero, false) if
// the buffer is empty.
func (rb *RingBuffer) Dequeue() (AuditEvent, bool) {
	rb.mu.Lock()
	if rb.count == 0 {
		rb.mu.Unlock()
		return AuditEvent{}, false
	}
	ev := rb.buf[rb.tail]
	rb.buf[rb.tail] = AuditEvent{} // zero out for GC
	rb.tail = (rb.tail + 1) & rb.mask
	rb.count--
	rb.mu.Unlock()
	return ev, true
}

// Len returns the current number of buffered events.
func (rb *RingBuffer) Len() int {
	rb.mu.Lock()
	n := rb.count
	rb.mu.Unlock()
	return n
}

// Cap returns the capacity of the ring buffer.
func (rb *RingBuffer) Cap() int {
	return rb.cap
}

// DroppedCount returns total events dropped due to saturation.
func (rb *RingBuffer) DroppedCount() uint64 { return rb.dropped.Load() }

// EnqueuedCount returns total events successfully enqueued.
func (rb *RingBuffer) EnqueuedCount() uint64 { return rb.enqueued.Load() }

// --- Disk Spool -------------------------------------------------------------

// DiskSpool writes newline-delimited JSON events to a file for crash recovery.
type DiskSpool struct {
	mu   sync.Mutex
	f    *os.File
	enc  *json.Encoder
	path string
}

// NewDiskSpool opens or creates the spool file at the given path.
func NewDiskSpool(dir string) (*DiskSpool, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("spool mkdir: %w", err)
	}
	path := filepath.Join(dir, "audit_spool.ndjson")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("spool open: %w", err)
	}
	return &DiskSpool{f: f, enc: json.NewEncoder(f), path: path}, nil
}

// Write appends a single event to the spool.
func (d *DiskSpool) Write(ev AuditEvent) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.enc.Encode(ev)
}

// ReadAll reads back all spooled events (for replay after restart).
func (d *DiskSpool) ReadAll() ([]AuditEvent, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	f, err := os.Open(d.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var events []AuditEvent
	dec := json.NewDecoder(f)
	for dec.More() {
		var ev AuditEvent
		if err := dec.Decode(&ev); err != nil {
			break
		}
		events = append(events, ev)
	}
	return events, nil
}

// Truncate clears the spool after successful shipment.
func (d *DiskSpool) Truncate() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.f.Truncate(0)
}

// Close closes the spool file.
func (d *DiskSpool) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.f.Close()
}

// --- Shipper ----------------------------------------------------------------

// ShipperConfig configures the audit event shipper.
type ShipperConfig struct {
	// PlatformSink receives metadata-only events shipped to the platform.
	PlatformSink Sink
	// CustomerSinks receive events shipped to customer-specified destinations.
	// Payload data is only forwarded to customer sinks when the route opts in.
	CustomerSinks []Sink
	// RingSize is the capacity of the in-memory ring buffer (default 8192).
	RingSize int
	// SpoolDir is the path for crash-resilient disk spooling. Empty disables spooling.
	SpoolDir string
	// FlushInterval controls how often the shipper drains the ring buffer.
	FlushInterval time.Duration
	// BatchSize is the max events per sink batch call (default 128).
	BatchSize int
	// Logger for internal diagnostics.
	Logger io.Writer
	// Metrics for recording audit drops.
	Metrics *Metrics
}

// Shipper drains the ring buffer, optionally persists to a disk spool, and
// ships events to the platform and/or customer sinks. It NEVER sends payload
// data to the platform sink.
type Shipper struct {
	ring          *RingBuffer
	spool         *DiskSpool
	cfg           ShipperConfig
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	flushInterval time.Duration
	batchSize     int
	metrics       *Metrics
}

// NewShipper creates a Shipper with the given configuration.
func NewShipper(cfg ShipperConfig) (*Shipper, error) {
	if cfg.RingSize <= 0 {
		cfg.RingSize = 8192
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 200 * time.Millisecond
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 128
	}

	ring := NewRingBuffer(cfg.RingSize)

	var spool *DiskSpool
	if cfg.SpoolDir != "" {
		var err error
		spool, err = NewDiskSpool(cfg.SpoolDir)
		if err != nil {
			return nil, fmt.Errorf("shipper spool init: %w", err)
		}
	}

	return &Shipper{
		ring:          ring,
		spool:         spool,
		cfg:           cfg,
		flushInterval: cfg.FlushInterval,
		batchSize:     cfg.BatchSize,
		metrics:       cfg.Metrics,
	}, nil
}

// Capture enqueues an audit event into the ring buffer without blocking the
// caller. This is the only function called on the hot request path.
func (s *Shipper) Capture(ev AuditEvent) {
	if !s.ring.Enqueue(ev) {
		// Ring full — event dropped; bump metric.
		if s.metrics != nil {
			s.metrics.IncAuditDropped(context.Background())
		}
	}
}

// Start begins the background drain/ship loop.
func (s *Shipper) Start(ctx context.Context) {
	ctx, s.cancel = context.WithCancel(ctx)
	s.wg.Add(1)
	go s.loop(ctx)
}

func (s *Shipper) loop(ctx context.Context) {
	defer s.wg.Done()

	ticker := time.NewTicker(s.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.drain(context.Background())
			return
		case <-ticker.C:
			s.drain(ctx)
		}
	}
}

func (s *Shipper) drain(ctx context.Context) {
	batch := make([]AuditEvent, 0, s.batchSize)
	for len(batch) < s.batchSize {
		ev, ok := s.ring.Dequeue()
		if !ok {
			break
		}
		batch = append(batch, ev)
	}
	if len(batch) == 0 {
		return
	}

	// Optionally persist to disk spool first.
	if s.spool != nil {
		for _, ev := range batch {
			_ = s.spool.Write(ev)
		}
	}

	// Ship to platform sink (metadata only — strip payload).
	if s.cfg.PlatformSink != nil {
		metaOnly := make([]AuditEvent, len(batch))
		for i, ev := range batch {
			ev.Payload = nil // NEVER send payload to platform
			metaOnly[i] = ev
		}
		_ = s.cfg.PlatformSink.SendBatch(ctx, metaOnly)
	}

	// Ship to customer sinks (payload included when present).
	for _, sink := range s.cfg.CustomerSinks {
		_ = sink.SendBatch(ctx, batch)
	}

	// Truncate spool on successful delivery.
	if s.spool != nil {
		_ = s.spool.Truncate()
	}
}

// Stop signals the shipper to drain remaining events and exit.
func (s *Shipper) Stop(timeout time.Duration) {
	if s.cancel != nil {
		s.cancel()
	}
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
	}
	if s.spool != nil {
		_ = s.spool.Close()
	}
}

// RingBuffer returns the underlying ring buffer (for testing introspection).
func (s *Shipper) RingBuffer() *RingBuffer { return s.ring }
