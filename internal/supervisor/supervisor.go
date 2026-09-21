package supervisor

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/phaselume/torana/internal/config"
	"github.com/phaselume/torana/internal/egress"
	"github.com/phaselume/torana/internal/ingress"
	"github.com/phaselume/torana/internal/pipeline"
	"github.com/phaselume/torana/internal/router"
	"github.com/phaselume/torana/internal/telemetry"
)

// Supervisor orchestrates all background tasks, listeners, and graceful shutdown.
type Supervisor struct {
	cfg       *config.BootstrapConfig
	logger    *slog.Logger
	holder    *config.SnapshotHolder
	egressReg *egress.Registry
	emitter   *telemetry.Emitter
	httpLsnr  *ingress.HTTPListener
	wg        sync.WaitGroup
}

// New creates a new Supervisor instance.
func New(cfg *config.BootstrapConfig, logger *slog.Logger) *Supervisor {
	holder := config.NewSnapshotHolder()

	// Initialize default snapshot for startup if needed
	defaultSnap := &config.Snapshot{
		Version:   1,
		Timestamp: time.Now(),
		Routes:    nil,
		Upstreams: make(map[string]config.UpstreamCluster),
	}
	_ = holder.Store(defaultSnap)

	// Logging telemetry sink
	sink := telemetry.NewLoggingSink(logger)
	emitter := telemetry.NewEmitter(cfg.TelemetryQueueSize, sink, logger)

	// Egress registry
	egressReg := egress.NewRegistry()

	// Pipeline filter chain (standard auth/logging filters can be attached)
	chain := pipeline.NewChain()

	httpLsnr := ingress.NewHTTPListener(cfg, holder, egressReg, emitter, chain, logger)
	httpLsnr.UpdateRouter(router.Compile(defaultSnap))
	httpLsnr.SetReady(true)

	return &Supervisor{
		cfg:       cfg,
		logger:    logger,
		holder:    holder,
		egressReg: egressReg,
		emitter:   emitter,
		httpLsnr:  httpLsnr,
	}
}

// UpdateSnapshot applies a new configuration snapshot atomically across the data plane.
func (s *Supervisor) UpdateSnapshot(snap *config.Snapshot) error {
	if err := s.holder.Store(snap); err != nil {
		return fmt.Errorf("failed to store snapshot: %w", err)
	}

	compiledRouter := router.Compile(snap)
	s.httpLsnr.UpdateRouter(compiledRouter)

	s.logger.Info("applied configuration snapshot",
		"version", snap.Version,
		"routes_count", len(snap.Routes),
		"upstreams_count", len(snap.Upstreams),
	)
	return nil
}

// Run blocks until SIGINT/SIGTERM, managing listener lifecycles and graceful draining.
func (s *Supervisor) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Start telemetry emitter background worker
	s.emitter.Start(ctx)

	// Listen for OS signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	serverErr := make(chan error, 1)

	// Start HTTP Ingress listener in managed goroutine
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := s.httpLsnr.Start(ctx); err != nil {
			serverErr <- err
		}
	}()

	s.logger.Info("torana data plane ready",
		"namespace", s.cfg.Namespace,
		"http_addr", s.cfg.HTTPAddress(),
		"env", s.cfg.Environment,
	)

	select {
	case sig := <-sigChan:
		s.logger.Info("received termination signal, initiating graceful drain", "signal", sig.String())
	case err := <-serverErr:
		s.logger.Error("ingress listener encountered fatal error", "error", err)
		return err
	case <-ctx.Done():
		s.logger.Info("supervisor context cancelled")
	}

	// Graceful Drain sequence
	drainCtx, drainCancel := context.WithTimeout(context.Background(), s.cfg.DrainTimeout)
	defer drainCancel()

	// 1. Stop HTTP listener
	if err := s.httpLsnr.Stop(drainCtx); err != nil {
		s.logger.Error("error stopping http listener", "error", err)
	}

	// 2. Wait for ingress goroutine
	s.wg.Wait()

	// 3. Drain and stop telemetry emitter
	s.emitter.Stop(s.cfg.DrainTimeout)

	// 4. Close egress connection pools
	_ = s.egressReg.Close()

	s.logger.Info("torana data plane shutdown completed gracefully")
	return nil
}
