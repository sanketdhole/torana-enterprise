package supervisor

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/phaselume/torana/internal/config"
	"github.com/phaselume/torana/internal/controlplane"
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
	cpClient  *controlplane.Client
	wg        sync.WaitGroup
}

// New creates a new Supervisor instance.
func New(cfg *config.BootstrapConfig, logger *slog.Logger) *Supervisor {
	holder := config.NewSnapshotHolder()

	// Logging telemetry sink
	sink := telemetry.NewLoggingSink(logger)
	emitter := telemetry.NewEmitter(cfg.TelemetryQueueSize, sink, logger)

	// Egress registry
	egressReg := egress.NewRegistry()

	// Pipeline filter chain
	chain := pipeline.NewChain()
	chain.SetLogger(logger)

	httpLsnr := ingress.NewHTTPListener(cfg, holder, egressReg, emitter, chain, logger)

	sup := &Supervisor{
		cfg:       cfg,
		logger:    logger,
		holder:    holder,
		egressReg: egressReg,
		emitter:   emitter,
		httpLsnr:  httpLsnr,
	}

	// 1. Check if a static bootstrap bundle file is provided
	if cfg.ConfigBundle != "" {
		snap, err := config.LoadBundleFromFile(cfg.ConfigBundle)
		if err != nil {
			logger.Warn("failed to load initial config bundle", "path", cfg.ConfigBundle, "error", err)
			httpLsnr.SetReady(false)
		} else if err := sup.UpdateSnapshot(snap); err != nil {
			logger.Warn("failed to apply initial config bundle", "error", err)
			httpLsnr.SetReady(false)
		} else {
			logger.Info("loaded bootstrap config bundle", "path", cfg.ConfigBundle, "version", snap.Version)
		}
	} else if cfg.LKGPath != "" {
		// 2. Attempt to load Last-Known-Good snapshot from disk fallback if platform is unreachable
		lkgSnap, err := config.LoadLKG(cfg.LKGPath)
		if err == nil && lkgSnap != nil {
			if err := sup.UpdateSnapshot(lkgSnap); err == nil {
				logger.Info("recovered from Last-Known-Good snapshot on disk", "path", cfg.LKGPath, "version", lkgSnap.Version)
			}
		} else {
			httpLsnr.SetReady(false)
		}
	} else {
		httpLsnr.SetReady(false)
	}

	// 3. If PlatformURL is configured, initialize control plane client
	if cfg.PlatformURL != "" {
		sup.cpClient = controlplane.NewClient(cfg, sup, logger)
	}

	return sup
}

// Holder returns the snapshot holder.
func (s *Supervisor) Holder() *config.SnapshotHolder {
	return s.holder
}

// HTTPListener returns the HTTP ingress listener.
func (s *Supervisor) HTTPListener() *ingress.HTTPListener {
	return s.httpLsnr
}

// UpdateSnapshot applies a new configuration snapshot atomically across the data plane.
func (s *Supervisor) UpdateSnapshot(snap *config.Snapshot) error {
	if err := snap.Validate(); err != nil {
		return fmt.Errorf("snapshot validation failed: %w", err)
	}

	if err := s.holder.Store(snap); err != nil {
		return fmt.Errorf("failed to store snapshot: %w", err)
	}

	compiledRouter := router.Compile(snap)
	s.httpLsnr.UpdateRouter(compiledRouter)
	s.httpLsnr.SetReady(true)

	// Persist LKG snapshot to disk
	if s.cfg.LKGPath != "" {
		if err := config.SaveLKG(s.cfg.LKGPath, snap); err != nil {
			s.logger.Warn("failed to persist last-known-good snapshot to disk", "path", s.cfg.LKGPath, "error", err)
		}
	}

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

	// Start control plane client worker if configured
	if s.cpClient != nil {
		s.cpClient.Start(ctx)
	}

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

	s.logger.Info("torana data plane initialized",
		"namespace", s.cfg.Namespace,
		"http_addr", s.cfg.HTTPAddress(),
		"grpc_addr", s.cfg.GRPCAddress(),
		"platform_url", s.cfg.PlatformURL,
		"env", s.cfg.Environment,
		"ready", s.holder.HasSnapshot(),
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

	// 1. Mark unready & stop HTTP listener
	if err := s.httpLsnr.Stop(drainCtx); err != nil {
		s.logger.Error("error stopping http listener", "error", err)
	}

	// 2. Wait for ingress goroutine
	s.wg.Wait()

	// 3. Stop control plane client
	if s.cpClient != nil {
		s.cpClient.Stop()
	}

	// 4. Drain and stop telemetry emitter
	s.emitter.Stop(s.cfg.DrainTimeout)

	// 5. Close egress connection pools
	_ = s.egressReg.Close()

	s.logger.Info("torana data plane shutdown completed gracefully")
	return nil
}
