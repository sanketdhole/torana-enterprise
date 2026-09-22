package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/phaselume/torana/internal/config"
	"github.com/phaselume/torana/internal/supervisor"
)

var (
	// Version is injected at build time using -ldflags "-X main.Version=x.y.z"
	Version = "0.1.0-dev"
)

func main() {
	cfg, showVersion, err := config.ParseFlags(os.Args[1:])
	if err != nil {
		os.Exit(2)
	}

	if showVersion {
		fmt.Printf("gateway-data version %s\n", Version)
		os.Exit(0)
	}

	var logger *slog.Logger
	if cfg.Environment == "production" {
		logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))
	} else {
		logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		}))
	}

	logger.Info("bootstrapping gateway-data",
		"version", Version,
		"namespace", cfg.Namespace,
		"platform_url", cfg.PlatformURL,
		"listen_http", cfg.ListenHTTP,
		"listen_grpc", cfg.ListenGRPC,
		"environment", cfg.Environment,
	)

	sup := supervisor.New(cfg, logger)

	if err := sup.Run(context.Background()); err != nil {
		logger.Error("gateway supervisor terminated with error", "error", err)
		os.Exit(1)
	}
}
