package main

import (
	"context"
	"flag"
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

func parseFlags(args []string) (*config.BootstrapConfig, bool, error) {
	fs := flag.NewFlagSet("gateway-data", flag.ContinueOnError)

	cfg := config.LoadBootstrapConfig()

	fs.StringVar(&cfg.Namespace, "namespace", cfg.Namespace, "Deployment namespace identity")
	fs.StringVar(&cfg.PlatformURL, "platform-url", cfg.PlatformURL, "Platform control plane gRPC service URL")
	fs.StringVar(&cfg.EnrollTokenFile, "enroll-token-file", cfg.EnrollTokenFile, "Path to node enrollment token file")
	fs.StringVar(&cfg.ListenHTTP, "listen-http", cfg.ListenHTTP, "HTTP ingress listen address (default :8080)")
	fs.StringVar(&cfg.ListenGRPC, "listen-grpc", cfg.ListenGRPC, "gRPC ingress listen address (default :9090)")
	fs.StringVar(&cfg.PeersDNS, "peers-dns", cfg.PeersDNS, "DNS SRV / headless service name for peer discovery")
	fs.StringVar(&cfg.ConfigBundle, "config-bundle", cfg.ConfigBundle, "Path to local static configuration bundle JSON file")

	showVersion := fs.Bool("version", false, "Print binary version and exit")

	if err := fs.Parse(args); err != nil {
		return nil, false, err
	}

	return cfg, *showVersion, nil
}

func main() {
	cfg, showVersion, err := parseFlags(os.Args[1:])
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
