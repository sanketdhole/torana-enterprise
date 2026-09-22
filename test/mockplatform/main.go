package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	controlplanev1 "github.com/phaselume/torana/api/proto/controlplane/v1"
	"google.golang.org/grpc"
)

func main() {
	grpcPort := flag.String("grpc-port", ":9090", "gRPC control plane listen address")
	httpPort := flag.String("http-port", ":9091", "HTTP dashboard listen address")
	configFile := flag.String("config-file", "test/mockplatform/config.json", "Path to snapshot configuration file")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	logger.Info("starting Torana Mock Platform",
		"grpc_port", *grpcPort,
		"http_port", *httpPort,
		"config_file", *configFile,
	)

	state, err := NewPlatformState(*configFile, logger)
	if err != nil {
		logger.Error("failed to initialize platform state", "error", err)
		os.Exit(1)
	}

	// Start file watcher for hot reloading
	state.StartWatcher(500 * time.Millisecond)

	// 1. Start gRPC server
	lis, err := net.Listen("tcp", *grpcPort)
	if err != nil {
		logger.Error("failed to listen on gRPC port", "error", err)
		os.Exit(1)
	}

	grpcServer := grpc.NewServer()
	cpServer := NewControlPlaneServer(state, logger)
	controlplanev1.RegisterControlPlaneServiceServer(grpcServer, cpServer)

	go func() {
		logger.Info("gRPC control plane server listening", "addr", *grpcPort)
		if err := grpcServer.Serve(lis); err != nil {
			logger.Error("gRPC server error", "error", err)
		}
	}()

	// 2. Start HTTP dashboard
	go func() {
		logger.Info("HTTP dashboard listening", "url", fmt.Sprintf("http://localhost%s", *httpPort))
		if err := StartHTTPDashboard(*httpPort, state); err != nil {
			logger.Error("HTTP dashboard server error", "error", err)
		}
	}()

	// Wait for termination signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logger.Info("shutting down mock platform...")
	grpcServer.GracefulStop()
	logger.Info("mock platform stopped")
}
