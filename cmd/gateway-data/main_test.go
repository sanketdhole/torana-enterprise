package main

import (
	"os"
	"testing"
)

func TestParseFlags_DefaultsAndOverrides(t *testing.T) {
	t.Run("default flags", func(t *testing.T) {
		cfg, showVersion, err := parseFlags([]string{})
		if err != nil {
			t.Fatalf("unexpected error parsing flags: %v", err)
		}
		if showVersion {
			t.Errorf("expected showVersion to be false")
		}
		if cfg.ListenHTTP != ":8080" {
			t.Errorf("expected default HTTP port ':8080', got %s", cfg.ListenHTTP)
		}
		if cfg.ListenGRPC != ":9090" {
			t.Errorf("expected default gRPC port ':9090', got %s", cfg.ListenGRPC)
		}
		if cfg.Namespace != "default" {
			t.Errorf("expected default namespace 'default', got %s", cfg.Namespace)
		}
	})

	t.Run("flag overrides", func(t *testing.T) {
		args := []string{
			"--namespace=prod-ai",
			"--platform-url=https://cp.torana.io:443",
			"--listen-http=:8000",
			"--listen-grpc=:9000",
			"--peers-dns=torana-peers.internal",
			"--config-bundle=/etc/torana/bundle.json",
		}
		cfg, _, err := parseFlags(args)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Namespace != "prod-ai" {
			t.Errorf("expected namespace 'prod-ai', got %s", cfg.Namespace)
		}
		if cfg.PlatformURL != "https://cp.torana.io:443" {
			t.Errorf("expected platform URL 'https://cp.torana.io:443', got %s", cfg.PlatformURL)
		}
		if cfg.ListenHTTP != ":8000" {
			t.Errorf("expected HTTP port ':8000', got %s", cfg.ListenHTTP)
		}
		if cfg.ListenGRPC != ":9000" {
			t.Errorf("expected gRPC port ':9000', got %s", cfg.ListenGRPC)
		}
		if cfg.PeersDNS != "torana-peers.internal" {
			t.Errorf("expected peers DNS 'torana-peers.internal', got %s", cfg.PeersDNS)
		}
		if cfg.ConfigBundle != "/etc/torana/bundle.json" {
			t.Errorf("expected config bundle '/etc/torana/bundle.json', got %s", cfg.ConfigBundle)
		}
	})

	t.Run("env var fallback", func(t *testing.T) {
		_ = os.Setenv("GATEWAY_NAMESPACE", "staging-ai")
		_ = os.Setenv("PLATFORM_URL", "grpc://cp.staging.local:9090")
		defer func() {
			_ = os.Unsetenv("GATEWAY_NAMESPACE")
			_ = os.Unsetenv("PLATFORM_URL")
		}()

		cfg, _, err := parseFlags([]string{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Namespace != "staging-ai" {
			t.Errorf("expected namespace 'staging-ai', got %s", cfg.Namespace)
		}
		if cfg.PlatformURL != "grpc://cp.staging.local:9090" {
			t.Errorf("expected platform URL 'grpc://cp.staging.local:9090', got %s", cfg.PlatformURL)
		}
	})

	t.Run("version flag", func(t *testing.T) {
		_, showVersion, err := parseFlags([]string{"--version"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !showVersion {
			t.Errorf("expected showVersion to be true")
		}
	})
}
