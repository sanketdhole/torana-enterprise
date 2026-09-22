package process

import (
	"fmt"
	"log/slog"
	"sync"
)

// ProcessPluginManager manages the lifecycle, launch, and discovery of process and remote plugins.
type ProcessPluginManager struct {
	logger  *slog.Logger
	filters sync.Map // map[string]*ProcessFilter
	mu      sync.Mutex
}

// NewProcessPluginManager creates a new ProcessPluginManager.
func NewProcessPluginManager(logger *slog.Logger) *ProcessPluginManager {
	return &ProcessPluginManager{
		logger: logger,
	}
}

// RegisterPlugin launches or connects to a plugin specified by manifest, returning a ProcessFilter.
func (m *ProcessPluginManager) RegisterPlugin(manifest *ProcessManifest) (*ProcessFilter, error) {
	if manifest == nil {
		return nil, ErrNilManifest
	}

	var launcher *ProcessLauncher
	var client *PluginClient
	var err error

	if manifest.Tier == TierLocalProcess {
		// 1. Verify binary before starting
		if err := VerifyBinary(manifest.BinaryPath, manifest.SHA256Checksum, manifest.AllowedBinaryDirs); err != nil {
			return nil, err
		}

		// 2. Start Process Launcher
		launcher = NewProcessLauncher(manifest, func() {
			if client != nil {
				_ = client.Redial()
			}
			if m.logger != nil {
				m.logger.Info("process plugin restarted by supervisor", "plugin", manifest.Name)
			}
		}, m.logger)

		if err := launcher.Start(); err != nil {
			return nil, fmt.Errorf("failed to launch child plugin %s: %w", manifest.Name, err)
		}

		// 3. Dial gRPC over Unix Domain Socket
		client, err = NewPluginClient(manifest, launcher.SocketPath(), m.logger)
		if err != nil {
			_ = launcher.Close()
			return nil, fmt.Errorf("failed to establish client connection to plugin %s: %w", manifest.Name, err)
		}
	} else {
		// Remote Tier: Dial gRPC over TLS/mTLS
		client, err = NewPluginClient(manifest, "", m.logger)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to remote plugin %s: %w", manifest.Name, err)
		}
	}

	filter := NewProcessFilter(manifest, launcher, client, m.logger)
	m.filters.Store(manifest.Name, filter)

	return filter, nil
}

// RegisterEgress launches or connects to a plugin configured as an Egress connector.
func (m *ProcessPluginManager) RegisterEgress(manifest *ProcessManifest) (*EgressConnector, error) {
	filter, err := m.RegisterPlugin(manifest)
	if err != nil {
		return nil, err
	}
	return NewEgressConnector(manifest.Name, filter), nil
}

// RegisterIngress launches or connects to a plugin configured as an Ingress connector.
func (m *ProcessPluginManager) RegisterIngress(manifest *ProcessManifest) (*IngressConnector, error) {
	filter, err := m.RegisterPlugin(manifest)
	if err != nil {
		return nil, err
	}
	return NewIngressConnector(manifest.Name, filter), nil
}

// GetFilter retrieves an active filter by name.
func (m *ProcessPluginManager) GetFilter(name string) (*ProcessFilter, bool) {
	val, ok := m.filters.Load(name)
	if !ok {
		return nil, false
	}
	return val.(*ProcessFilter), true
}

// Close gracefully stops all active process and remote plugins.
func (m *ProcessPluginManager) Close() error {
	var errs []error
	m.filters.Range(func(key, value any) bool {
		f := value.(*ProcessFilter)
		if err := f.Close(); err != nil {
			errs = append(errs, err)
		}
		return true
	})
	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}
