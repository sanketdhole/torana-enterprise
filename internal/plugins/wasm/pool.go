package wasm

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// PooledInstance wraps an instantiated wazero.api.Module with identity and generation tracking.
type PooledInstance struct {
	ID       string
	Module   api.Module
	Faulted  bool
	instance uint64
}

// InstancePool manages a thread-safe pool of warm Wasm module instances.
type InstancePool struct {
	runtime        wazero.Runtime
	compiled       wazero.CompiledModule
	manifest       *PluginManifest
	pool           chan *PooledInstance
	instanceSeq    atomic.Uint64
	activeBorrow   atomic.Int64
	maxInstances   int
	closed         atomic.Bool
	closeOnce      sync.Once
	ctx            context.Context
	cancel         context.CancelFunc
}

// NewInstancePool compiles the Wasm bytecode once and initializes an instance pool.
func NewInstancePool(parentCtx context.Context, wasmBytes []byte, manifest *PluginManifest, env *HostEnv) (*InstancePool, error) {
	if manifest == nil {
		return nil, ErrNilManifest
	}

	ctx, cancel := context.WithCancel(parentCtx)

	// Wazero pure-Go optimizing JIT runtime with memory limits and context cancellation
	rConfig := wazero.NewRuntimeConfig().WithCloseOnContextDone(true)
	if manifest.MemoryLimitPages > 0 {
		rConfig = rConfig.WithMemoryLimitPages(manifest.MemoryLimitPages)
	}
	r := wazero.NewRuntimeWithConfig(ctx, rConfig)

	// Register sandboxed capability-gated host functions
	if err := RegisterHostFunctions(ctx, r, manifest, env); err != nil {
		_ = r.Close(ctx)
		cancel()
		return nil, fmt.Errorf("failed to register host functions: %w", err)
	}

	// Compile the Wasm binary ONCE
	compiled, err := r.CompileModule(ctx, wasmBytes)
	if err != nil {
		_ = r.Close(ctx)
		cancel()
		return nil, fmt.Errorf("failed to compile wasm module %s: %w", manifest.Name, err)
	}

	poolSize := manifest.PoolSize
	if poolSize <= 0 {
		poolSize = 10
	}

	p := &InstancePool{
		runtime:      r,
		compiled:     compiled,
		manifest:     manifest,
		pool:         make(chan *PooledInstance, poolSize),
		maxInstances: poolSize,
		ctx:          ctx,
		cancel:       cancel,
	}

	// Pre-warm initial instances
	initialWarm := min(poolSize, 2)
	for i := 0; i < initialWarm; i++ {
		inst, err := p.createInstance(ctx)
		if err != nil {
			_ = p.Close(ctx)
			return nil, fmt.Errorf("failed to pre-warm wasm instance: %w", err)
		}
		p.pool <- inst
	}

	return p, nil
}

func (p *InstancePool) createInstance(ctx context.Context) (*PooledInstance, error) {
	seq := p.instanceSeq.Add(1)
	instName := fmt.Sprintf("%s-inst-%d", p.manifest.Name, seq)

	mConfig := wazero.NewModuleConfig().
		WithName(instName)

	mod, err := p.runtime.InstantiateModule(ctx, p.compiled, mConfig)
	if err != nil {
		return nil, err
	}

	return &PooledInstance{
		ID:       instName,
		Module:   mod,
		instance: seq,
	}, nil
}

// Get borrows a warm instance from the pool or creates a fresh one.
func (p *InstancePool) Get(ctx context.Context) (*PooledInstance, error) {
	if p.closed.Load() {
		return nil, ErrPluginClosed
	}

	p.activeBorrow.Add(1)

	select {
	case <-ctx.Done():
		p.activeBorrow.Add(-1)
		return nil, ctx.Err()
	case inst := <-p.pool:
		return inst, nil
	default:
		// Pool empty, dynamically instantiate new instance
		inst, err := p.createInstance(ctx)
		if err != nil {
			p.activeBorrow.Add(-1)
			return nil, err
		}
		return inst, nil
	}
}

// Put returns an instance to the pool. If faulted, discards and closes the dirty instance.
func (p *InstancePool) Put(inst *PooledInstance) {
	p.activeBorrow.Add(-1)
	if inst == nil {
		return
	}

	if p.closed.Load() || inst.Faulted {
		_ = inst.Module.Close(context.Background())
		return
	}

	select {
	case p.pool <- inst:
		if p.closed.Load() {
			// If closed concurrently, drain and close
			select {
			case drained := <-p.pool:
				_ = drained.Module.Close(context.Background())
			default:
			}
		}
	default:
		// Pool capacity exceeded, close redundant instance
		_ = inst.Module.Close(context.Background())
	}
}

// ActiveCount returns the number of instances currently borrowed and executing.
func (p *InstancePool) ActiveCount() int64 {
	return p.activeBorrow.Load()
}

// Close gracefully closes all pooled instances and the wazero runtime.
func (p *InstancePool) Close(ctx context.Context) error {
	var closeErr error
	p.closeOnce.Do(func() {
		p.closed.Store(true)
		p.cancel()

		// Drain pooled instances without closing the channel to avoid send on closed channel
	drainLoop:
		for {
			select {
			case inst := <-p.pool:
				_ = inst.Module.Close(ctx)
			default:
				break drainLoop
			}
		}

		if p.compiled != nil {
			_ = p.compiled.Close(ctx)
		}

		if p.runtime != nil {
			closeErr = p.runtime.Close(ctx)
		}
	})
	return closeErr
}
