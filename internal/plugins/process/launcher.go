package process

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ProcessLauncher manages the child process OS lifecycle, sandboxing, supervision, and restart backoff.
type ProcessLauncher struct {
	manifest        *ProcessManifest
	logger          *slog.Logger
	socketPath      string
	cmd             *exec.Cmd
	inFlightCalls   atomic.Int64
	restarts        atomic.Int32
	closed          atomic.Bool
	readyChan       chan struct{}
	restartCallback func()

	mu        sync.Mutex
	closeOnce sync.Once
	stopChan  chan struct{}
	wg        sync.WaitGroup
}

// NewProcessLauncher initializes a new process launcher for a local child binary.
func NewProcessLauncher(manifest *ProcessManifest, restartCb func(), logger *slog.Logger) *ProcessLauncher {
	return &ProcessLauncher{
		manifest:        manifest,
		logger:          logger,
		readyChan:       make(chan struct{}),
		restartCallback: restartCb,
		stopChan:        make(chan struct{}),
	}
}

// SocketPath returns the Unix domain socket path allocated for this child process.
func (l *ProcessLauncher) SocketPath() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.socketPath
}

// Start spawns the sandboxed child process and monitors its execution.
func (l *ProcessLauncher) Start() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.startLocked()
}

func (l *ProcessLauncher) startLocked() error {
	// Verify binary security (checksum, allowlisting)
	if err := VerifyBinary(l.manifest.BinaryPath, l.manifest.SHA256Checksum, l.manifest.AllowedBinaryDirs); err != nil {
		return err
	}

	socketDir := l.manifest.SocketDir
	if socketDir == "" {
		socketDir = os.TempDir()
	}
	if err := os.MkdirAll(socketDir, 0700); err != nil {
		return fmt.Errorf("failed to create socket directory: %w", err)
	}

	if l.socketPath == "" {
		socketName := fmt.Sprintf("torana-%s-%d.sock", l.manifest.Name, time.Now().UnixNano())
		l.socketPath = filepath.Join(socketDir, socketName)
	}
	_ = os.Remove(l.socketPath)

	cmd := exec.Command(l.manifest.BinaryPath, l.manifest.Args...)

	// 1. Environment Scrubbing: pass only minimal safe variables
	scrubbedEnv := []string{
		"PATH=/usr/bin:/bin:/usr/local/bin",
		"HOME=/tmp",
		"TMPDIR=/tmp",
		fmt.Sprintf("TORANA_PLUGIN_SOCKET=%s", l.socketPath),
		fmt.Sprintf("TORANA_PLUGIN_NAME=%s", l.manifest.Name),
		fmt.Sprintf("TORANA_PLUGIN_VERSION=%s", l.manifest.Version),
	}
	for k, v := range l.manifest.Env {
		scrubbedEnv = append(scrubbedEnv, fmt.Sprintf("%s=%s", k, v))
	}
	cmd.Env = scrubbedEnv

	// 2. SysProcAttr Sandboxing (Dedicated UID/GID & Process Group)
	sysAttr := &syscall.SysProcAttr{
		Setpgid: true, // isolate in process group
	}
	if (l.manifest.RunAsUID != nil || l.manifest.RunAsGID != nil) && os.Geteuid() == 0 {
		cred := &syscall.Credential{}
		if l.manifest.RunAsUID != nil {
			cred.Uid = *l.manifest.RunAsUID
		}
		if l.manifest.RunAsGID != nil {
			cred.Gid = *l.manifest.RunAsGID
		}
		sysAttr.Credential = cred
	} else if l.manifest.RunAsUID != nil && l.logger != nil {
		l.logger.Debug("running unprivileged; skipping child UID switch", "requested_uid", *l.manifest.RunAsUID)
	}
	cmd.SysProcAttr = sysAttr

	// 3. Capture Child stdout and stderr to structured logger
	stdoutPipe, err := cmd.StdoutPipe()
	if err == nil {
		go l.streamLogs(stdoutPipe, "stdout")
	}
	stderrPipe, err := cmd.StderrPipe()
	if err == nil {
		go l.streamLogs(stderrPipe, "stderr")
	}

	// 4. Start Child Process
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start child plugin %s: %w", l.manifest.Name, err)
	}
	l.cmd = cmd

	if l.logger != nil {
		l.logger.Info("started child plugin process",
			"plugin", l.manifest.Name,
			"pid", cmd.Process.Pid,
			"socket", l.socketPath,
		)
	}

	// 5. Wait for Unix Domain Socket Readiness
	readyTimeout := l.manifest.Timeout
	if readyTimeout <= 0 {
		readyTimeout = 5 * time.Second
	}
	if err := l.waitForSocket(l.socketPath, readyTimeout); err != nil {
		_ = cmd.Process.Kill()
		_ = os.Remove(l.socketPath)
		return fmt.Errorf("plugin %s failed socket readiness probe: %w", l.manifest.Name, err)
	}

	// 6. Spawn Supervisor Watcher
	l.wg.Add(1)
	go l.supervise(cmd)

	return nil
}

func (l *ProcessLauncher) streamLogs(r io.Reader, stream string) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		text := scanner.Text()
		if l.logger != nil {
			l.logger.Info(text, "plugin", l.manifest.Name, "stream", stream)
		}
	}
}

func (l *ProcessLauncher) waitForSocket(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("unix", path, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for unix socket %s", path)
}

func (l *ProcessLauncher) supervise(cmd *exec.Cmd) {
	defer l.wg.Done()

	err := cmd.Wait()

	if l.closed.Load() {
		return
	}

	if l.logger != nil {
		l.logger.Warn("child plugin process exited unexpectedly",
			"plugin", l.manifest.Name,
			"pid", cmd.Process.Pid,
			"error", err,
		)
	}

	// Exponential backoff restart loop
	maxRestarts := l.manifest.MaxRestartAttempts
	if maxRestarts <= 0 {
		maxRestarts = 5
	}

	currentRestarts := l.restarts.Add(1)
	if int(currentRestarts) > maxRestarts {
		if l.logger != nil {
			l.logger.Error("max restart attempts exceeded for plugin", "plugin", l.manifest.Name)
		}
		return
	}

	backoff := l.manifest.RestartBackoff
	if backoff <= 0 {
		backoff = 100 * time.Millisecond
	}
	backoff = backoff * time.Duration(1<<min(currentRestarts-1, 6))

	select {
	case <-l.stopChan:
		return
	case <-time.After(backoff):
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed.Load() {
		return
	}

	if err := l.startLocked(); err != nil {
		if l.logger != nil {
			l.logger.Error("failed to restart child plugin", "plugin", l.manifest.Name, "error", err)
		}
	} else if l.restartCallback != nil {
		l.restartCallback()
	}
}

// InFlightAdd records an active in-flight RPC call.
func (l *ProcessLauncher) InFlightAdd(delta int64) {
	l.inFlightCalls.Add(delta)
}

// Close gracefully drains active calls, issues SIGTERM/SIGKILL, and unlinks socket.
func (l *ProcessLauncher) Close() error {
	l.closeOnce.Do(func() {
		l.closed.Store(true)
		close(l.stopChan)

		// 1. Drain active in-flight calls (up to 5s)
		drainDeadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(drainDeadline) {
			if l.inFlightCalls.Load() <= 0 {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}

		// 2. Terminate child process
		l.mu.Lock()
		cmd := l.cmd
		sock := l.socketPath
		l.mu.Unlock()

		if cmd != nil && cmd.Process != nil {
			// Issue SIGTERM
			_ = cmd.Process.Signal(syscall.SIGTERM)

			// Wait up to 2 seconds for graceful exit, then force kill
			done := make(chan struct{})
			go func() {
				l.wg.Wait()
				close(done)
			}()

			select {
			case <-done:
			case <-time.After(2 * time.Second):
				_ = cmd.Process.Kill()
			}
		}

		if sock != "" {
			_ = os.Remove(sock)
		}
	})
	return nil
}
