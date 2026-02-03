// Package hardware provides process management for isolated entropy.
package hardware

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// Errors for entropy process management
var (
	ErrDaemonStartFailed  = errors.New("entropy daemon failed to start")
	ErrDaemonDied         = errors.New("entropy daemon died unexpectedly")
	ErrConnectionFailed   = errors.New("failed to connect to entropy daemon")
	ErrHealthCheckFailed  = errors.New("entropy source health check failed")
)

// EntropyProcessManager manages the isolated entropy daemon process.
type EntropyProcessManager struct {
	mu sync.RWMutex

	// Configuration
	socketPath     string
	daemonPath     string
	dropUID        int
	dropGID        int
	restartOnDeath bool

	// Process state
	cmd        *exec.Cmd
	client     *EntropyClient
	running    atomic.Bool
	startTime  time.Time

	// Health tracking
	healthFailures   uint32
	lastHealthCheck  time.Time
	healthCheckMu    sync.Mutex

	// Shutdown
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
}

// EntropyProcessConfig configures the entropy process manager.
type EntropyProcessConfig struct {
	// SocketPath is the Unix socket for IPC
	SocketPath string
	// DaemonPath is the path to the entropy daemon binary
	DaemonPath string
	// DropUID is the UID to drop privileges to (0 = don't drop)
	DropUID int
	// DropGID is the GID to drop privileges to (0 = don't drop)
	DropGID int
	// RestartOnDeath automatically restarts the daemon if it dies
	RestartOnDeath bool
	// HealthCheckInterval is how often to check daemon health
	HealthCheckInterval time.Duration
	// MaxHealthFailures is how many health failures before restart
	MaxHealthFailures uint32
}

// DefaultEntropyProcessConfig returns sensible defaults.
func DefaultEntropyProcessConfig() EntropyProcessConfig {
	socketPath := filepath.Join(os.TempDir(), "witnessd-entropy.sock")
	if runtimeDir := os.Getenv("XDG_RUNTIME_DIR"); runtimeDir != "" {
		socketPath = filepath.Join(runtimeDir, "witnessd", "entropy.sock")
	}

	return EntropyProcessConfig{
		SocketPath:          socketPath,
		DaemonPath:          findDaemonPath(),
		DropUID:             os.Getuid(),
		DropGID:             os.Getgid(),
		RestartOnDeath:      true,
		HealthCheckInterval: 5 * time.Second,
		MaxHealthFailures:   3,
	}
}

// findDaemonPath attempts to locate the entropy daemon binary.
func findDaemonPath() string {
	// Check common locations
	candidates := []string{
		"./witnessd-entropy",
		"/usr/local/bin/witnessd-entropy",
		"/usr/bin/witnessd-entropy",
	}

	// Also check relative to the main binary
	if exePath, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exePath)
		candidates = append([]string{
			filepath.Join(exeDir, "witnessd-entropy"),
		}, candidates...)
	}

	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return "witnessd-entropy" // Fall back to PATH lookup
}

// NewEntropyProcessManager creates a new entropy process manager.
func NewEntropyProcessManager(config EntropyProcessConfig) *EntropyProcessManager {
	ctx, cancel := context.WithCancel(context.Background())

	return &EntropyProcessManager{
		socketPath:     config.SocketPath,
		daemonPath:     config.DaemonPath,
		dropUID:        config.DropUID,
		dropGID:        config.DropGID,
		restartOnDeath: config.RestartOnDeath,
		ctx:            ctx,
		cancel:         cancel,
		done:           make(chan struct{}),
	}
}

// Start launches the isolated entropy daemon as a subprocess.
func (m *EntropyProcessManager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running.Load() {
		return nil // Already running
	}

	// Ensure socket directory exists
	socketDir := filepath.Dir(m.socketPath)
	if err := os.MkdirAll(socketDir, 0700); err != nil {
		return fmt.Errorf("failed to create socket directory: %w", err)
	}

	// Remove old socket if present
	os.Remove(m.socketPath)

	// Build command
	args := []string{
		"-socket", m.socketPath,
		"-foreground",
	}

	if m.dropUID > 0 {
		args = append(args, "-uid", fmt.Sprintf("%d", m.dropUID))
	}
	if m.dropGID > 0 {
		args = append(args, "-gid", fmt.Sprintf("%d", m.dropGID))
	}

	m.cmd = exec.CommandContext(m.ctx, m.daemonPath, args...)

	// Isolate the process
	m.cmd.Stdin = nil
	m.cmd.Stdout = nil
	m.cmd.Stderr = nil

	// Start the daemon
	if err := m.cmd.Start(); err != nil {
		return fmt.Errorf("%w: %v", ErrDaemonStartFailed, err)
	}

	m.startTime = time.Now()
	m.running.Store(true)

	// Wait for socket to be available
	for i := 0; i < 50; i++ { // 5 seconds max
		time.Sleep(100 * time.Millisecond)
		if _, err := os.Stat(m.socketPath); err == nil {
			break
		}
	}

	// Connect to the daemon
	client, err := NewEntropyClient(m.socketPath)
	if err != nil {
		m.cmd.Process.Kill()
		m.running.Store(false)
		return fmt.Errorf("%w: %v", ErrConnectionFailed, err)
	}
	m.client = client

	// Start process monitor
	go m.monitorProcess()

	return nil
}

// monitorProcess watches the daemon process and restarts if needed.
func (m *EntropyProcessManager) monitorProcess() {
	defer close(m.done)

	for {
		select {
		case <-m.ctx.Done():
			return
		default:
		}

		// Wait for process to exit
		err := m.cmd.Wait()

		m.mu.Lock()
		m.running.Store(false)
		wasRunning := m.client != nil
		m.mu.Unlock()

		if !wasRunning {
			return
		}

		// Process died
		if m.restartOnDeath && m.ctx.Err() == nil {
			// Attempt restart after brief delay
			time.Sleep(500 * time.Millisecond)

			m.mu.Lock()
			// Reconnect client will fail, clear it
			if m.client != nil {
				m.client.Close()
				m.client = nil
			}
			m.mu.Unlock()

			if err := m.Start(); err != nil {
				// Log and continue monitoring
				continue
			}
		} else {
			// Not restarting
			if err != nil {
				// Abnormal exit
			}
			return
		}
	}
}

// Stop shuts down the entropy daemon.
func (m *EntropyProcessManager) Stop() error {
	m.cancel()

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.client != nil {
		m.client.Close()
		m.client = nil
	}

	if m.cmd != nil && m.cmd.Process != nil {
		// Send SIGTERM first
		m.cmd.Process.Signal(os.Interrupt)

		// Wait briefly for graceful shutdown
		select {
		case <-m.done:
		case <-time.After(2 * time.Second):
			// Force kill
			m.cmd.Process.Kill()
		}
	}

	m.running.Store(false)
	return nil
}

// Read implements io.Reader interface for entropy.
func (m *EntropyProcessManager) Read(p []byte) (int, error) {
	m.mu.RLock()
	client := m.client
	m.mu.RUnlock()

	if client == nil {
		return 0, ErrDaemonNotRunning
	}

	return client.Read(p)
}

// RequestEntropy requests entropy bytes from the daemon.
func (m *EntropyProcessManager) RequestEntropy(numBytes uint32) ([]byte, error) {
	m.mu.RLock()
	client := m.client
	m.mu.RUnlock()

	if client == nil {
		return nil, ErrDaemonNotRunning
	}

	return client.RequestEntropy(numBytes)
}

// IsHealthy returns whether the entropy daemon is running and healthy.
func (m *EntropyProcessManager) IsHealthy() bool {
	m.mu.RLock()
	running := m.running.Load()
	client := m.client
	m.mu.RUnlock()

	if !running || client == nil {
		return false
	}

	// Try to get a small amount of entropy as health check
	_, err := client.RequestEntropy(1)
	return err == nil
}

// Stats returns statistics about the entropy daemon.
func (m *EntropyProcessManager) Stats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := map[string]interface{}{
		"running":        m.running.Load(),
		"socket_path":    m.socketPath,
		"daemon_path":    m.daemonPath,
		"health_failures": atomic.LoadUint32(&m.healthFailures),
	}

	if m.running.Load() {
		stats["uptime_seconds"] = time.Since(m.startTime).Seconds()
	}

	if m.cmd != nil && m.cmd.Process != nil {
		stats["pid"] = m.cmd.Process.Pid
	}

	return stats
}

// IsolatedEntropySource provides entropy from the isolated daemon with fallback.
type IsolatedEntropySource struct {
	manager    *EntropyProcessManager
	fallback   io.Reader
	useFallback atomic.Bool
}

// NewIsolatedEntropySource creates an entropy source with automatic fallback.
func NewIsolatedEntropySource(config EntropyProcessConfig) (*IsolatedEntropySource, error) {
	manager := NewEntropyProcessManager(config)

	source := &IsolatedEntropySource{
		manager:  manager,
		fallback: rand.Reader,
	}

	// Try to start the daemon
	if err := manager.Start(); err != nil {
		// Fall back to OS entropy but log warning
		source.useFallback.Store(true)
		return source, nil
	}

	return source, nil
}

// Read implements io.Reader with automatic fallback.
func (s *IsolatedEntropySource) Read(p []byte) (int, error) {
	if s.useFallback.Load() {
		return s.fallback.Read(p)
	}

	n, err := s.manager.Read(p)
	if err != nil {
		// Switch to fallback
		s.useFallback.Store(true)
		return s.fallback.Read(p)
	}

	return n, nil
}

// IsIsolated returns true if using the isolated daemon (not fallback).
func (s *IsolatedEntropySource) IsIsolated() bool {
	return !s.useFallback.Load()
}

// Stop shuts down the entropy source.
func (s *IsolatedEntropySource) Stop() error {
	return s.manager.Stop()
}
