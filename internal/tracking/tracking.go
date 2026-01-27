// Package tracking manages keyboard tracking sessions.
//
// This package ties together:
// - Keystroke counting (no capture)
// - Jitter computation and injection
// - Document hash sampling
// - Session persistence
//
// A tracking session runs in the background while the user writes,
// building evidence of real typing activity without capturing content.
package tracking

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"witnessd/internal/jitter"
	"witnessd/internal/keystroke"
)

// Session manages a keyboard tracking session.
type Session struct {
	mu sync.RWMutex

	// Session identity
	ID        string    `json:"id"`
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at,omitempty"`

	// Document being tracked
	DocumentPath string `json:"document_path"`

	// Components
	jitterSession *jitter.Session
	counter       keystroke.Counter

	// Control
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}

	// Status
	running bool
	error   error

	// Configuration
	injectJitter bool
}

// Config configures a tracking session.
type Config struct {
	// Document to track
	DocumentPath string

	// Jitter parameters
	JitterParams jitter.Parameters

	// Whether to inject jitter delays
	InjectJitter bool

	// Use simulated keystroke counter (for testing)
	Simulated bool
}

// DefaultConfig returns sensible defaults.
func DefaultConfig(documentPath string) Config {
	return Config{
		DocumentPath: documentPath,
		JitterParams: jitter.DefaultParameters(),
		InjectJitter: true,
		Simulated:    false,
	}
}

// NewSession creates a new tracking session.
func NewSession(cfg Config) (*Session, error) {
	// Create jitter session
	jitterSess, err := jitter.NewSession(cfg.DocumentPath, cfg.JitterParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create jitter session: %w", err)
	}

	// Create keystroke counter
	var counter keystroke.Counter
	if cfg.Simulated {
		counter = keystroke.NewSimulated()
	} else {
		counter = keystroke.New()
	}

	return &Session{
		ID:            jitterSess.ID,
		StartedAt:     time.Now(),
		DocumentPath:  cfg.DocumentPath,
		jitterSession: jitterSess,
		counter:       counter,
		injectJitter:  cfg.InjectJitter,
	}, nil
}

// Start begins the tracking session.
func (s *Session) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("session already running")
	}

	// Check if keyboard counting is available
	available, msg := s.counter.Available()
	if !available {
		return fmt.Errorf("keyboard tracking not available: %s", msg)
	}

	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.done = make(chan struct{})

	// Start keystroke counter
	if err := s.counter.Start(s.ctx); err != nil {
		return fmt.Errorf("failed to start keystroke counter: %w", err)
	}

	// Subscribe to keystroke events
	interval := s.jitterSession.Params.SampleInterval
	events := s.counter.Subscribe(interval)

	// Start event loop
	go s.eventLoop(events)

	s.running = true
	return nil
}

// eventLoop processes keystroke events.
func (s *Session) eventLoop(events <-chan keystroke.Event) {
	defer close(s.done)

	for {
		select {
		case <-s.ctx.Done():
			return
		case event, ok := <-events:
			if !ok {
				return
			}
			s.handleKeystrokeEvent(event)
		}
	}
}

// handleKeystrokeEvent processes a keystroke event.
func (s *Session) handleKeystrokeEvent(event keystroke.Event) {
	// Record in jitter session and get jitter to inject
	jitterMicros, sampled := s.jitterSession.RecordKeystroke()

	if sampled && s.injectJitter && jitterMicros > 0 {
		// Inject the jitter delay
		time.Sleep(time.Duration(jitterMicros) * time.Microsecond)
	}
}

// Stop ends the tracking session.
func (s *Session) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	// Signal shutdown
	if s.cancel != nil {
		s.cancel()
	}

	// Stop keystroke counter
	if err := s.counter.Stop(); err != nil {
		s.error = err
	}

	// Wait for event loop
	if s.done != nil {
		<-s.done
	}

	s.jitterSession.End()
	s.EndedAt = time.Now()
	s.running = false

	return s.error
}

// Status returns the current session status.
type Status struct {
	ID               string        `json:"id"`
	Running          bool          `json:"running"`
	StartedAt        time.Time     `json:"started_at"`
	EndedAt          time.Time     `json:"ended_at,omitempty"`
	Duration         time.Duration `json:"duration"`
	DocumentPath     string        `json:"document_path"`
	KeystrokeCount   uint64        `json:"keystroke_count"`
	SampleCount      int           `json:"sample_count"`
	KeystrokesPerMin float64       `json:"keystrokes_per_minute"`
	Error            string        `json:"error,omitempty"`
}

// Status returns the current session status.
func (s *Session) Status() Status {
	s.mu.RLock()
	defer s.mu.RUnlock()

	status := Status{
		ID:             s.ID,
		Running:        s.running,
		StartedAt:      s.StartedAt,
		EndedAt:        s.EndedAt,
		DocumentPath:   s.DocumentPath,
		KeystrokeCount: s.jitterSession.KeystrokeCount(),
		SampleCount:    s.jitterSession.SampleCount(),
	}

	// Compute duration
	end := s.EndedAt
	if end.IsZero() {
		end = time.Now()
	}
	status.Duration = end.Sub(s.StartedAt)

	// Compute rate
	if status.Duration > 0 {
		minutes := status.Duration.Minutes()
		if minutes > 0 {
			status.KeystrokesPerMin = float64(status.KeystrokeCount) / minutes
		}
	}

	if s.error != nil {
		status.Error = s.error.Error()
	}

	return status
}

// Export returns jitter evidence from this session.
func (s *Session) Export() jitter.Evidence {
	return s.jitterSession.Export()
}

// Save persists the session to disk.
func (s *Session) Save(witnessdDir string) error {
	path := filepath.Join(witnessdDir, "tracking", s.ID+".json")
	return s.jitterSession.Save(path)
}

// Load reads a session from disk.
func Load(witnessdDir, sessionID string) (*Session, error) {
	path := filepath.Join(witnessdDir, "tracking", sessionID+".json")
	jitterSess, err := jitter.LoadSession(path)
	if err != nil {
		return nil, err
	}

	return &Session{
		ID:            jitterSess.ID,
		StartedAt:     jitterSess.StartedAt,
		EndedAt:       jitterSess.EndedAt,
		DocumentPath:  jitterSess.DocumentPath,
		jitterSession: jitterSess,
	}, nil
}

// Manager manages multiple tracking sessions.
type Manager struct {
	mu          sync.RWMutex
	sessions    map[string]*Session
	witnessdDir string
}

// NewManager creates a session manager.
func NewManager(witnessdDir string) *Manager {
	return &Manager{
		sessions:    make(map[string]*Session),
		witnessdDir: witnessdDir,
	}
}

// StartSession starts tracking a document.
func (m *Manager) StartSession(documentPath string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if already tracking this document
	absPath, err := filepath.Abs(documentPath)
	if err != nil {
		return nil, err
	}

	for _, sess := range m.sessions {
		if sess.DocumentPath == absPath && sess.running {
			return nil, fmt.Errorf("already tracking %s", documentPath)
		}
	}

	cfg := DefaultConfig(absPath)
	sess, err := NewSession(cfg)
	if err != nil {
		return nil, err
	}

	if err := sess.Start(); err != nil {
		return nil, err
	}

	m.sessions[sess.ID] = sess
	return sess, nil
}

// StopSession stops a tracking session.
func (m *Manager) StopSession(sessionID string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	sess, ok := m.sessions[sessionID]
	if !ok {
		return nil, fmt.Errorf("session not found: %s", sessionID)
	}

	if err := sess.Stop(); err != nil {
		return sess, err
	}

	// Save session
	if err := sess.Save(m.witnessdDir); err != nil {
		return sess, fmt.Errorf("failed to save session: %w", err)
	}

	return sess, nil
}

// GetSession returns a session by ID.
func (m *Manager) GetSession(sessionID string) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	sess, ok := m.sessions[sessionID]
	return sess, ok
}

// ActiveSessions returns all active sessions.
func (m *Manager) ActiveSessions() []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var active []*Session
	for _, sess := range m.sessions {
		if sess.running {
			active = append(active, sess)
		}
	}
	return active
}

// StopAll stops all active sessions.
func (m *Manager) StopAll() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var lastErr error
	for _, sess := range m.sessions {
		if sess.running {
			if err := sess.Stop(); err != nil {
				lastErr = err
			}
			if err := sess.Save(m.witnessdDir); err != nil {
				lastErr = err
			}
		}
	}
	return lastErr
}

// ListSavedSessions lists sessions saved to disk.
func (m *Manager) ListSavedSessions() ([]string, error) {
	dir := filepath.Join(m.witnessdDir, "tracking")
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil, nil
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var ids []string
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
			id := entry.Name()[:len(entry.Name())-5] // Remove .json
			ids = append(ids, id)
		}
	}
	return ids, nil
}

// LoadEvidence loads jitter evidence from a saved session.
func (m *Manager) LoadEvidence(sessionID string) (*jitter.Evidence, error) {
	path := filepath.Join(m.witnessdDir, "tracking", sessionID+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Load the session data
	sess, err := jitter.LoadSession(path)
	if err != nil {
		// Try loading as evidence directly
		var ev jitter.Evidence
		if err := json.Unmarshal(data, &ev); err != nil {
			return nil, err
		}
		return &ev, nil
	}

	ev := sess.Export()
	return &ev, nil
}
