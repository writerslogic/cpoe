package tracking

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"witnessd/internal/jitter"
)

// =============================================================================
// Helper functions
// =============================================================================

func createTestDocument(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(path, []byte("test content for tracking"), 0600); err != nil {
		t.Fatalf("failed to create test document: %v", err)
	}
	return path
}

// =============================================================================
// Tests for DefaultConfig
// =============================================================================

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig("/test/doc.txt")

	if cfg.DocumentPath != "/test/doc.txt" {
		t.Error("document path mismatch")
	}
	if !cfg.InjectJitter {
		t.Error("InjectJitter should be true by default")
	}
	if cfg.Simulated {
		t.Error("Simulated should be false by default")
	}
}

// =============================================================================
// Tests for NewSession
// =============================================================================

func TestNewSession(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir)

	cfg := DefaultConfig(docPath)
	cfg.Simulated = true // Use simulated for testing

	session, err := NewSession(cfg)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	if session == nil {
		t.Fatal("NewSession returned nil")
	}
	if session.ID == "" {
		t.Error("session ID should not be empty")
	}
	if session.DocumentPath != docPath {
		t.Error("document path mismatch")
	}
	if session.StartedAt.IsZero() {
		t.Error("started at should be set")
	}
}

func TestNewSessionNonexistentDocument(t *testing.T) {
	cfg := DefaultConfig("/nonexistent/path/doc.txt")
	cfg.Simulated = true

	// NewSession does not validate document existence - it's checked
	// when reading the document hash during RecordKeystroke.
	// This is intentional: allows creating sessions for files that
	// will be created during the writing process.
	session, err := NewSession(cfg)
	if err != nil {
		t.Fatalf("NewSession should succeed even for nonexistent path: %v", err)
	}
	if session == nil {
		t.Error("session should not be nil")
	}
}

// =============================================================================
// Tests for Session Start/Stop
// =============================================================================

func TestSessionStart(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir)

	cfg := DefaultConfig(docPath)
	cfg.Simulated = true

	session, _ := NewSession(cfg)

	err := session.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	status := session.Status()
	if !status.Running {
		t.Error("session should be running")
	}
}

func TestSessionStartAlreadyRunning(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir)

	cfg := DefaultConfig(docPath)
	cfg.Simulated = true

	session, _ := NewSession(cfg)
	session.Start()

	err := session.Start()
	if err == nil {
		t.Error("expected error when already running")
	}
}

func TestSessionStop(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir)

	cfg := DefaultConfig(docPath)
	cfg.Simulated = true

	session, _ := NewSession(cfg)
	session.Start()

	err := session.Stop()
	if err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	status := session.Status()
	if status.Running {
		t.Error("session should not be running after stop")
	}
	if status.EndedAt.IsZero() {
		t.Error("ended at should be set")
	}
}

func TestSessionStopNotRunning(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir)

	cfg := DefaultConfig(docPath)
	cfg.Simulated = true

	session, _ := NewSession(cfg)

	// Stop without starting should not error
	err := session.Stop()
	if err != nil {
		t.Errorf("Stop on non-running session should not error: %v", err)
	}
}

// =============================================================================
// Tests for Status
// =============================================================================

func TestSessionStatus(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir)

	cfg := DefaultConfig(docPath)
	cfg.Simulated = true

	session, _ := NewSession(cfg)

	status := session.Status()

	if status.ID == "" {
		t.Error("ID should not be empty")
	}
	if status.DocumentPath != docPath {
		t.Error("document path mismatch")
	}
	if status.Running {
		t.Error("should not be running before Start")
	}
}

func TestSessionStatusWhileRunning(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir)

	cfg := DefaultConfig(docPath)
	cfg.Simulated = true

	session, _ := NewSession(cfg)
	session.Start()

	// Let it run briefly
	time.Sleep(10 * time.Millisecond)

	status := session.Status()

	if !status.Running {
		t.Error("should be running")
	}
	if status.Duration <= 0 {
		t.Error("duration should be positive while running")
	}

	session.Stop()
}

// =============================================================================
// Tests for Export
// =============================================================================

func TestSessionExport(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir)

	cfg := DefaultConfig(docPath)
	cfg.Simulated = true

	session, _ := NewSession(cfg)

	evidence := session.Export()

	if evidence.SessionID == "" {
		t.Error("session ID should not be empty")
	}
	if evidence.DocumentPath != docPath {
		t.Error("document path mismatch")
	}
}

// =============================================================================
// Tests for Save
// =============================================================================

func TestSessionSave(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir)
	witnessdDir := filepath.Join(tmpDir, ".witnessd")

	cfg := DefaultConfig(docPath)
	cfg.Simulated = true

	session, _ := NewSession(cfg)

	err := session.Save(witnessdDir)
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Verify file was created
	expectedPath := filepath.Join(witnessdDir, "tracking", session.ID+".json")
	if _, err := os.Stat(expectedPath); os.IsNotExist(err) {
		t.Error("session file was not created")
	}
}

// =============================================================================
// Tests for Manager
// =============================================================================

func TestNewManager(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager(tmpDir)

	if m == nil {
		t.Fatal("NewManager returned nil")
	}
	if m.witnessdDir != tmpDir {
		t.Error("witnessd dir mismatch")
	}
}

func TestManagerGetSession(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager(tmpDir)

	// Non-existent session
	_, ok := m.GetSession("fake-id")
	if ok {
		t.Error("should not find non-existent session")
	}
}

func TestManagerActiveSessions(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager(tmpDir)

	active := m.ActiveSessions()
	if len(active) != 0 {
		t.Error("should have no active sessions initially")
	}
}

func TestManagerListSavedSessions(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager(tmpDir)

	// No tracking directory yet
	ids, err := m.ListSavedSessions()
	if err != nil {
		t.Fatalf("ListSavedSessions failed: %v", err)
	}
	if len(ids) != 0 {
		t.Error("should have no saved sessions initially")
	}

	// Create tracking directory with a file
	trackingDir := filepath.Join(tmpDir, "tracking")
	os.MkdirAll(trackingDir, 0700)
	os.WriteFile(filepath.Join(trackingDir, "test-session.json"), []byte("{}"), 0600)

	ids, err = m.ListSavedSessions()
	if err != nil {
		t.Fatalf("ListSavedSessions failed: %v", err)
	}
	if len(ids) != 1 {
		t.Errorf("expected 1 saved session, got %d", len(ids))
	}
	if ids[0] != "test-session" {
		t.Errorf("expected 'test-session', got %q", ids[0])
	}
}

// =============================================================================
// Tests for Config struct
// =============================================================================

func TestConfigFields(t *testing.T) {
	cfg := Config{
		DocumentPath: "/test/path.txt",
		JitterParams: jitter.DefaultParameters(),
		InjectJitter: true,
		Simulated:    false,
	}

	if cfg.DocumentPath == "" {
		t.Error("DocumentPath should be set")
	}
	if cfg.JitterParams.SampleInterval == 0 {
		t.Error("JitterParams should have defaults")
	}
}

// =============================================================================
// Tests for Status struct
// =============================================================================

func TestStatusStruct(t *testing.T) {
	status := Status{
		ID:               "test-id",
		Running:          true,
		StartedAt:        time.Now(),
		DocumentPath:     "/test/doc.txt",
		KeystrokeCount:   100,
		SampleCount:      10,
		KeystrokesPerMin: 60.0,
	}

	if status.ID == "" {
		t.Error("ID should be set")
	}
	if !status.Running {
		t.Error("Running should be true")
	}
}

// =============================================================================
// Tests for Load
// =============================================================================

func TestLoad(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir)
	witnessdDir := filepath.Join(tmpDir, ".witnessd")

	cfg := DefaultConfig(docPath)
	cfg.Simulated = true

	// Create and save a session
	session, _ := NewSession(cfg)
	session.Save(witnessdDir)
	sessionID := session.ID

	// Load it back
	loaded, err := Load(witnessdDir, sessionID)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if loaded.ID != sessionID {
		t.Error("ID mismatch")
	}
	if loaded.DocumentPath != docPath {
		t.Error("document path mismatch")
	}
}

func TestLoadNonexistent(t *testing.T) {
	tmpDir := t.TempDir()

	_, err := Load(tmpDir, "nonexistent-id")
	if err == nil {
		t.Error("expected error for nonexistent session")
	}
}

// =============================================================================
// Integration tests
// =============================================================================

func TestTrackingWorkflow(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir)
	witnessdDir := filepath.Join(tmpDir, ".witnessd")

	cfg := DefaultConfig(docPath)
	cfg.Simulated = true

	// Create session
	session, err := NewSession(cfg)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	// Start tracking
	if err := session.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Verify running
	status := session.Status()
	if !status.Running {
		t.Error("should be running")
	}

	// Let it run briefly
	time.Sleep(50 * time.Millisecond)

	// Stop tracking
	if err := session.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	// Verify stopped
	status = session.Status()
	if status.Running {
		t.Error("should not be running")
	}

	// Save session
	if err := session.Save(witnessdDir); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Export evidence
	evidence := session.Export()
	if evidence.SessionID == "" {
		t.Error("evidence should have session ID")
	}

	// Load saved session
	loaded, err := Load(witnessdDir, session.ID)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if loaded.ID != session.ID {
		t.Error("loaded session ID mismatch")
	}
}

func TestManagerWorkflow(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir)
	witnessdDir := filepath.Join(tmpDir, ".witnessd")

	m := NewManager(witnessdDir)

	// Can't start with real keyboard counter in tests
	// This would normally work but requires simulated mode
	// For now just test what we can
	if m == nil {
		t.Fatal("manager should not be nil")
	}

	// List should be empty
	ids, _ := m.ListSavedSessions()
	if len(ids) != 0 {
		t.Error("should have no sessions initially")
	}

	// Active sessions should be empty
	active := m.ActiveSessions()
	if len(active) != 0 {
		t.Error("should have no active sessions")
	}

	// Create and save a session manually to test loading
	cfg := DefaultConfig(docPath)
	cfg.Simulated = true
	session, _ := NewSession(cfg)
	session.Save(witnessdDir)

	// Now list should find it
	ids, _ = m.ListSavedSessions()
	if len(ids) != 1 {
		t.Errorf("expected 1 session, got %d", len(ids))
	}
}

// =============================================================================
// Tests for Manager.StopAll
// =============================================================================

func TestManagerStopAll(t *testing.T) {
	tmpDir := t.TempDir()
	witnessdDir := filepath.Join(tmpDir, ".witnessd")

	m := NewManager(witnessdDir)

	// No active sessions - StopAll should not error
	err := m.StopAll()
	if err != nil {
		t.Errorf("StopAll with no sessions should not error: %v", err)
	}
}

// =============================================================================
// Tests for Manager.LoadEvidence
// =============================================================================

func TestManagerLoadEvidence(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir)
	witnessdDir := filepath.Join(tmpDir, ".witnessd")

	m := NewManager(witnessdDir)

	// Create and save a session
	cfg := DefaultConfig(docPath)
	cfg.Simulated = true
	session, _ := NewSession(cfg)
	session.Start()
	time.Sleep(10 * time.Millisecond)
	session.Stop()
	session.Save(witnessdDir)

	// Load evidence
	evidence, err := m.LoadEvidence(session.ID)
	if err != nil {
		t.Fatalf("LoadEvidence failed: %v", err)
	}
	if evidence == nil {
		t.Error("expected evidence, got nil")
	}
	if evidence != nil && evidence.SessionID != session.ID {
		t.Errorf("session ID mismatch: expected %s, got %s", session.ID, evidence.SessionID)
	}
}

func TestManagerLoadEvidenceNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	witnessdDir := filepath.Join(tmpDir, ".witnessd")

	m := NewManager(witnessdDir)

	_, err := m.LoadEvidence("nonexistent-session")
	if err == nil {
		t.Error("expected error for nonexistent session")
	}
}

// =============================================================================
// Tests for Session keystroke handling
// =============================================================================

func TestSessionKeystrokeHandling(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir)

	cfg := DefaultConfig(docPath)
	cfg.Simulated = true

	session, err := NewSession(cfg)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	err = session.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Get the simulated counter and generate keystrokes
	// The session uses a simulated counter in test mode
	// We'll just let it run briefly to exercise the event loop
	time.Sleep(50 * time.Millisecond)

	// Check status while running
	status := session.Status()
	if !status.Running {
		t.Error("session should be running")
	}

	err = session.Stop()
	if err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	// Check final status
	status = session.Status()
	if status.Running {
		t.Error("session should not be running after stop")
	}
}

// =============================================================================
// Tests for session with document updates
// =============================================================================

func TestSessionWithDocumentUpdates(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir)

	cfg := DefaultConfig(docPath)
	cfg.Simulated = true

	session, _ := NewSession(cfg)
	session.Start()

	// Simulate document changes by updating the file
	for i := 0; i < 3; i++ {
		content := fmt.Sprintf("test content version %d", i)
		os.WriteFile(docPath, []byte(content), 0600)
		time.Sleep(10 * time.Millisecond)
	}

	session.Stop()

	// Export and check evidence
	evidence := session.Export()
	if evidence.SessionID == "" {
		t.Error("evidence should have session ID")
	}
	if evidence.DocumentPath != docPath {
		t.Errorf("document path mismatch: expected %s, got %s", docPath, evidence.DocumentPath)
	}
}

// =============================================================================
// Tests for Session.Export with data
// =============================================================================

func TestSessionExportWithData(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir)
	witnessdDir := filepath.Join(tmpDir, ".witnessd")

	cfg := DefaultConfig(docPath)
	cfg.Simulated = true

	session, _ := NewSession(cfg)
	session.Start()
	time.Sleep(20 * time.Millisecond)
	session.Stop()

	// Export evidence
	evidence := session.Export()

	// Verify evidence structure
	if evidence.SessionID == "" {
		t.Error("expected session ID in evidence")
	}
	if evidence.StartedAt.IsZero() {
		t.Error("expected non-zero started at")
	}
	if evidence.EndedAt.IsZero() {
		t.Error("expected non-zero ended at")
	}
	if evidence.DocumentPath != docPath {
		t.Errorf("document path mismatch")
	}

	// Save and reload
	session.Save(witnessdDir)

	loaded, err := Load(witnessdDir, session.ID)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	loadedEvidence := loaded.Export()
	if loadedEvidence.SessionID != evidence.SessionID {
		t.Error("session ID mismatch after reload")
	}
}

// =============================================================================
// Additional Manager tests
// =============================================================================

func TestManagerGetSessionNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager(tmpDir)

	sess, ok := m.GetSession("nonexistent")
	if ok {
		t.Error("should not find nonexistent session")
	}
	if sess != nil {
		t.Error("session should be nil")
	}
}

func TestManagerActiveSessionsEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager(tmpDir)

	active := m.ActiveSessions()
	if active == nil {
		// nil is acceptable
	} else if len(active) != 0 {
		t.Errorf("expected empty active sessions, got %d", len(active))
	}
}

// =============================================================================
// Tests for Session ID Consistency (Fix #1)
// =============================================================================

// TestSessionIDConsistency verifies that the tracking session and its
// internal jitter session share the same ID. This is critical for
// evidence correlation.
func TestSessionIDConsistency(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir)

	cfg := DefaultConfig(docPath)
	cfg.Simulated = true

	session, err := NewSession(cfg)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	// Get the tracking session ID
	trackingID := session.ID

	// Export jitter evidence and verify it has the same ID
	jitterEvidence := session.Export()

	if jitterEvidence.SessionID != trackingID {
		t.Errorf("session ID mismatch: tracking=%s, jitter=%s",
			trackingID, jitterEvidence.SessionID)
	}
}

// TestSessionIDConsistencyAfterSaveLoad verifies that session IDs remain
// consistent after saving and loading from disk.
func TestSessionIDConsistencyAfterSaveLoad(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir)
	witnessdDir := filepath.Join(tmpDir, ".witnessd")

	cfg := DefaultConfig(docPath)
	cfg.Simulated = true

	// Create, start, stop, and save a session
	session, _ := NewSession(cfg)
	session.Start()
	time.Sleep(10 * time.Millisecond)
	session.Stop()
	session.Save(witnessdDir)

	originalID := session.ID

	// Load the session back
	loaded, err := Load(witnessdDir, originalID)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Verify the loaded session has the same ID
	if loaded.ID != originalID {
		t.Errorf("loaded session ID mismatch: expected=%s, got=%s",
			originalID, loaded.ID)
	}

	// Verify exported evidence has the same ID
	loadedEvidence := loaded.Export()
	if loadedEvidence.SessionID != originalID {
		t.Errorf("loaded evidence session ID mismatch: expected=%s, got=%s",
			originalID, loadedEvidence.SessionID)
	}
}

// TestManagerLoadEvidenceSessionIDMatch verifies that LoadEvidence returns
// evidence with the correct session ID matching the file name.
func TestManagerLoadEvidenceSessionIDMatch(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir)
	witnessdDir := filepath.Join(tmpDir, ".witnessd")

	m := NewManager(witnessdDir)

	// Create and save a session
	cfg := DefaultConfig(docPath)
	cfg.Simulated = true
	session, _ := NewSession(cfg)
	session.Start()
	time.Sleep(10 * time.Millisecond)
	session.Stop()
	session.Save(witnessdDir)

	expectedID := session.ID

	// Load evidence via manager
	evidence, err := m.LoadEvidence(expectedID)
	if err != nil {
		t.Fatalf("LoadEvidence failed: %v", err)
	}

	// Verify the evidence session ID matches what we requested
	if evidence.SessionID != expectedID {
		t.Errorf("evidence session ID mismatch: expected=%s, got=%s",
			expectedID, evidence.SessionID)
	}
}
