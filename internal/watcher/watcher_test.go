package watcher

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHashFile(t *testing.T) {
	// Create temp file
	tmpDir, err := os.MkdirTemp("", "watcher_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	testFile := filepath.Join(tmpDir, "test.txt")
	content := []byte("test content for hashing")

	if err := os.WriteFile(testFile, content, 0600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	hash1, size1, err := HashFile(testFile)
	if err != nil {
		t.Fatalf("HashFile failed: %v", err)
	}

	if size1 != int64(len(content)) {
		t.Errorf("expected size %d, got %d", len(content), size1)
	}

	// Hash same content again should produce same hash
	hash2, _, err := HashFile(testFile)
	if err != nil {
		t.Fatalf("second HashFile failed: %v", err)
	}

	if hash1 != hash2 {
		t.Error("same file should produce same hash")
	}

	// Modify file
	if err := os.WriteFile(testFile, []byte("different content"), 0600); err != nil {
		t.Fatalf("failed to modify test file: %v", err)
	}

	hash3, _, err := HashFile(testFile)
	if err != nil {
		t.Fatalf("third HashFile failed: %v", err)
	}

	if hash1 == hash3 {
		t.Error("different content should produce different hash")
	}
}

func TestHashFileNotFound(t *testing.T) {
	_, _, err := HashFile("/nonexistent/file.txt")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestWatcherCreation(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "watcher_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	w, err := New([]string{tmpDir}, 1)
	if err != nil {
		t.Fatalf("failed to create watcher: %v", err)
	}

	if len(w.WatchedPaths()) != 1 {
		t.Errorf("expected 1 watched path, got %d", len(w.WatchedPaths()))
	}

	if w.TrackedFiles() != 0 {
		t.Errorf("expected 0 tracked files before start, got %d", w.TrackedFiles())
	}
}

func TestWatcherStartStop(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "watcher_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create initial file
	testFile := filepath.Join(tmpDir, "initial.txt")
	if err := os.WriteFile(testFile, []byte("initial"), 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	w, err := New([]string{tmpDir}, 1)
	if err != nil {
		t.Fatalf("failed to create watcher: %v", err)
	}

	if err := w.Start(); err != nil {
		t.Fatalf("failed to start watcher: %v", err)
	}

	// Should have tracked the existing file
	time.Sleep(100 * time.Millisecond)

	if w.TrackedFiles() != 1 {
		t.Errorf("expected 1 tracked file, got %d", w.TrackedFiles())
	}

	if err := w.Stop(); err != nil {
		t.Fatalf("failed to stop watcher: %v", err)
	}
}

func TestWatcherEvents(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "watcher_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Use 1 second debounce
	w, err := New([]string{tmpDir}, 1)
	if err != nil {
		t.Fatalf("failed to create watcher: %v", err)
	}

	if err := w.Start(); err != nil {
		t.Fatalf("failed to start watcher: %v", err)
	}
	defer w.Stop()

	// Create a file
	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test content"), 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Wait for debounce + processing
	select {
	case event := <-w.Events():
		if event.Path != testFile {
			t.Errorf("expected path %s, got %s", testFile, event.Path)
		}
		if event.Size != 12 { // "test content" = 12 bytes
			t.Errorf("expected size 12, got %d", event.Size)
		}
	case <-time.After(3 * time.Second):
		t.Error("timeout waiting for event")
	}
}

func TestWatcherDebounce(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "watcher_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Use 2 second debounce
	w, err := New([]string{tmpDir}, 2)
	if err != nil {
		t.Fatalf("failed to create watcher: %v", err)
	}

	if err := w.Start(); err != nil {
		t.Fatalf("failed to start watcher: %v", err)
	}
	defer w.Stop()

	testFile := filepath.Join(tmpDir, "debounce.txt")

	// Write multiple times quickly
	for i := 0; i < 5; i++ {
		if err := os.WriteFile(testFile, []byte("v"+string(rune('0'+i))), 0600); err != nil {
			t.Fatalf("failed to write: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}

	// Should get only one event (after debounce)
	eventCount := 0
	timeout := time.After(5 * time.Second)

	for {
		select {
		case <-w.Events():
			eventCount++
			if eventCount > 1 {
				t.Error("expected only one event due to debouncing")
				return
			}
		case <-timeout:
			if eventCount != 1 {
				t.Errorf("expected 1 event, got %d", eventCount)
			}
			return
		}
	}
}
