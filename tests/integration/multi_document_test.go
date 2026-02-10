//go:build integration

package integration

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"witnessd/internal/checkpoint"
	"witnessd/internal/tracking"
	"witnessd/internal/vdf"
)

// MultiDocEnv manages multiple document test environments.
type MultiDocEnv struct {
	T           *testing.T
	TempDir     string
	WitnessdDir string
	Documents   map[string]*DocumentState
	VDFParams   vdf.Parameters
}

// DocumentState tracks the state of a single document.
type DocumentState struct {
	Path     string
	ID       string
	Chain    *checkpoint.Chain
	Tracking *tracking.Session
	Content  []byte
}

// NewMultiDocEnv creates a test environment for multiple documents.
func NewMultiDocEnv(t *testing.T) *MultiDocEnv {
	t.Helper()

	tempDir := t.TempDir()
	witnessdDir := filepath.Join(tempDir, ".witnessd")

	// Create directories
	for _, subdir := range []string{"chains", "tracking", "wal"} {
		if err := os.MkdirAll(filepath.Join(witnessdDir, subdir), 0700); err != nil {
			t.Fatalf("failed to create %s dir: %v", subdir, err)
		}
	}

	return &MultiDocEnv{
		T:           t,
		TempDir:     tempDir,
		WitnessdDir: witnessdDir,
		Documents:   make(map[string]*DocumentState),
		VDFParams: vdf.Parameters{
			IterationsPerSecond: 100000,
			MinIterations:       100,
			MaxIterations:       1000000,
		},
	}
}

// CreateDocument creates a new document and initializes its tracking.
func (env *MultiDocEnv) CreateDocument(name, content string) *DocumentState {
	env.T.Helper()

	docPath := filepath.Join(env.TempDir, name)
	if err := os.WriteFile(docPath, []byte(content), 0600); err != nil {
		env.T.Fatalf("failed to create document %s: %v", name, err)
	}

	// Generate document ID
	absPath, _ := filepath.Abs(docPath)
	pathHash := sha256.Sum256([]byte(absPath))
	docID := hex.EncodeToString(pathHash[:8])

	// Create chain
	chain, err := checkpoint.NewChain(docPath, env.VDFParams)
	if err != nil {
		env.T.Fatalf("failed to create chain for %s: %v", name, err)
	}

	// Create tracking session
	cfg := tracking.DefaultConfig(docPath)
	cfg.Simulated = true

	trackingSession, err := tracking.NewSession(cfg)
	if err != nil {
		env.T.Fatalf("failed to create tracking for %s: %v", name, err)
	}

	state := &DocumentState{
		Path:     docPath,
		ID:       docID,
		Chain:    chain,
		Tracking: trackingSession,
		Content:  []byte(content),
	}

	env.Documents[name] = state
	return state
}

// ModifyDocument modifies an existing document.
func (env *MultiDocEnv) ModifyDocument(name, content string) {
	env.T.Helper()

	state, ok := env.Documents[name]
	if !ok {
		env.T.Fatalf("document %s not found", name)
	}

	newContent := append(state.Content, []byte(content)...)
	if err := os.WriteFile(state.Path, newContent, 0600); err != nil {
		env.T.Fatalf("failed to modify document %s: %v", name, err)
	}
	state.Content = newContent
}

// Cleanup stops all tracking sessions.
func (env *MultiDocEnv) Cleanup() {
	for _, state := range env.Documents {
		if state.Tracking != nil {
			state.Tracking.Stop()
		}
	}
}

// TestMultiDocumentBasic tests basic multi-document operations.
func TestMultiDocumentBasic(t *testing.T) {
	env := NewMultiDocEnv(t)
	defer env.Cleanup()

	// Create three documents
	doc1 := env.CreateDocument("essay.md", "# Essay\n\nIntroduction paragraph.\n")
	doc2 := env.CreateDocument("notes.txt", "Study notes for chapter 1.\n")
	doc3 := env.CreateDocument("report.md", "# Report\n\n## Summary\n")

	// Verify separate document IDs
	ids := make(map[string]bool)
	for name, state := range env.Documents {
		if ids[state.ID] {
			t.Errorf("duplicate document ID for %s", name)
		}
		ids[state.ID] = true
	}

	// Create initial checkpoints for all
	cp1, err := doc1.Chain.Commit("Initial essay")
	AssertNoError(t, err, "doc1 checkpoint should succeed")

	cp2, err := doc2.Chain.Commit("Initial notes")
	AssertNoError(t, err, "doc2 checkpoint should succeed")

	cp3, err := doc3.Chain.Commit("Initial report")
	AssertNoError(t, err, "doc3 checkpoint should succeed")

	// Verify checkpoints are independent
	AssertNotEqual(t, cp1.ContentHash, cp2.ContentHash, "different docs should have different hashes")
	AssertNotEqual(t, cp2.ContentHash, cp3.ContentHash, "different docs should have different hashes")

	// Modify documents independently
	env.ModifyDocument("essay.md", "\nBody paragraph 1.\n")
	env.ModifyDocument("notes.txt", "More notes about concepts.\n")

	// Create more checkpoints
	doc1.Chain.Commit("Added body paragraph")
	doc2.Chain.Commit("Added more notes")

	// Verify chains are independent
	AssertEqual(t, 2, len(doc1.Chain.Checkpoints), "essay should have 2 checkpoints")
	AssertEqual(t, 2, len(doc2.Chain.Checkpoints), "notes should have 2 checkpoints")
	AssertEqual(t, 1, len(doc3.Chain.Checkpoints), "report should have 1 checkpoint")
}

// TestMultiDocumentConcurrent tests concurrent operations on multiple documents.
func TestMultiDocumentConcurrent(t *testing.T) {
	env := NewMultiDocEnv(t)
	defer env.Cleanup()

	// Create documents
	numDocs := 5
	for i := 0; i < numDocs; i++ {
		name := "doc" + string(rune('A'+i)) + ".md"
		content := "# Document " + string(rune('A'+i)) + "\n"
		env.CreateDocument(name, content)
	}

	// Concurrent modifications and checkpoints
	var wg sync.WaitGroup
	errors := make(chan error, numDocs*10)

	for name, state := range env.Documents {
		wg.Add(1)
		go func(docName string, docState *DocumentState) {
			defer wg.Done()

			// Multiple modifications per document
			for i := 0; i < 5; i++ {
				content := "\nParagraph " + string(rune('1'+i)) + " in " + docName + "\n"

				// Modify document
				newContent := append(docState.Content, []byte(content)...)
				if err := os.WriteFile(docState.Path, newContent, 0600); err != nil {
					errors <- err
					return
				}
				docState.Content = newContent

				// Create checkpoint
				_, err := docState.Chain.Commit("Commit " + string(rune('1'+i)))
				if err != nil {
					errors <- err
					return
				}

				time.Sleep(10 * time.Millisecond)
			}
		}(name, state)
	}

	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		t.Errorf("concurrent operation failed: %v", err)
	}

	// Verify all documents have checkpoints
	for name, state := range env.Documents {
		AssertEqual(t, 6, len(state.Chain.Checkpoints), "%s should have 6 checkpoints", name)

		// Verify chain integrity
		err := state.Chain.Verify()
		AssertNoError(t, err, "%s chain should verify", name)
	}
}

// TestMultiDocumentTrackingSessions tests separate tracking sessions per document.
func TestMultiDocumentTrackingSessions(t *testing.T) {
	env := NewMultiDocEnv(t)
	defer env.Cleanup()

	// Create documents
	doc1 := env.CreateDocument("thesis.md", "# Thesis\n\n")
	doc2 := env.CreateDocument("bibliography.md", "# Bibliography\n\n")

	// Start tracking on both
	err := doc1.Tracking.Start()
	AssertNoError(t, err, "thesis tracking should start")

	err = doc2.Tracking.Start()
	AssertNoError(t, err, "bibliography tracking should start")

	// Verify sessions are independent
	status1 := doc1.Tracking.Status()
	status2 := doc2.Tracking.Status()

	AssertNotEqual(t, status1.ID, status2.ID, "sessions should have different IDs")
	AssertTrue(t, status1.Running, "thesis tracking should be running")
	AssertTrue(t, status2.Running, "bibliography tracking should be running")

	// Simulate activity
	time.Sleep(50 * time.Millisecond)

	// Stop and verify
	doc1.Tracking.Stop()
	doc2.Tracking.Stop()

	status1 = doc1.Tracking.Status()
	status2 = doc2.Tracking.Status()

	AssertFalse(t, status1.Running, "thesis tracking should be stopped")
	AssertFalse(t, status2.Running, "bibliography tracking should be stopped")

	// Export evidence from both
	evidence1 := doc1.Tracking.Export()
	evidence2 := doc2.Tracking.Export()

	AssertNotEqual(t, evidence1.SessionID, evidence2.SessionID, "evidence should have different session IDs")
}

// TestMultiDocumentSwitching tests switching between active documents.
func TestMultiDocumentSwitching(t *testing.T) {
	env := NewMultiDocEnv(t)
	defer env.Cleanup()

	// Create documents
	doc1 := env.CreateDocument("chapter1.md", "# Chapter 1\n\n")
	doc2 := env.CreateDocument("chapter2.md", "# Chapter 2\n\n")
	doc3 := env.CreateDocument("chapter3.md", "# Chapter 3\n\n")

	// Simulate working on doc1
	doc1.Tracking.Start()
	env.ModifyDocument("chapter1.md", "Writing intro for chapter 1.\n")
	doc1.Chain.Commit("Intro")
	time.Sleep(20 * time.Millisecond)

	// Switch to doc2
	doc1.Tracking.Stop()
	doc2.Tracking.Start()
	env.ModifyDocument("chapter2.md", "Writing intro for chapter 2.\n")
	doc2.Chain.Commit("Intro")
	time.Sleep(20 * time.Millisecond)

	// Switch to doc3
	doc2.Tracking.Stop()
	doc3.Tracking.Start()
	env.ModifyDocument("chapter3.md", "Writing intro for chapter 3.\n")
	doc3.Chain.Commit("Intro")
	time.Sleep(20 * time.Millisecond)

	// Back to doc1
	doc3.Tracking.Stop()
	doc1.Tracking.Start()
	env.ModifyDocument("chapter1.md", "\nAdding more to chapter 1.\n")
	doc1.Chain.Commit("More content")
	doc1.Tracking.Stop()

	// Verify each document has correct checkpoints
	AssertEqual(t, 3, len(doc1.Chain.Checkpoints), "chapter1 should have 3 checkpoints")
	AssertEqual(t, 2, len(doc2.Chain.Checkpoints), "chapter2 should have 2 checkpoints")
	AssertEqual(t, 2, len(doc3.Chain.Checkpoints), "chapter3 should have 2 checkpoints")

	// Verify all chains
	for name, state := range env.Documents {
		err := state.Chain.Verify()
		AssertNoError(t, err, "%s chain should verify", name)
	}
}

// TestMultiDocumentPersistence tests saving and loading multiple chains.
func TestMultiDocumentPersistence(t *testing.T) {
	env := NewMultiDocEnv(t)
	defer env.Cleanup()

	// Create and populate documents
	docs := []struct {
		name    string
		content string
		commits int
	}{
		{"research.md", "# Research\n", 5},
		{"draft.md", "# Draft\n", 3},
		{"final.md", "# Final\n", 7},
	}

	for _, doc := range docs {
		state := env.CreateDocument(doc.name, doc.content)

		// Create checkpoints
		for i := 0; i < doc.commits; i++ {
			env.ModifyDocument(doc.name, "\nCommit "+string(rune('1'+i)))
			state.Chain.Commit("Commit " + string(rune('1'+i)))
		}

		// Save chain
		chainPath := filepath.Join(env.WitnessdDir, "chains", state.ID+".json")
		err := state.Chain.Save(chainPath)
		AssertNoError(t, err, "saving %s chain should succeed", doc.name)
	}

	// Load chains and verify
	for _, doc := range docs {
		state := env.Documents[doc.name]
		chainPath := filepath.Join(env.WitnessdDir, "chains", state.ID+".json")

		loaded, err := checkpoint.Load(chainPath)
		AssertNoError(t, err, "loading %s chain should succeed", doc.name)

		// Verify checkpoint count (+1 for initial content)
		expectedCount := doc.commits + 1
		AssertEqual(t, expectedCount, len(loaded.Checkpoints), "%s should have %d checkpoints", doc.name, expectedCount)

		// Verify chain integrity
		err = loaded.Verify()
		AssertNoError(t, err, "%s loaded chain should verify", doc.name)
	}
}

// TestMultiDocumentFindChain tests finding chains for documents.
func TestMultiDocumentFindChain(t *testing.T) {
	env := NewMultiDocEnv(t)
	defer env.Cleanup()

	// Create and save a document with chain
	state := env.CreateDocument("findme.md", "# Find Me\n")
	state.Chain.Commit("Initial")

	chainPath := filepath.Join(env.WitnessdDir, "chains", state.ID+".json")
	err := state.Chain.Save(chainPath)
	AssertNoError(t, err, "save should succeed")

	// Find chain
	foundPath, err := checkpoint.FindChain(state.Path, env.WitnessdDir)
	AssertNoError(t, err, "should find chain")
	AssertEqual(t, chainPath, foundPath, "found path should match")

	// Try to find non-existent chain
	_, err = checkpoint.FindChain("/nonexistent/path.md", env.WitnessdDir)
	AssertError(t, err, "should not find chain for nonexistent document")
}

// TestMultiDocumentGetOrCreate tests GetOrCreateChain for multiple documents.
func TestMultiDocumentGetOrCreate(t *testing.T) {
	env := NewMultiDocEnv(t)
	defer env.Cleanup()

	// Create document without pre-existing chain
	docPath := filepath.Join(env.TempDir, "newdoc.md")
	if err := os.WriteFile(docPath, []byte("# New Doc\n"), 0600); err != nil {
		t.Fatalf("failed to create document: %v", err)
	}

	// GetOrCreate should create new chain
	chain1, err := checkpoint.GetOrCreateChain(docPath, env.WitnessdDir, env.VDFParams)
	AssertNoError(t, err, "GetOrCreate should succeed")
	AssertEqual(t, 0, len(chain1.Checkpoints), "new chain should be empty")

	// Add checkpoint and save
	chain1.Commit("First")
	chain1.Save(chain1.StoragePath())

	// GetOrCreate again should load existing
	chain2, err := checkpoint.GetOrCreateChain(docPath, env.WitnessdDir, env.VDFParams)
	AssertNoError(t, err, "GetOrCreate should succeed")
	AssertEqual(t, 1, len(chain2.Checkpoints), "should load existing chain")
	AssertEqual(t, chain1.DocumentID, chain2.DocumentID, "document IDs should match")
}

// TestMultiDocumentIsolation tests that document chains are properly isolated.
func TestMultiDocumentIsolation(t *testing.T) {
	env := NewMultiDocEnv(t)
	defer env.Cleanup()

	// Create two documents with same initial content
	doc1 := env.CreateDocument("copy1.md", "# Same Content\n\nIdentical text.\n")
	doc2 := env.CreateDocument("copy2.md", "# Same Content\n\nIdentical text.\n")

	// Initial content hashes should be the same
	doc1.Chain.Commit("Initial")
	doc2.Chain.Commit("Initial")

	cp1 := doc1.Chain.Latest()
	cp2 := doc2.Chain.Latest()

	AssertEqual(t, cp1.ContentHash, cp2.ContentHash, "identical content should have same hash")

	// But chains should be different (different document IDs)
	AssertNotEqual(t, doc1.ID, doc2.ID, "document IDs should differ")

	// Modify only doc1
	env.ModifyDocument("copy1.md", "\nUnique addition to copy1.\n")
	doc1.Chain.Commit("Modified copy1")

	// Verify doc2 is unchanged
	AssertEqual(t, 1, len(doc2.Chain.Checkpoints), "doc2 should still have 1 checkpoint")
	AssertEqual(t, 2, len(doc1.Chain.Checkpoints), "doc1 should have 2 checkpoints")

	// Content hashes should now differ
	cp1Latest := doc1.Chain.Latest()
	cp2Latest := doc2.Chain.Latest()
	AssertNotEqual(t, cp1Latest.ContentHash, cp2Latest.ContentHash, "modified content should differ")
}

// TestMultiDocumentSummary tests summary generation for multiple documents.
func TestMultiDocumentSummary(t *testing.T) {
	env := NewMultiDocEnv(t)
	defer env.Cleanup()

	// Create documents with different activity levels
	doc1 := env.CreateDocument("active.md", "# Active\n")
	doc2 := env.CreateDocument("sparse.md", "# Sparse\n")

	// Active document with many commits
	for i := 0; i < 10; i++ {
		env.ModifyDocument("active.md", "\nParagraph\n")
		doc1.Chain.Commit("Commit")
		time.Sleep(5 * time.Millisecond)
	}

	// Sparse document with few commits
	doc2.Chain.Commit("Initial")
	env.ModifyDocument("sparse.md", "\nOne change\n")
	doc2.Chain.Commit("Final")

	// Get summaries
	summary1 := doc1.Chain.Summary()
	summary2 := doc2.Chain.Summary()

	// Verify summaries
	AssertEqual(t, 11, summary1.CheckpointCount, "active should have 11 checkpoints")
	AssertEqual(t, 2, summary2.CheckpointCount, "sparse should have 2 checkpoints")

	AssertTrue(t, summary1.ChainValid, "active chain should be valid")
	AssertTrue(t, summary2.ChainValid, "sparse chain should be valid")

	// Active document should have some elapsed time
	AssertTrue(t, summary1.TotalElapsedTime >= 0, "should have non-negative elapsed time")
}
