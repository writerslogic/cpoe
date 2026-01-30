package checkpoint

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"witnessd/internal/vdf"
)

// =============================================================================
// Helper functions
// =============================================================================

func createTestDocument(t *testing.T, dir, content string) string {
	t.Helper()
	path := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("failed to create test document: %v", err)
	}
	return path
}

func testVDFParams() vdf.Parameters {
	return vdf.Parameters{
		IterationsPerSecond: 100000,
		MinIterations:       100,
		MaxIterations:       1000000,
	}
}

// =============================================================================
// Tests for NewChain
// =============================================================================

func TestNewChain(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "test content")

	chain, err := NewChain(docPath, testVDFParams())
	if err != nil {
		t.Fatalf("NewChain failed: %v", err)
	}

	if chain.DocumentID == "" {
		t.Error("DocumentID should not be empty")
	}
	if chain.DocumentPath == "" {
		t.Error("DocumentPath should not be empty")
	}
	if chain.CreatedAt.IsZero() {
		t.Error("CreatedAt should not be zero")
	}
	if len(chain.Checkpoints) != 0 {
		t.Errorf("expected 0 checkpoints, got %d", len(chain.Checkpoints))
	}
}

func TestNewChainAbsolutePath(t *testing.T) {
	tmpDir := t.TempDir()
	createTestDocument(t, tmpDir, "test content")

	// Use relative path
	origDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	chain, err := NewChain("test.txt", testVDFParams())
	if err != nil {
		t.Fatalf("NewChain failed: %v", err)
	}

	// DocumentPath should be absolute
	if !filepath.IsAbs(chain.DocumentPath) {
		t.Errorf("DocumentPath should be absolute: %s", chain.DocumentPath)
	}
}

func TestNewChainSameDocumentID(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "test content")

	chain1, _ := NewChain(docPath, testVDFParams())
	chain2, _ := NewChain(docPath, testVDFParams())

	if chain1.DocumentID != chain2.DocumentID {
		t.Error("same document path should produce same document ID")
	}
}

// =============================================================================
// Tests for Commit
// =============================================================================

func TestCommitFirst(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "test content")

	chain, _ := NewChain(docPath, testVDFParams())

	cp, err := chain.Commit("Initial commit")
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	if cp.Ordinal != 0 {
		t.Errorf("expected ordinal 0, got %d", cp.Ordinal)
	}
	if cp.PreviousHash != ([32]byte{}) {
		t.Error("first checkpoint should have zero previous hash")
	}
	if cp.Message != "Initial commit" {
		t.Errorf("expected message 'Initial commit', got %q", cp.Message)
	}
	if cp.VDF != nil {
		t.Error("first checkpoint should not have VDF proof")
	}
	if cp.Hash == ([32]byte{}) {
		t.Error("hash should not be zero")
	}

	// Check content hash
	content, _ := os.ReadFile(docPath)
	expectedHash := sha256.Sum256(content)
	if cp.ContentHash != expectedHash {
		t.Error("content hash mismatch")
	}
}

func TestCommitSecond(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "test content")

	chain, _ := NewChain(docPath, testVDFParams())

	cp1, _ := chain.Commit("First commit")

	// Modify document
	os.WriteFile(docPath, []byte("modified content"), 0600)

	cp2, err := chain.Commit("Second commit")
	if err != nil {
		t.Fatalf("Second commit failed: %v", err)
	}

	if cp2.Ordinal != 1 {
		t.Errorf("expected ordinal 1, got %d", cp2.Ordinal)
	}
	if cp2.PreviousHash != cp1.Hash {
		t.Error("second checkpoint should link to first")
	}
	if cp2.VDF == nil {
		t.Error("second checkpoint should have VDF proof")
	}
}

func TestCommitChain(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "v1")

	chain, _ := NewChain(docPath, testVDFParams())

	// Create a chain of commits
	for i := 0; i < 5; i++ {
		os.WriteFile(docPath, []byte("v"+string(rune('1'+i))), 0600)
		_, err := chain.Commit("Commit " + string(rune('1'+i)))
		if err != nil {
			t.Fatalf("Commit %d failed: %v", i, err)
		}
	}

	if len(chain.Checkpoints) != 5 {
		t.Errorf("expected 5 checkpoints, got %d", len(chain.Checkpoints))
	}
}

func TestCommitMissingDocument(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := filepath.Join(tmpDir, "nonexistent.txt")

	chain, _ := NewChain(docPath, testVDFParams())

	_, err := chain.Commit("should fail")
	if err == nil {
		t.Error("expected error for missing document")
	}
}

// =============================================================================
// Tests for CommitWithVDFDuration
// =============================================================================

func TestCommitWithVDFDuration(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "test content")

	chain, _ := NewChain(docPath, testVDFParams())

	// First commit (no VDF)
	chain.Commit("First")

	// Modify and commit with specific duration
	os.WriteFile(docPath, []byte("modified"), 0600)
	cp, err := chain.CommitWithVDFDuration("Second", 10*time.Millisecond)
	if err != nil {
		t.Fatalf("CommitWithVDFDuration failed: %v", err)
	}

	if cp.VDF == nil {
		t.Error("expected VDF proof")
	}
}

// =============================================================================
// Tests for computeHash
// =============================================================================

func TestComputeHash(t *testing.T) {
	cp := &Checkpoint{
		Ordinal:     1,
		ContentHash: sha256.Sum256([]byte("content")),
		ContentSize: 7,
		Timestamp:   time.Now(),
	}

	hash1 := cp.computeHash()
	hash2 := cp.computeHash()

	if hash1 != hash2 {
		t.Error("computeHash should be deterministic")
	}

	if hash1 == ([32]byte{}) {
		t.Error("hash should not be zero")
	}
}

func TestComputeHashDifferentOrdinal(t *testing.T) {
	base := &Checkpoint{
		ContentHash: sha256.Sum256([]byte("content")),
		ContentSize: 7,
		Timestamp:   time.Now(),
	}

	cp1 := *base
	cp1.Ordinal = 1
	hash1 := cp1.computeHash()

	cp2 := *base
	cp2.Ordinal = 2
	hash2 := cp2.computeHash()

	if hash1 == hash2 {
		t.Error("different ordinals should produce different hashes")
	}
}

// =============================================================================
// Tests for Verify
// =============================================================================

func TestVerifyValidChain(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "v1")

	chain, _ := NewChain(docPath, testVDFParams())

	for i := 0; i < 3; i++ {
		os.WriteFile(docPath, []byte("v"+string(rune('1'+i))), 0600)
		chain.Commit("Commit")
	}

	err := chain.Verify()
	if err != nil {
		t.Errorf("valid chain should verify: %v", err)
	}
}

func TestVerifyBrokenHash(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "content")

	chain, _ := NewChain(docPath, testVDFParams())
	chain.Commit("First")

	// Corrupt the hash
	chain.Checkpoints[0].Hash[0] ^= 0xff

	err := chain.Verify()
	if err == nil {
		t.Error("corrupted hash should fail verification")
	}
}

func TestVerifyBrokenChainLink(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "v1")

	chain, _ := NewChain(docPath, testVDFParams())
	chain.Commit("First")

	os.WriteFile(docPath, []byte("v2"), 0600)
	chain.Commit("Second")

	// Break the chain link
	chain.Checkpoints[1].PreviousHash[0] ^= 0xff

	err := chain.Verify()
	if err == nil {
		t.Error("broken chain link should fail verification")
	}
}

func TestVerifyFirstWithNonZeroPrevious(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "content")

	chain, _ := NewChain(docPath, testVDFParams())
	chain.Commit("First")

	// Set non-zero previous hash on first checkpoint
	chain.Checkpoints[0].PreviousHash = sha256.Sum256([]byte("fake"))
	// Recompute hash
	chain.Checkpoints[0].Hash = chain.Checkpoints[0].computeHash()

	err := chain.Verify()
	if err == nil {
		t.Error("first checkpoint with non-zero previous should fail")
	}
}

func TestVerifyEmptyChain(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "content")

	chain, _ := NewChain(docPath, testVDFParams())

	err := chain.Verify()
	if err != nil {
		t.Errorf("empty chain should verify: %v", err)
	}
}

// =============================================================================
// Tests for TotalElapsedTime
// =============================================================================

func TestTotalElapsedTime(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "content")

	chain, _ := NewChain(docPath, testVDFParams())

	// First checkpoint (no VDF)
	chain.Commit("First")

	if chain.TotalElapsedTime() != 0 {
		t.Error("single checkpoint should have zero elapsed time")
	}

	// Add more commits
	os.WriteFile(docPath, []byte("v2"), 0600)
	chain.Commit("Second")

	elapsed := chain.TotalElapsedTime()
	if elapsed < 0 {
		t.Error("elapsed time should not be negative")
	}
}

// =============================================================================
// Tests for Summary
// =============================================================================

func TestSummary(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "content")

	chain, _ := NewChain(docPath, testVDFParams())
	chain.Commit("First")

	summary := chain.Summary()

	if summary.DocumentPath != chain.DocumentPath {
		t.Error("document path mismatch")
	}
	if summary.CheckpointCount != 1 {
		t.Errorf("expected 1 checkpoint, got %d", summary.CheckpointCount)
	}
	if summary.FirstCommit.IsZero() {
		t.Error("first commit should not be zero")
	}
	if summary.LastCommit.IsZero() {
		t.Error("last commit should not be zero")
	}
	if summary.FinalContentHash == "" {
		t.Error("final content hash should not be empty")
	}
	if !summary.ChainValid {
		t.Error("valid chain should have ChainValid=true")
	}
}

func TestSummaryEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "content")

	chain, _ := NewChain(docPath, testVDFParams())

	summary := chain.Summary()

	if summary.CheckpointCount != 0 {
		t.Errorf("expected 0 checkpoints, got %d", summary.CheckpointCount)
	}
	if summary.FinalContentHash != "" {
		t.Error("empty chain should have empty final hash")
	}
	if !summary.ChainValid {
		t.Error("empty chain should be valid")
	}
}

// =============================================================================
// Tests for Save and Load
// =============================================================================

func TestSaveAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "content")
	chainPath := filepath.Join(tmpDir, "chain.json")

	chain, _ := NewChain(docPath, testVDFParams())
	chain.Commit("First")

	os.WriteFile(docPath, []byte("v2"), 0600)
	chain.Commit("Second")

	err := chain.Save(chainPath)
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loaded, err := Load(chainPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if loaded.DocumentID != chain.DocumentID {
		t.Error("DocumentID mismatch")
	}
	if len(loaded.Checkpoints) != len(chain.Checkpoints) {
		t.Error("checkpoint count mismatch")
	}
	if loaded.storagePath != chainPath {
		t.Error("storage path not set on load")
	}
}

func TestSaveCreatesDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "content")
	chainPath := filepath.Join(tmpDir, "subdir", "chain.json")

	chain, _ := NewChain(docPath, testVDFParams())
	chain.Commit("First")

	err := chain.Save(chainPath)
	if err != nil {
		t.Fatalf("Save should create directory: %v", err)
	}

	if _, err := os.Stat(chainPath); os.IsNotExist(err) {
		t.Error("chain file was not created")
	}
}

func TestLoadNonexistent(t *testing.T) {
	_, err := Load("/nonexistent/chain.json")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestLoadInvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	chainPath := filepath.Join(tmpDir, "chain.json")

	os.WriteFile(chainPath, []byte("not valid json{{{"), 0600)

	_, err := Load(chainPath)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

// =============================================================================
// Tests for FindChain
// =============================================================================

func TestFindChainExists(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "content")
	witnessdDir := filepath.Join(tmpDir, ".witnessd")

	chain, _ := NewChain(docPath, testVDFParams())

	// Compute expected chain path
	absPath, _ := filepath.Abs(docPath)
	pathHash := sha256.Sum256([]byte(absPath))
	docID := hex.EncodeToString(pathHash[:8])
	chainPath := filepath.Join(witnessdDir, "chains", docID+".json")

	chain.Save(chainPath)

	found, err := FindChain(docPath, witnessdDir)
	if err != nil {
		t.Fatalf("FindChain failed: %v", err)
	}
	if found != chainPath {
		t.Errorf("expected %s, got %s", chainPath, found)
	}
}

func TestFindChainNotExists(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "content")
	witnessdDir := filepath.Join(tmpDir, ".witnessd")

	_, err := FindChain(docPath, witnessdDir)
	if err == nil {
		t.Error("expected error for nonexistent chain")
	}
}

// =============================================================================
// Tests for GetOrCreateChain
// =============================================================================

func TestGetOrCreateChainNew(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "content")
	witnessdDir := filepath.Join(tmpDir, ".witnessd")

	chain, err := GetOrCreateChain(docPath, witnessdDir, testVDFParams())
	if err != nil {
		t.Fatalf("GetOrCreateChain failed: %v", err)
	}

	if chain.DocumentPath == "" {
		t.Error("chain should have document path")
	}
	if chain.StoragePath() == "" {
		t.Error("chain should have storage path")
	}
}

func TestGetOrCreateChainExisting(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "content")
	witnessdDir := filepath.Join(tmpDir, ".witnessd")

	// Create and save chain
	chain1, _ := GetOrCreateChain(docPath, witnessdDir, testVDFParams())
	chain1.Commit("First")
	chain1.Save(chain1.StoragePath())

	// Get existing chain
	chain2, err := GetOrCreateChain(docPath, witnessdDir, testVDFParams())
	if err != nil {
		t.Fatalf("GetOrCreateChain failed: %v", err)
	}

	if len(chain2.Checkpoints) != 1 {
		t.Errorf("expected 1 checkpoint from loaded chain, got %d", len(chain2.Checkpoints))
	}
}

// =============================================================================
// Tests for Latest and At
// =============================================================================

func TestLatest(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "content")

	chain, _ := NewChain(docPath, testVDFParams())

	if chain.Latest() != nil {
		t.Error("empty chain should return nil Latest")
	}

	cp1, _ := chain.Commit("First")
	if chain.Latest() != cp1 {
		t.Error("Latest should return first checkpoint")
	}

	os.WriteFile(docPath, []byte("v2"), 0600)
	cp2, _ := chain.Commit("Second")
	if chain.Latest() != cp2 {
		t.Error("Latest should return second checkpoint")
	}
}

func TestAt(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "content")

	chain, _ := NewChain(docPath, testVDFParams())
	cp0, _ := chain.Commit("First")

	os.WriteFile(docPath, []byte("v2"), 0600)
	cp1, _ := chain.Commit("Second")

	got0, err := chain.At(0)
	if err != nil {
		t.Fatalf("At(0) failed: %v", err)
	}
	if got0 != cp0 {
		t.Error("At(0) returned wrong checkpoint")
	}

	got1, err := chain.At(1)
	if err != nil {
		t.Fatalf("At(1) failed: %v", err)
	}
	if got1 != cp1 {
		t.Error("At(1) returned wrong checkpoint")
	}
}

func TestAtOutOfRange(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "content")

	chain, _ := NewChain(docPath, testVDFParams())
	chain.Commit("First")

	_, err := chain.At(5)
	if err == nil {
		t.Error("expected error for out of range ordinal")
	}
}

// =============================================================================
// Tests for StoragePath
// =============================================================================

func TestStoragePath(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "content")
	chainPath := filepath.Join(tmpDir, "chain.json")

	chain, _ := NewChain(docPath, testVDFParams())

	if chain.StoragePath() != "" {
		t.Error("new chain should have empty storage path")
	}

	chain.Save(chainPath)

	if chain.StoragePath() != chainPath {
		t.Errorf("storage path mismatch: expected %s, got %s", chainPath, chain.StoragePath())
	}
}

// =============================================================================
// Tests for JSON serialization
// =============================================================================

func TestCheckpointJSON(t *testing.T) {
	cp := &Checkpoint{
		Ordinal:      1,
		PreviousHash: sha256.Sum256([]byte("prev")),
		Hash:         sha256.Sum256([]byte("hash")),
		ContentHash:  sha256.Sum256([]byte("content")),
		ContentSize:  100,
		FilePath:     "/test/file.txt",
		Timestamp:    time.Now().UTC(),
		Message:      "Test commit",
	}

	data, err := json.Marshal(cp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded Checkpoint
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.Ordinal != cp.Ordinal {
		t.Error("ordinal mismatch")
	}
	if decoded.Message != cp.Message {
		t.Error("message mismatch")
	}
}

func TestChainSummaryJSON(t *testing.T) {
	summary := ChainSummary{
		DocumentPath:     "/test/doc.txt",
		CheckpointCount:  5,
		FirstCommit:      time.Now().Add(-24 * time.Hour),
		LastCommit:       time.Now(),
		TotalElapsedTime: 1 * time.Hour,
		FinalContentHash: "abc123",
		ChainValid:       true,
	}

	data, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded ChainSummary
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.CheckpointCount != 5 {
		t.Error("checkpoint count mismatch")
	}
	if !decoded.ChainValid {
		t.Error("chain valid mismatch")
	}
}

func TestTPMBindingJSON(t *testing.T) {
	binding := &TPMBinding{
		MonotonicCounter: 42,
		ClockInfo:        []byte{1, 2, 3},
		Attestation:      []byte{4, 5, 6},
		Signature:        []byte{7, 8, 9},
		PublicKey:        []byte{10, 11, 12},
	}

	data, err := json.Marshal(binding)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded TPMBinding
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.MonotonicCounter != 42 {
		t.Error("monotonic counter mismatch")
	}
}
