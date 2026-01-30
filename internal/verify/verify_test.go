package verify

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"witnessd/internal/mmr"
)

// =============================================================================
// Helper functions
// =============================================================================

func createTestKeys(t *testing.T, dir string) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	// Write raw public key
	pubPath := filepath.Join(dir, "key.pub")
	if err := os.WriteFile(pubPath, pub, 0600); err != nil {
		t.Fatalf("failed to write public key: %v", err)
	}

	return pub, priv
}

func createTestMMR(t *testing.T, dbPath string, hashes ...[32]byte) *mmr.MMR {
	t.Helper()
	store, err := mmr.OpenFileStore(dbPath)
	if err != nil {
		t.Fatalf("failed to open store: %v", err)
	}

	m, err := mmr.New(store)
	if err != nil {
		store.Close()
		t.Fatalf("failed to create mmr: %v", err)
	}

	for _, h := range hashes {
		if _, err := m.Append(h[:]); err != nil {
			store.Close()
			t.Fatalf("failed to append to mmr: %v", err)
		}
	}

	store.Close()
	return nil // Return nil since we close it
}

// =============================================================================
// Tests for splitLines
// =============================================================================

func TestSplitLines(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "empty",
			input:    "",
			expected: []string{},
		},
		{
			name:     "single line no newline",
			input:    "hello",
			expected: []string{"hello"},
		},
		{
			name:     "single line with newline",
			input:    "hello\n",
			expected: []string{"hello"},
		},
		{
			name:     "multiple lines",
			input:    "line1\nline2\nline3",
			expected: []string{"line1", "line2", "line3"},
		},
		{
			name:     "multiple lines with trailing newline",
			input:    "line1\nline2\nline3\n",
			expected: []string{"line1", "line2", "line3"},
		},
		{
			name:     "empty lines",
			input:    "line1\n\nline3",
			expected: []string{"line1", "", "line3"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := splitLines([]byte(tt.input))

			if len(result) != len(tt.expected) {
				t.Fatalf("expected %d lines, got %d", len(tt.expected), len(result))
			}

			for i, line := range result {
				if string(line) != tt.expected[i] {
					t.Errorf("line %d: expected %q, got %q", i, tt.expected[i], string(line))
				}
			}
		})
	}
}

// =============================================================================
// Tests for loadSignatures
// =============================================================================

func TestLoadSignatures(t *testing.T) {
	tmpDir := t.TempDir()
	sigsPath := filepath.Join(tmpDir, "signatures.log")

	// Create valid signature entries
	rootHash := sha256.Sum256([]byte("test root"))
	rootHex := hex.EncodeToString(rootHash[:])
	sigHex := hex.EncodeToString(make([]byte, 64))

	content := "2025-01-15T10:00:00Z " + rootHex + " " + sigHex + " 100\n"
	content += "2025-01-15T11:00:00Z " + rootHex + " " + sigHex + " 200\n"

	if err := os.WriteFile(sigsPath, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write signatures: %v", err)
	}

	entries, err := loadSignatures(sigsPath)
	if err != nil {
		t.Fatalf("loadSignatures failed: %v", err)
	}

	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	if entries[0].Size != 100 {
		t.Errorf("expected size 100, got %d", entries[0].Size)
	}
	if entries[1].Size != 200 {
		t.Errorf("expected size 200, got %d", entries[1].Size)
	}
}

func TestLoadSignaturesEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	sigsPath := filepath.Join(tmpDir, "signatures.log")

	if err := os.WriteFile(sigsPath, []byte(""), 0600); err != nil {
		t.Fatalf("failed to write signatures: %v", err)
	}

	entries, err := loadSignatures(sigsPath)
	if err != nil {
		t.Fatalf("loadSignatures failed: %v", err)
	}

	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestLoadSignaturesInvalidLines(t *testing.T) {
	tmpDir := t.TempDir()
	sigsPath := filepath.Join(tmpDir, "signatures.log")

	// Mix of valid and invalid lines
	rootHash := sha256.Sum256([]byte("test root"))
	rootHex := hex.EncodeToString(rootHash[:])
	sigHex := hex.EncodeToString(make([]byte, 64))

	content := "invalid line\n"
	content += "2025-01-15T10:00:00Z " + rootHex + " " + sigHex + " 100\n"
	content += "bad timestamp " + rootHex + " " + sigHex + " 200\n"
	content += "2025-01-15T12:00:00Z invalid_root " + sigHex + " 300\n"

	if err := os.WriteFile(sigsPath, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write signatures: %v", err)
	}

	entries, err := loadSignatures(sigsPath)
	if err != nil {
		t.Fatalf("loadSignatures failed: %v", err)
	}

	// Only one valid entry
	if len(entries) != 1 {
		t.Errorf("expected 1 valid entry, got %d", len(entries))
	}
}

func TestLoadSignaturesNonexistent(t *testing.T) {
	_, err := loadSignatures("/nonexistent/path/signatures.log")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

// =============================================================================
// Tests for SaveEvidence
// =============================================================================

func TestSaveEvidence(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "evidence.json")

	testHash := sha256.Sum256([]byte("test"))
	rootHash := sha256.Sum256([]byte("root"))
	peakHash := sha256.Sum256([]byte("peak"))

	packet := &EvidencePacket{
		Version:     1,
		GeneratedAt: time.Now().UTC(),
		FilePath:    "/test/file.txt",
		FileHash:    hex.EncodeToString(testHash[:]),
		FileSize:    100,
		MMRIndex:    0,
		MMRSize:     1,
		MMRRoot:     hex.EncodeToString(rootHash[:]),
		MerklePath:  []ProofStep{},
		Peaks:       []string{hex.EncodeToString(peakHash[:])},
		PeakPos:     0,
		PublicKey:   hex.EncodeToString(make([]byte, 32)),
		Signature:   "",
	}

	err := SaveEvidence(packet, outputPath)
	if err != nil {
		t.Fatalf("SaveEvidence failed: %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Fatal("output file was not created")
	}

	// Verify it's valid JSON
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("failed to read output: %v", err)
	}

	var loaded EvidencePacket
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if loaded.Version != 1 {
		t.Errorf("expected version 1, got %d", loaded.Version)
	}
	if loaded.FilePath != "/test/file.txt" {
		t.Errorf("expected file path /test/file.txt, got %s", loaded.FilePath)
	}
}

// =============================================================================
// Tests for VerifyEvidence
// =============================================================================

func TestVerifyEvidenceSinglePeak(t *testing.T) {
	// Create a simple single-leaf MMR proof
	fileHash := sha256.Sum256([]byte("test content"))
	leafHash := mmr.HashLeaf(fileHash[:])

	// For single leaf, the leaf hash is the peak and root
	packet := &EvidencePacket{
		Version:    1,
		FilePath:   "/test/file.txt",
		FileHash:   hex.EncodeToString(fileHash[:]),
		FileSize:   100,
		MMRIndex:   0,
		MMRSize:    1,
		MMRRoot:    hex.EncodeToString(leafHash[:]),
		MerklePath: []ProofStep{},
		Peaks:      []string{hex.EncodeToString(leafHash[:])},
		PeakPos:    0,
		PublicKey:  "",
		Signature:  "",
	}

	err := VerifyEvidence(packet, nil)
	if err != nil {
		t.Fatalf("VerifyEvidence failed: %v", err)
	}
}

func TestVerifyEvidenceWithMerklePath(t *testing.T) {
	// Create a two-leaf MMR
	fileHash := sha256.Sum256([]byte("file1"))
	siblingHash := sha256.Sum256([]byte("file2"))

	leafHash := mmr.HashLeaf(fileHash[:])
	siblingLeafHash := mmr.HashLeaf(siblingHash[:])

	// Internal node (peak and root for 2 leaves)
	peakHash := mmr.HashInternal(leafHash, siblingLeafHash)

	packet := &EvidencePacket{
		Version:  1,
		FilePath: "/test/file1.txt",
		FileHash: hex.EncodeToString(fileHash[:]),
		FileSize: 100,
		MMRIndex: 0,
		MMRSize:  2,
		MMRRoot:  hex.EncodeToString(peakHash[:]),
		MerklePath: []ProofStep{
			{
				Hash:   hex.EncodeToString(siblingLeafHash[:]),
				IsLeft: false, // sibling is on right
			},
		},
		Peaks:     []string{hex.EncodeToString(peakHash[:])},
		PeakPos:   0,
		PublicKey: "",
		Signature: "",
	}

	err := VerifyEvidence(packet, nil)
	if err != nil {
		t.Fatalf("VerifyEvidence failed: %v", err)
	}
}

func TestVerifyEvidenceInvalidFileHash(t *testing.T) {
	packet := &EvidencePacket{
		FileHash: "invalid_hex",
	}

	err := VerifyEvidence(packet, nil)
	if err == nil {
		t.Error("expected error for invalid file hash")
	}
}

func TestVerifyEvidenceInvalidSiblingHash(t *testing.T) {
	fileHash := sha256.Sum256([]byte("test"))
	leafHash := mmr.HashLeaf(fileHash[:])

	packet := &EvidencePacket{
		FileHash: hex.EncodeToString(fileHash[:]),
		MerklePath: []ProofStep{
			{
				Hash:   "invalid_hex",
				IsLeft: false,
			},
		},
		Peaks:   []string{hex.EncodeToString(leafHash[:])},
		PeakPos: 0,
	}

	err := VerifyEvidence(packet, nil)
	if err == nil {
		t.Error("expected error for invalid sibling hash")
	}
}

func TestVerifyEvidenceInvalidPeakPosition(t *testing.T) {
	fileHash := sha256.Sum256([]byte("test"))
	leafHash := mmr.HashLeaf(fileHash[:])

	packet := &EvidencePacket{
		FileHash:   hex.EncodeToString(fileHash[:]),
		MerklePath: []ProofStep{},
		Peaks:      []string{hex.EncodeToString(leafHash[:])},
		PeakPos:    5, // Out of bounds
	}

	err := VerifyEvidence(packet, nil)
	if err != ErrProofInvalid {
		t.Errorf("expected ErrProofInvalid, got %v", err)
	}
}

func TestVerifyEvidenceInvalidProof(t *testing.T) {
	fileHash := sha256.Sum256([]byte("test"))
	wrongHash := sha256.Sum256([]byte("wrong"))

	packet := &EvidencePacket{
		FileHash:   hex.EncodeToString(fileHash[:]),
		MerklePath: []ProofStep{},
		Peaks:      []string{hex.EncodeToString(wrongHash[:])}, // Wrong peak
		PeakPos:    0,
	}

	err := VerifyEvidence(packet, nil)
	if err != ErrProofInvalid {
		t.Errorf("expected ErrProofInvalid, got %v", err)
	}
}

func TestVerifyEvidenceMultiplePeaks(t *testing.T) {
	// Create a 3-leaf MMR (2 complete + 1 pending)
	// Peaks: internal(leaf0, leaf1) and leaf2
	file1Hash := sha256.Sum256([]byte("file1"))
	file2Hash := sha256.Sum256([]byte("file2"))
	file3Hash := sha256.Sum256([]byte("file3"))

	leaf1 := mmr.HashLeaf(file1Hash[:])
	leaf2 := mmr.HashLeaf(file2Hash[:])
	leaf3 := mmr.HashLeaf(file3Hash[:])

	peak0 := mmr.HashInternal(leaf1, leaf2)
	peak1 := leaf3

	// Root = HashInternal(peak0, peak1)
	root := mmr.HashInternal(peak0, peak1)

	// Verify file1 (in first peak)
	packet := &EvidencePacket{
		FileHash: hex.EncodeToString(file1Hash[:]),
		MerklePath: []ProofStep{
			{Hash: hex.EncodeToString(leaf2[:]), IsLeft: false},
		},
		Peaks:   []string{hex.EncodeToString(peak0[:]), hex.EncodeToString(peak1[:])},
		PeakPos: 0,
		MMRRoot: hex.EncodeToString(root[:]),
	}

	err := VerifyEvidence(packet, nil)
	if err != nil {
		t.Fatalf("VerifyEvidence failed: %v", err)
	}
}

func TestVerifyEvidenceWithSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)

	fileHash := sha256.Sum256([]byte("test"))
	leafHash := mmr.HashLeaf(fileHash[:])

	signature := ed25519.Sign(priv, leafHash[:])

	packet := &EvidencePacket{
		FileHash:   hex.EncodeToString(fileHash[:]),
		MerklePath: []ProofStep{},
		Peaks:      []string{hex.EncodeToString(leafHash[:])},
		PeakPos:    0,
		MMRRoot:    hex.EncodeToString(leafHash[:]),
		PublicKey:  hex.EncodeToString(pub),
		Signature:  hex.EncodeToString(signature),
	}

	err := VerifyEvidence(packet, pub)
	if err != nil {
		t.Fatalf("VerifyEvidence with signature failed: %v", err)
	}
}

func TestVerifyEvidenceInvalidSignature(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)

	fileHash := sha256.Sum256([]byte("test"))
	leafHash := mmr.HashLeaf(fileHash[:])

	packet := &EvidencePacket{
		FileHash:   hex.EncodeToString(fileHash[:]),
		MerklePath: []ProofStep{},
		Peaks:      []string{hex.EncodeToString(leafHash[:])},
		PeakPos:    0,
		MMRRoot:    hex.EncodeToString(leafHash[:]),
		PublicKey:  hex.EncodeToString(pub),
		Signature:  hex.EncodeToString(make([]byte, 64)), // Invalid signature
	}

	err := VerifyEvidence(packet, pub)
	if err != ErrSignatureInvalid {
		t.Errorf("expected ErrSignatureInvalid, got %v", err)
	}
}

func TestVerifyEvidenceInvalidSignatureHex(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)

	fileHash := sha256.Sum256([]byte("test"))
	leafHash := mmr.HashLeaf(fileHash[:])

	packet := &EvidencePacket{
		FileHash:   hex.EncodeToString(fileHash[:]),
		MerklePath: []ProofStep{},
		Peaks:      []string{hex.EncodeToString(leafHash[:])},
		PeakPos:    0,
		MMRRoot:    hex.EncodeToString(leafHash[:]),
		Signature:  "invalid_hex",
	}

	err := VerifyEvidence(packet, pub)
	if err == nil {
		t.Error("expected error for invalid signature hex")
	}
}

func TestVerifyEvidenceInvalidRootHex(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)

	fileHash := sha256.Sum256([]byte("test"))
	leafHash := mmr.HashLeaf(fileHash[:])
	signature := ed25519.Sign(priv, leafHash[:])

	packet := &EvidencePacket{
		FileHash:   hex.EncodeToString(fileHash[:]),
		MerklePath: []ProofStep{},
		Peaks:      []string{hex.EncodeToString(leafHash[:])},
		PeakPos:    0,
		MMRRoot:    "invalid_hex",
		Signature:  hex.EncodeToString(signature),
	}

	err := VerifyEvidence(packet, pub)
	if err == nil {
		t.Error("expected error for invalid root hex")
	}
}

// =============================================================================
// Tests for Result struct
// =============================================================================

func TestResultJSON(t *testing.T) {
	result := &Result{
		Path:          "/test/file.txt",
		CurrentHash:   "abc123",
		WitnessedHash: "abc123",
		MMRIndex:      42,
		MMRRoot:       "def456",
		Timestamp:     time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC),
		Valid:         true,
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded Result
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.Path != result.Path {
		t.Errorf("path mismatch: expected %s, got %s", result.Path, decoded.Path)
	}
	if decoded.MMRIndex != result.MMRIndex {
		t.Errorf("MMRIndex mismatch: expected %d, got %d", result.MMRIndex, decoded.MMRIndex)
	}
	if decoded.Valid != result.Valid {
		t.Errorf("Valid mismatch: expected %v, got %v", result.Valid, decoded.Valid)
	}
}

func TestResultWithError(t *testing.T) {
	result := &Result{
		Path:  "/test/file.txt",
		Valid: false,
		Error: "file not found",
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded Result
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.Error != "file not found" {
		t.Errorf("error mismatch: expected %q, got %q", "file not found", decoded.Error)
	}
}

// =============================================================================
// Tests for EvidencePacket struct
// =============================================================================

func TestEvidencePacketJSON(t *testing.T) {
	packet := &EvidencePacket{
		Version:     1,
		GeneratedAt: time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC),
		FilePath:    "/test/file.txt",
		FileHash:    "abc123",
		FileSize:    1024,
		MMRIndex:    5,
		MMRSize:     10,
		MMRRoot:     "root123",
		MerklePath: []ProofStep{
			{Hash: "sibling1", IsLeft: true},
			{Hash: "sibling2", IsLeft: false},
		},
		Peaks:     []string{"peak1", "peak2"},
		PeakPos:   0,
		PublicKey: "pubkey",
		Signature: "sig",
		Anchors: []AnchorProof{
			{Type: "ots", Timestamp: time.Now().UTC(), Proof: "proofdata"},
		},
	}

	data, err := json.Marshal(packet)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded EvidencePacket
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.Version != 1 {
		t.Errorf("version mismatch")
	}
	if decoded.FilePath != "/test/file.txt" {
		t.Errorf("file path mismatch")
	}
	if len(decoded.MerklePath) != 2 {
		t.Errorf("merkle path length mismatch")
	}
	if len(decoded.Anchors) != 1 {
		t.Errorf("anchors length mismatch")
	}
}

// =============================================================================
// Tests for error constants
// =============================================================================

func TestErrorMessages(t *testing.T) {
	errors := []error{
		ErrFileNotFound,
		ErrHashMismatch,
		ErrProofInvalid,
		ErrSignatureInvalid,
	}

	for _, e := range errors {
		if e.Error() == "" {
			t.Errorf("error %v should have non-empty message", e)
		}
	}
}

// =============================================================================
// Integration-like tests for NewVerifier
// =============================================================================

func TestNewVerifierMissingDB(t *testing.T) {
	_, err := NewVerifier("/nonexistent/path.db", "", "")
	if err == nil {
		t.Error("expected error for missing database")
	}
}

func TestNewVerifierMissingPubKey(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "mmr.db")

	// Create a valid database
	store, err := mmr.OpenFileStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	m, err := mmr.New(store)
	if err != nil {
		store.Close()
		t.Fatalf("failed to create mmr: %v", err)
	}
	if _, err := m.Append([]byte("test")); err != nil {
		store.Close()
		t.Fatalf("failed to append: %v", err)
	}
	store.Close()

	_, err = NewVerifier(dbPath, "/nonexistent/key.pub", "")
	if err == nil {
		t.Error("expected error for missing public key")
	}
}

func TestNewVerifierValid(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "mmr.db")
	pubKeyPath := filepath.Join(tmpDir, "key.pub")

	// Create a valid database
	store, err := mmr.OpenFileStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	m, err := mmr.New(store)
	if err != nil {
		store.Close()
		t.Fatalf("failed to create mmr: %v", err)
	}
	if _, err := m.Append([]byte("test")); err != nil {
		store.Close()
		t.Fatalf("failed to append: %v", err)
	}
	store.Close()

	// Create public key
	pub, _, _ := ed25519.GenerateKey(nil)
	if err := os.WriteFile(pubKeyPath, pub, 0600); err != nil {
		t.Fatalf("failed to write public key: %v", err)
	}

	v, err := NewVerifier(dbPath, pubKeyPath, "")
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}
	defer v.Close()

	if v.mmr == nil {
		t.Error("mmr should not be nil")
	}
	if v.pubKey == nil {
		t.Error("pubKey should not be nil")
	}
}

func TestVerifierClose(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "mmr.db")
	pubKeyPath := filepath.Join(tmpDir, "key.pub")

	// Create a valid database
	store, err := mmr.OpenFileStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	m, err := mmr.New(store)
	if err != nil {
		store.Close()
		t.Fatalf("failed to create mmr: %v", err)
	}
	if _, err := m.Append([]byte("test")); err != nil {
		store.Close()
		t.Fatalf("failed to append: %v", err)
	}
	store.Close()

	// Create public key
	pub, _, _ := ed25519.GenerateKey(nil)
	if err := os.WriteFile(pubKeyPath, pub, 0600); err != nil {
		t.Fatalf("failed to write public key: %v", err)
	}

	v, err := NewVerifier(dbPath, pubKeyPath, "")
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}

	err = v.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

// =============================================================================
// Tests for SignatureEntry struct
// =============================================================================

func TestSignatureEntry(t *testing.T) {
	entry := SignatureEntry{
		Timestamp: time.Now(),
		Root:      sha256.Sum256([]byte("root")),
		Signature: make([]byte, 64),
		Size:      100,
	}

	if entry.Size != 100 {
		t.Errorf("expected size 100, got %d", entry.Size)
	}
	if entry.Timestamp.IsZero() {
		t.Error("timestamp should not be zero")
	}
}
