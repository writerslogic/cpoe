//go:build integration

// Package integration provides comprehensive end-to-end integration tests for witnessd.
//
// These tests verify the complete flow from document monitoring through
// evidence packet creation and verification.
//
// Run with: go test -tags=integration ./tests/integration/...
package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"witnessd/internal/checkpoint"
	"witnessd/internal/declaration"
	"witnessd/internal/evidence"
	"witnessd/internal/forensics"
	"witnessd/internal/hardware"
	"witnessd/internal/jitter"
	"witnessd/internal/keyhierarchy"
	"witnessd/internal/tracking"
	"witnessd/internal/vdf"
	"witnessd/internal/wal"
	"witnessd/pkg/anchors"
)

// =============================================================================
// Test Environment Setup
// =============================================================================

// TestEnv holds all the components needed for integration testing.
type TestEnv struct {
	T            *testing.T
	TempDir      string
	WitnessdDir  string
	DocumentPath string
	DocumentID   string

	// Key hierarchy components
	PUF            hardware.PUF
	MasterIdentity *keyhierarchy.MasterIdentity
	Session        *keyhierarchy.Session

	// Checkpoint chain
	Chain     *checkpoint.Chain
	VDFParams vdf.Parameters

	// WAL
	WAL     *wal.WAL
	HMACKey []byte

	// Tracking
	TrackingSession *tracking.Session

	// Anchors
	AnchorRegistry *anchors.Registry

	// Context for operations
	Ctx    context.Context
	Cancel context.CancelFunc
}

// NewTestEnv creates a fully initialized test environment.
func NewTestEnv(t *testing.T) *TestEnv {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)

	tempDir := t.TempDir()
	witnessdDir := filepath.Join(tempDir, ".witnessd")
	if err := os.MkdirAll(witnessdDir, 0700); err != nil {
		t.Fatalf("failed to create witnessd dir: %v", err)
	}

	// Create subdirectories
	for _, subdir := range []string{"chains", "wal", "tracking", "keys", "evidence"} {
		if err := os.MkdirAll(filepath.Join(witnessdDir, subdir), 0700); err != nil {
			t.Fatalf("failed to create %s dir: %v", subdir, err)
		}
	}

	// Create test document
	docPath := filepath.Join(tempDir, "test_document.md")
	initialContent := "# Test Document\n\nThis is the initial content.\n"
	if err := os.WriteFile(docPath, []byte(initialContent), 0600); err != nil {
		t.Fatalf("failed to create test document: %v", err)
	}

	// Generate document ID
	absPath, _ := filepath.Abs(docPath)
	pathHash := sha256.Sum256([]byte(absPath))
	docID := hex.EncodeToString(pathHash[:8])

	// Create VDF parameters (fast for testing)
	vdfParams := vdf.Parameters{
		IterationsPerSecond: 100000,
		MinIterations:       100,
		MaxIterations:       1000000,
	}

	// Generate HMAC key for WAL
	hmacKey := make([]byte, 32)
	if _, err := rand.Read(hmacKey); err != nil {
		t.Fatalf("failed to generate HMAC key: %v", err)
	}

	env := &TestEnv{
		T:            t,
		TempDir:      tempDir,
		WitnessdDir:  witnessdDir,
		DocumentPath: docPath,
		DocumentID:   docID,
		VDFParams:    vdfParams,
		HMACKey:      hmacKey,
		Ctx:          ctx,
		Cancel:       cancel,
	}

	return env
}

// InitPUF initializes a software PUF for testing.
func (env *TestEnv) InitPUF() {
	env.T.Helper()

	config := hardware.DefaultSRAMPUFConfig()
	config.Repetitions = 3 // Fast for testing

	puf, err := hardware.NewSRAMPUF(config)
	if err != nil {
		env.T.Fatalf("failed to create PUF: %v", err)
	}

	env.PUF = puf
}

// InitKeyHierarchy initializes the key hierarchy with master identity.
func (env *TestEnv) InitKeyHierarchy() {
	env.T.Helper()

	if env.PUF == nil {
		env.InitPUF()
	}

	// Create a mock PUF provider that wraps our PUF
	provider := &mockPUFProvider{puf: env.PUF}

	identity, err := keyhierarchy.DeriveMasterIdentity(provider)
	if err != nil {
		env.T.Fatalf("failed to derive master identity: %v", err)
	}
	env.MasterIdentity = identity

	// Read document hash
	content, err := os.ReadFile(env.DocumentPath)
	if err != nil {
		env.T.Fatalf("failed to read document: %v", err)
	}
	docHash := sha256.Sum256(content)

	// Start session
	session, err := keyhierarchy.StartSession(provider, docHash)
	if err != nil {
		env.T.Fatalf("failed to start session: %v", err)
	}
	env.Session = session
}

// InitChain initializes the checkpoint chain.
func (env *TestEnv) InitChain() {
	env.T.Helper()

	chain, err := checkpoint.NewChain(env.DocumentPath, env.VDFParams)
	if err != nil {
		env.T.Fatalf("failed to create chain: %v", err)
	}
	env.Chain = chain
}

// InitWAL initializes the write-ahead log.
func (env *TestEnv) InitWAL() {
	env.T.Helper()

	var sessionID [32]byte
	if env.Session != nil {
		sessionID = env.Session.Certificate.SessionID
	} else {
		rand.Read(sessionID[:])
	}

	walPath := filepath.Join(env.WitnessdDir, "wal", env.DocumentID+".wal")
	w, err := wal.Open(walPath, sessionID, env.HMACKey)
	if err != nil {
		env.T.Fatalf("failed to open WAL: %v", err)
	}
	env.WAL = w
}

// InitTracking initializes keystroke tracking.
func (env *TestEnv) InitTracking() {
	env.T.Helper()

	cfg := tracking.DefaultConfig(env.DocumentPath)
	cfg.Simulated = true // Use simulated keystroke counter
	cfg.JitterParams = jitter.DefaultParameters()

	session, err := tracking.NewSession(cfg)
	if err != nil {
		env.T.Fatalf("failed to create tracking session: %v", err)
	}
	env.TrackingSession = session
}

// InitAnchors initializes the anchor registry with mock provider.
func (env *TestEnv) InitAnchors() {
	env.T.Helper()

	registry := anchors.NewRegistry()
	// Register mock provider for testing
	registry.RegisterProvider(&mockAnchorProvider{})
	registry.Enable("mock", nil)

	env.AnchorRegistry = registry
}

// InitAll initializes all components.
func (env *TestEnv) InitAll() {
	env.InitPUF()
	env.InitKeyHierarchy()
	env.InitChain()
	env.InitWAL()
	env.InitTracking()
	env.InitAnchors()
}

// Cleanup closes all resources.
func (env *TestEnv) Cleanup() {
	env.Cancel()

	if env.Session != nil {
		env.Session.End()
	}
	if env.WAL != nil {
		env.WAL.Close()
	}
	if env.TrackingSession != nil {
		env.TrackingSession.Stop()
	}
}

// ModifyDocument appends content to the test document.
func (env *TestEnv) ModifyDocument(content string) {
	env.T.Helper()

	existing, err := os.ReadFile(env.DocumentPath)
	if err != nil {
		env.T.Fatalf("failed to read document: %v", err)
	}

	newContent := append(existing, []byte(content)...)
	if err := os.WriteFile(env.DocumentPath, newContent, 0600); err != nil {
		env.T.Fatalf("failed to write document: %v", err)
	}
}

// GetDocumentHash returns the current document hash.
func (env *TestEnv) GetDocumentHash() [32]byte {
	env.T.Helper()

	content, err := os.ReadFile(env.DocumentPath)
	if err != nil {
		env.T.Fatalf("failed to read document: %v", err)
	}
	return sha256.Sum256(content)
}

// CreateCheckpoint creates a checkpoint with the current document state.
func (env *TestEnv) CreateCheckpoint(message string) *checkpoint.Checkpoint {
	env.T.Helper()

	cp, err := env.Chain.Commit(message)
	if err != nil {
		env.T.Fatalf("failed to create checkpoint: %v", err)
	}
	return cp
}

// SignCheckpoint signs a checkpoint using the key hierarchy.
func (env *TestEnv) SignCheckpoint(cp *checkpoint.Checkpoint) *keyhierarchy.CheckpointSignature {
	env.T.Helper()

	sig, err := env.Session.SignCheckpoint(cp.Hash)
	if err != nil {
		env.T.Fatalf("failed to sign checkpoint: %v", err)
	}
	return sig
}

// WriteWALEntry writes an entry to the WAL.
func (env *TestEnv) WriteWALEntry(entryType wal.EntryType, payload []byte) {
	env.T.Helper()

	if err := env.WAL.Append(entryType, payload); err != nil {
		env.T.Fatalf("failed to write WAL entry: %v", err)
	}
}

// =============================================================================
// Mock Implementations
// =============================================================================

// mockPUFProvider wraps a hardware.PUF for keyhierarchy.
type mockPUFProvider struct {
	puf      hardware.PUF
	deviceID string
}

func (m *mockPUFProvider) GetResponse(challenge []byte) ([]byte, error) {
	return m.puf.Challenge(challenge)
}

func (m *mockPUFProvider) DeviceID() string {
	if m.deviceID == "" {
		return "test-device-001"
	}
	return m.deviceID
}

// mockAnchorProvider provides a mock timestamp anchor for testing.
type mockAnchorProvider struct {
	timestamps []*anchors.Proof
}

func (m *mockAnchorProvider) Name() string {
	return "mock"
}

func (m *mockAnchorProvider) Timestamp(ctx context.Context, hash [32]byte) (*anchors.Proof, error) {
	proof := &anchors.Proof{
		Provider:  "mock",
		Hash:      hash,
		Timestamp: time.Now(),
		Status:    anchors.StatusConfirmed,
		RawProof:  []byte("mock-proof-data"),
		VerifyURL: "https://mock.example.com/verify",
	}
	m.timestamps = append(m.timestamps, proof)
	return proof, nil
}

func (m *mockAnchorProvider) Verify(ctx context.Context, proof *anchors.Proof) (*anchors.VerifyResult, error) {
	return &anchors.VerifyResult{
		Valid:     true,
		Timestamp: proof.Timestamp,
		Hash:      proof.Hash,
	}, nil
}

func (m *mockAnchorProvider) Upgrade(ctx context.Context, proof *anchors.Proof) (*anchors.Proof, error) {
	return proof, nil
}

func (m *mockAnchorProvider) Status(ctx context.Context) (*anchors.ProviderStatus, error) {
	return &anchors.ProviderStatus{
		Available:  true,
		Configured: true,
		LastCheck:  time.Now(),
	}, nil
}

func (m *mockAnchorProvider) Configure(config map[string]interface{}) error {
	return nil
}

func (m *mockAnchorProvider) Regions() []string {
	return []string{"GLOBAL"}
}

func (m *mockAnchorProvider) RequiresPayment() bool {
	return false
}

func (m *mockAnchorProvider) LegalStanding() anchors.LegalStanding {
	return anchors.StandingNone
}

// =============================================================================
// Test Data Generators
// =============================================================================

// GenerateKeystrokeEvents generates simulated keystroke events for testing.
func GenerateKeystrokeEvents(count int, startTime time.Time) []forensics.EventData {
	events := make([]forensics.EventData, count)
	currentTime := startTime

	for i := 0; i < count; i++ {
		// Random interval between 100ms and 2s
		interval := time.Duration(100+i*50) * time.Millisecond
		currentTime = currentTime.Add(interval)

		delta := int32(1) // Usually insertions
		if i%7 == 0 {
			delta = -1 // Occasional deletion
		}

		events[i] = forensics.EventData{
			ID:          int64(i + 1),
			TimestampNs: currentTime.UnixNano(),
			FileSize:    int64(100 + i*10),
			SizeDelta:   delta,
			FilePath:    "/test/document.md",
		}
	}

	return events
}

// GenerateRegionData generates edit region data for forensic analysis.
func GenerateRegionData(events []forensics.EventData) map[int64][]forensics.RegionData {
	regions := make(map[int64][]forensics.RegionData)

	for _, event := range events {
		// Simulate realistic editing patterns (mostly appends with some edits)
		startPct := float32(0.95) // Default to appending
		if event.ID%5 == 0 {
			startPct = float32(event.ID%100) / 100.0 // Some mid-document edits
		}

		regions[event.ID] = []forensics.RegionData{
			{
				StartPct:  startPct,
				EndPct:    startPct + 0.01,
				DeltaSign: int8(event.SizeDelta),
				ByteCount: 10,
			},
		}
	}

	return regions
}

// GenerateTestDeclaration creates a test declaration for evidence packets.
func GenerateTestDeclaration(t *testing.T, contentHash, chainHash [32]byte, title string) *declaration.Declaration {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	decl, err := declaration.NewDeclaration(contentHash, chainHash, title).
		AddModality(declaration.ModalityKeyboard, 100, "").
		WithStatement("I wrote this content myself").
		Sign(priv)

	if err != nil {
		t.Fatalf("failed to create declaration: %v", err)
	}

	return decl
}

// GenerateTestDeclarationWithAI creates a declaration that includes AI assistance.
func GenerateTestDeclarationWithAI(t *testing.T, contentHash, chainHash [32]byte, title string) *declaration.Declaration {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	decl, err := declaration.NewDeclaration(contentHash, chainHash, title).
		AddModality(declaration.ModalityKeyboard, 80, "").
		AddModality(declaration.ModalityDictation, 20, "").
		AddAITool("Claude", "3.5", declaration.PurposeResearch, "Research assistance", declaration.ExtentMinor).
		WithStatement("I wrote this with AI assistance for research").
		Sign(priv)

	if err != nil {
		t.Fatalf("failed to create declaration: %v", err)
	}

	return decl
}

// =============================================================================
// Assertion Helpers
// =============================================================================

// AssertNoError fails the test if err is not nil.
func AssertNoError(t *testing.T, err error, msg string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", msg, err)
	}
}

// AssertError fails the test if err is nil.
func AssertError(t *testing.T, err error, msg string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected error but got nil", msg)
	}
}

// AssertEqual fails the test if expected != actual.
func AssertEqual[T comparable](t *testing.T, expected, actual T, msg string) {
	t.Helper()
	if expected != actual {
		t.Fatalf("%s: expected %v, got %v", msg, expected, actual)
	}
}

// AssertNotEqual fails the test if expected == actual.
func AssertNotEqual[T comparable](t *testing.T, expected, actual T, msg string) {
	t.Helper()
	if expected == actual {
		t.Fatalf("%s: expected values to differ, both were %v", msg, actual)
	}
}

// AssertTrue fails the test if condition is false.
func AssertTrue(t *testing.T, condition bool, msg string) {
	t.Helper()
	if !condition {
		t.Fatalf("%s: expected true", msg)
	}
}

// AssertFalse fails the test if condition is true.
func AssertFalse(t *testing.T, condition bool, msg string) {
	t.Helper()
	if condition {
		t.Fatalf("%s: expected false", msg)
	}
}

// AssertValidEvidencePacket verifies an evidence packet has required fields.
func AssertValidEvidencePacket(t *testing.T, packet *evidence.Packet) {
	t.Helper()

	AssertTrue(t, packet != nil, "packet should not be nil")
	AssertTrue(t, packet.Version > 0, "packet should have version")
	AssertTrue(t, !packet.GeneratedAt.IsZero(), "packet should have generation time")
	AssertTrue(t, packet.Declaration != nil, "packet should have declaration")
	AssertTrue(t, len(packet.Checkpoints) > 0, "packet should have checkpoints")
	AssertTrue(t, len(packet.Claims) > 0, "packet should have claims")
}
