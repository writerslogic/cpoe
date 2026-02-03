package hardware

import (
	"crypto/sha256"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestContinuousAttestationSession(t *testing.T) {
	tpm := NewMockTPM()

	config := DefaultAttestationConfig()
	config.CheckpointInterval = 100 * time.Millisecond
	config.KeystrokeThreshold = 5

	session, err := NewContinuousAttestationSession(config, tpm)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	if err := session.Start(); err != nil {
		t.Fatalf("Failed to start session: %v", err)
	}

	// Record some keystrokes
	for i := 0; i < 10; i++ {
		contentHash := sha256.Sum256([]byte{byte(i)})
		timingData := []byte{byte(i * 10)}

		if err := session.RecordKeystroke(contentHash, timingData); err != nil {
			t.Fatalf("RecordKeystroke failed: %v", err)
		}
	}

	// Get chain
	chain := session.GetChain()
	if len(chain) < 2 { // Initial + at least one from keystrokes
		t.Errorf("Expected at least 2 checkpoints, got %d", len(chain))
	}

	// Verify chain has proper sequence numbers
	for i, cp := range chain {
		if cp.SequenceNumber != uint64(i) {
			t.Errorf("Checkpoint %d has sequence %d", i, cp.SequenceNumber)
		}
	}

	session.Stop()
}

func TestAttestationChainIntegrity(t *testing.T) {
	tpm := NewMockTPM()

	config := DefaultAttestationConfig()
	config.KeystrokeThreshold = 3

	session, err := NewContinuousAttestationSession(config, tpm)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	if err := session.Start(); err != nil {
		t.Fatalf("Failed to start session: %v", err)
	}

	// Create multiple checkpoints
	for i := 0; i < 15; i++ {
		contentHash := sha256.Sum256([]byte{byte(i)})
		session.RecordKeystroke(contentHash, nil)
	}

	chain := session.GetChain()
	session.Stop()

	// Verify chain integrity
	var prevHash [32]byte
	for i, cp := range chain {
		if i > 0 && cp.PreviousHash != prevHash {
			t.Errorf("Chain broken at checkpoint %d", i)
		}
		prevHash = cp.CheckpointHash
	}
}

func TestAttestationMonotonicCounter(t *testing.T) {
	tpm := NewMockTPM()

	config := DefaultAttestationConfig()
	config.KeystrokeThreshold = 2

	session, err := NewContinuousAttestationSession(config, tpm)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	session.Start()

	// Create checkpoints
	for i := 0; i < 10; i++ {
		contentHash := sha256.Sum256([]byte{byte(i)})
		session.RecordKeystroke(contentHash, nil)
	}

	chain := session.GetChain()
	session.Stop()

	// Verify monotonic counter
	var lastCounter uint64
	for i, cp := range chain {
		if cp.TPMCounter <= lastCounter && i > 0 {
			t.Errorf("Counter not monotonic at checkpoint %d: %d <= %d",
				i, cp.TPMCounter, lastCounter)
		}
		lastCounter = cp.TPMCounter
	}
}

func TestAttestationVerifier(t *testing.T) {
	tpm := NewMockTPM()

	config := DefaultAttestationConfig()
	config.KeystrokeThreshold = 3

	session, err := NewContinuousAttestationSession(config, tpm)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	session.Start()

	// Create checkpoints
	for i := 0; i < 12; i++ {
		contentHash := sha256.Sum256([]byte{byte(i)})
		session.RecordKeystroke(contentHash, nil)
	}

	export := session.ExportSession()
	session.Stop()

	// Verify
	verifier := NewAttestationVerifier()
	result, err := verifier.VerifyChain(export)
	if err != nil {
		t.Fatalf("Verification error: %v", err)
	}

	if !result.Valid {
		t.Errorf("Chain should be valid, errors: %v", result.Errors)
	}

	t.Logf("Verified %d checkpoints", result.CheckpointsVerified)
}

func TestAttestationWithPUF(t *testing.T) {
	tpm := NewMockTPM()
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())

	config := DefaultAttestationConfig()
	config.KeystrokeThreshold = 5

	session, err := NewContinuousAttestationSession(config, tpm)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	session.SetPUF(puf)
	session.Start()

	// Create checkpoints
	for i := 0; i < 10; i++ {
		contentHash := sha256.Sum256([]byte{byte(i)})
		session.RecordKeystroke(contentHash, nil)
	}

	chain := session.GetChain()
	session.Stop()

	// Verify PUF responses are present
	hasPUF := false
	for _, cp := range chain {
		if cp.PUFResponse != nil && len(cp.PUFResponse) > 0 {
			hasPUF = true
			break
		}
	}

	if !hasPUF {
		t.Error("Expected PUF responses in checkpoints")
	}
}

func TestAttestationCallback(t *testing.T) {
	tpm := NewMockTPM()

	config := DefaultAttestationConfig()
	config.KeystrokeThreshold = 3

	session, err := NewContinuousAttestationSession(config, tpm)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	var callbackCount int64
	session.SetCheckpointCallback(func(cp *AttestationCheckpoint) {
		atomic.AddInt64(&callbackCount, 1)
	})

	session.Start()

	// Create checkpoints
	for i := 0; i < 9; i++ {
		contentHash := sha256.Sum256([]byte{byte(i)})
		session.RecordKeystroke(contentHash, nil)
	}

	// Wait for callbacks
	time.Sleep(100 * time.Millisecond)

	session.Stop()

	if atomic.LoadInt64(&callbackCount) < 2 {
		t.Errorf("Expected at least 2 callbacks, got %d", atomic.LoadInt64(&callbackCount))
	}
}

func TestForceCheckpoint(t *testing.T) {
	tpm := NewMockTPM()

	config := DefaultAttestationConfig()
	config.KeystrokeThreshold = 100 // High threshold

	session, err := NewContinuousAttestationSession(config, tpm)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	session.Start()

	// Force a checkpoint
	contentHash := sha256.Sum256([]byte("forced"))
	if err := session.ForceCheckpoint(contentHash, []byte("timing")); err != nil {
		t.Fatalf("ForceCheckpoint failed: %v", err)
	}

	chain := session.GetChain()
	session.Stop()

	if len(chain) < 2 { // Initial + forced
		t.Errorf("Expected at least 2 checkpoints, got %d", len(chain))
	}

	// Last checkpoint should have our content hash
	last := chain[len(chain)-1]
	if last.ContentHash != contentHash {
		t.Error("Forced checkpoint doesn't have expected content hash")
	}
}

func TestAttestationSessionExport(t *testing.T) {
	tpm := NewMockTPM()

	config := DefaultAttestationConfig()
	config.KeystrokeThreshold = 5

	session, err := NewContinuousAttestationSession(config, tpm)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	session.Start()

	for i := 0; i < 10; i++ {
		contentHash := sha256.Sum256([]byte{byte(i)})
		session.RecordKeystroke(contentHash, nil)
	}

	export := session.ExportSession()
	session.Stop()

	if export.SessionID == [32]byte{} {
		t.Error("Export should have session ID")
	}

	if export.SessionStart.IsZero() {
		t.Error("Export should have session start time")
	}

	if export.KeystrokeCount != 10 {
		t.Errorf("Expected 10 keystrokes, got %d", export.KeystrokeCount)
	}

	if len(export.Checkpoints) == 0 {
		t.Error("Export should have checkpoints")
	}

	if export.FinalCounter == 0 {
		t.Error("Export should have final counter value")
	}
}

func TestVerifierDetectsTampering(t *testing.T) {
	tpm := NewMockTPM()

	config := DefaultAttestationConfig()
	config.KeystrokeThreshold = 3

	session, err := NewContinuousAttestationSession(config, tpm)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	session.Start()

	for i := 0; i < 12; i++ {
		contentHash := sha256.Sum256([]byte{byte(i)})
		session.RecordKeystroke(contentHash, nil)
	}

	export := session.ExportSession()
	session.Stop()

	// Tamper with a checkpoint
	if len(export.Checkpoints) > 2 {
		export.Checkpoints[2].KeystrokeCount = 999
	}

	// Verify should fail
	verifier := NewAttestationVerifier()
	result, err := verifier.VerifyChain(export)
	if err != nil {
		t.Fatalf("Verification error: %v", err)
	}

	if result.Valid {
		t.Error("Tampered chain should not be valid")
	}

	if len(result.Errors) == 0 {
		t.Error("Should have error messages")
	}
}

func TestMockTPM(t *testing.T) {
	tpm := NewMockTPM()

	// Test availability
	if !tpm.IsAvailable() {
		t.Error("Mock TPM should be available")
	}

	// Test counter
	c1, _ := tpm.IncrementCounter(0)
	c2, _ := tpm.IncrementCounter(0)
	if c2 <= c1 {
		t.Error("Counter should be monotonic")
	}

	// Test PCR operations
	pcr0, err := tpm.ReadPCR(0)
	if err != nil {
		t.Fatalf("ReadPCR failed: %v", err)
	}

	if err := tpm.ExtendPCR(0, []byte("data")); err != nil {
		t.Fatalf("ExtendPCR failed: %v", err)
	}

	pcr0After, _ := tpm.ReadPCR(0)
	if string(pcr0) == string(pcr0After) {
		t.Error("PCR should change after extend")
	}

	// Test quote
	nonce := make([]byte, 32)
	quote, err := tpm.Quote(nonce, []int{0, 1})
	if err != nil {
		t.Fatalf("Quote failed: %v", err)
	}

	if len(quote.RawQuote) == 0 {
		t.Error("Quote data should not be empty")
	}
	if len(quote.Signature) == 0 {
		t.Error("Signature should not be empty")
	}

	// Test seal/unseal
	data := []byte("secret data")
	sealed, err := tpm.Seal(data, []int{0})
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	unsealed, err := tpm.Unseal(sealed)
	if err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}

	if string(unsealed) != string(data) {
		t.Error("Unsealed data doesn't match original")
	}

	// Test random
	random, err := tpm.GetRandom(32)
	if err != nil {
		t.Fatalf("GetRandom failed: %v", err)
	}
	if len(random) != 32 {
		t.Errorf("Expected 32 random bytes, got %d", len(random))
	}
}

func TestErrorCallback(t *testing.T) {
	tpm := NewMockTPM()

	config := DefaultAttestationConfig()
	config.KeystrokeThreshold = 100 // High threshold so we don't auto-create checkpoints

	session, err := NewContinuousAttestationSession(config, tpm)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	var errorReceived atomic.Value
	session.SetErrorCallback(func(err error) {
		errorReceived.Store(err)
	})

	// Verify callback was set
	session.mu.RLock()
	hasCallback := session.onError != nil
	session.mu.RUnlock()

	if !hasCallback {
		t.Error("Error callback should be set")
	}

	session.Stop()
}

func TestDoubleStop(t *testing.T) {
	tpm := NewMockTPM()

	config := DefaultAttestationConfig()
	session, err := NewContinuousAttestationSession(config, tpm)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	session.Start()

	// Stop should be safe to call multiple times
	session.Stop()
	session.Stop() // Should not panic
	session.Stop() // Should not panic
}

func TestComputeCheckpointHash(t *testing.T) {
	// Test that the exported hash function works correctly
	checkpoint := &AttestationCheckpoint{
		SessionID:      [32]byte{1, 2, 3},
		SequenceNumber: 42,
		TPMCounter:     100,
		KeystrokeCount: 500,
	}

	hash1 := ComputeCheckpointHash(checkpoint)
	hash2 := ComputeCheckpointHash(checkpoint)

	// Same input should produce same hash
	if hash1 != hash2 {
		t.Error("Same checkpoint should produce same hash")
	}

	// Different input should produce different hash
	checkpoint.SequenceNumber = 43
	hash3 := ComputeCheckpointHash(checkpoint)

	if hash1 == hash3 {
		t.Error("Different checkpoint should produce different hash")
	}
}

func TestGetLastCheckpoint(t *testing.T) {
	tpm := NewMockTPM()

	config := DefaultAttestationConfig()
	config.KeystrokeThreshold = 5

	session, err := NewContinuousAttestationSession(config, tpm)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Before start, should be nil
	if session.GetLastCheckpoint() != nil {
		t.Error("Expected nil checkpoint before start")
	}

	session.Start()

	// After start, should have initial checkpoint
	if session.GetLastCheckpoint() == nil {
		t.Error("Expected checkpoint after start")
	}

	// Record keystrokes to create more checkpoints
	for i := 0; i < 10; i++ {
		contentHash := sha256.Sum256([]byte{byte(i)})
		session.RecordKeystroke(contentHash, nil)
	}

	lastCP := session.GetLastCheckpoint()
	if lastCP == nil {
		t.Error("Expected checkpoint after keystrokes")
	}

	// Verify it's actually the last one
	chain := session.GetChain()
	if lastCP.SequenceNumber != chain[len(chain)-1].SequenceNumber {
		t.Error("GetLastCheckpoint should return the last checkpoint in chain")
	}

	session.Stop()
}

func TestAttestationVerifierTrustedValues(t *testing.T) {
	verifier := NewAttestationVerifier()

	// Test AddTrustedAK
	ak1 := []byte("attestation-key-1")
	ak2 := []byte("attestation-key-2")
	verifier.AddTrustedAK(ak1)
	verifier.AddTrustedAK(ak2)

	if len(verifier.TrustedAKs) != 2 {
		t.Errorf("Expected 2 trusted AKs, got %d", len(verifier.TrustedAKs))
	}

	// Test AddTrustedPCRValue
	pcr0val1 := make([]byte, 32)
	pcr0val2 := []byte("alternative-pcr0-value")
	pcr7val := []byte("pcr7-value")

	verifier.AddTrustedPCRValue(0, pcr0val1)
	verifier.AddTrustedPCRValue(0, pcr0val2) // Multiple values for same PCR
	verifier.AddTrustedPCRValue(7, pcr7val)

	if len(verifier.TrustedPCRValues[0]) != 2 {
		t.Errorf("Expected 2 values for PCR0, got %d", len(verifier.TrustedPCRValues[0]))
	}
	if len(verifier.TrustedPCRValues[7]) != 1 {
		t.Errorf("Expected 1 value for PCR7, got %d", len(verifier.TrustedPCRValues[7]))
	}
}

func TestMockTPMReadPCRs(t *testing.T) {
	tpm := NewMockTPM()

	// Test ReadPCRs
	pcrs, err := tpm.ReadPCRs([]int{0, 1, 7})
	if err != nil {
		t.Fatalf("ReadPCRs failed: %v", err)
	}

	if len(pcrs) != 3 {
		t.Errorf("Expected 3 PCRs, got %d", len(pcrs))
	}

	// Verify each PCR was read
	for _, idx := range []int{0, 1, 7} {
		if _, ok := pcrs[idx]; !ok {
			t.Errorf("Missing PCR %d", idx)
		}
	}

	// Test reading non-existent PCR
	_, err = tpm.ReadPCR(99)
	if err == nil {
		t.Error("Expected error for non-existent PCR")
	}
}

func TestMockTPMExtendPCRError(t *testing.T) {
	tpm := NewMockTPM()

	// Test extending non-existent PCR
	err := tpm.ExtendPCR(99, []byte("data"))
	if err == nil {
		t.Error("Expected error for non-existent PCR")
	}
}

func TestMockTPMUnsealError(t *testing.T) {
	tpm := NewMockTPM()

	// Test unsealing invalid data (too short)
	_, err := tpm.Unseal([]byte("short"))
	if err == nil {
		t.Error("Expected error for invalid sealed data")
	}
}

func TestNewContinuousAttestationSessionErrors(t *testing.T) {
	// Test with nil TPM
	_, err := NewContinuousAttestationSession(DefaultAttestationConfig(), nil)
	if err != ErrTPMNotAvailable {
		t.Errorf("Expected ErrTPMNotAvailable, got %v", err)
	}
}

func TestCreateCheckpointCounterMismatch(t *testing.T) {
	// This test requires a custom TPM that returns decreasing counters
	// which would trigger ErrCounterMismatch
	// The mock TPM always increments, so we'll test the path through verification
	tpm := NewMockTPM()

	config := DefaultAttestationConfig()
	config.KeystrokeThreshold = 3

	session, _ := NewContinuousAttestationSession(config, tpm)
	session.Start()

	// Create checkpoints
	for i := 0; i < 9; i++ {
		contentHash := sha256.Sum256([]byte{byte(i)})
		session.RecordKeystroke(contentHash, nil)
	}

	export := session.ExportSession()
	session.Stop()

	// Tamper with counter to make it non-monotonic
	if len(export.Checkpoints) > 2 {
		export.Checkpoints[2].TPMCounter = export.Checkpoints[1].TPMCounter - 1
	}

	verifier := NewAttestationVerifier()
	result, _ := verifier.VerifyChain(export)

	if result.Valid {
		t.Error("Chain with non-monotonic counter should be invalid")
	}

	hasCounterError := false
	for _, e := range result.Errors {
		if e == "counter not monotonic at 2" {
			hasCounterError = true
			break
		}
	}
	if !hasCounterError {
		t.Errorf("Expected counter monotonic error, got: %v", result.Errors)
	}
}

func TestVerifyChainSequenceMismatch(t *testing.T) {
	tpm := NewMockTPM()

	config := DefaultAttestationConfig()
	config.KeystrokeThreshold = 3

	session, _ := NewContinuousAttestationSession(config, tpm)
	session.Start()

	for i := 0; i < 9; i++ {
		contentHash := sha256.Sum256([]byte{byte(i)})
		session.RecordKeystroke(contentHash, nil)
	}

	export := session.ExportSession()
	session.Stop()

	// Tamper with sequence number
	if len(export.Checkpoints) > 2 {
		export.Checkpoints[2].SequenceNumber = 99
	}

	verifier := NewAttestationVerifier()
	result, _ := verifier.VerifyChain(export)

	if result.Valid {
		t.Error("Chain with wrong sequence should be invalid")
	}
}

func TestVerifyChainBrokenHash(t *testing.T) {
	tpm := NewMockTPM()

	config := DefaultAttestationConfig()
	config.KeystrokeThreshold = 3

	session, _ := NewContinuousAttestationSession(config, tpm)
	session.Start()

	for i := 0; i < 9; i++ {
		contentHash := sha256.Sum256([]byte{byte(i)})
		session.RecordKeystroke(contentHash, nil)
	}

	export := session.ExportSession()
	session.Stop()

	// Tamper with previous hash to break chain
	if len(export.Checkpoints) > 2 {
		export.Checkpoints[2].PreviousHash = [32]byte{0xFF}
	}

	verifier := NewAttestationVerifier()
	result, _ := verifier.VerifyChain(export)

	if result.Valid {
		t.Error("Chain with broken hash link should be invalid")
	}
}

func TestVerifyEmptyChain(t *testing.T) {
	verifier := NewAttestationVerifier()

	export := &AttestationSessionExport{
		Checkpoints: []*AttestationCheckpoint{},
	}

	result, err := verifier.VerifyChain(export)
	if err != nil {
		t.Fatalf("Verification error: %v", err)
	}

	if !result.Valid {
		t.Error("Empty chain should be valid")
	}

	if result.CheckpointsVerified != 0 {
		t.Errorf("Expected 0 checkpoints verified, got %d", result.CheckpointsVerified)
	}
}

func TestVerifyChainWithUntrustedPCR(t *testing.T) {
	tpm := NewMockTPM()

	config := DefaultAttestationConfig()
	config.KeystrokeThreshold = 5

	session, _ := NewContinuousAttestationSession(config, tpm)
	session.Start()

	for i := 0; i < 10; i++ {
		contentHash := sha256.Sum256([]byte{byte(i)})
		session.RecordKeystroke(contentHash, nil)
	}

	export := session.ExportSession()
	session.Stop()

	verifier := NewAttestationVerifier()
	// Add a trusted PCR value that doesn't match
	verifier.AddTrustedPCRValue(0, []byte("different-value"))

	result, _ := verifier.VerifyChain(export)

	// Should still be valid but have warnings
	if !result.Valid {
		t.Error("Chain should be valid even with untrusted PCR")
	}

	if len(result.Warnings) == 0 {
		t.Error("Expected warnings about untrusted PCR values")
	}
}

func TestBackgroundRefreshWithError(t *testing.T) {
	tpm := NewMockTPM()

	config := DefaultAttestationConfig()
	config.QuoteRefreshInterval = 50 * time.Millisecond

	session, _ := NewContinuousAttestationSession(config, tpm)

	errorReceived := make(chan error, 1)
	session.SetErrorCallback(func(err error) {
		select {
		case errorReceived <- err:
		default:
		}
	})

	session.Start()

	// Let background refresh run
	time.Sleep(150 * time.Millisecond)

	session.Stop()

	// Note: Mock TPM doesn't fail, so no error expected
	// This tests the code path exists
}

func TestStartAlreadyRunning(t *testing.T) {
	tpm := NewMockTPM()

	config := DefaultAttestationConfig()
	session, _ := NewContinuousAttestationSession(config, tpm)

	err := session.Start()
	if err != nil {
		t.Fatalf("First start failed: %v", err)
	}

	// Second start should return nil (already running)
	err = session.Start()
	if err != nil {
		t.Errorf("Second start should succeed silently, got: %v", err)
	}

	session.Stop()
}

func TestStopNotRunning(t *testing.T) {
	tpm := NewMockTPM()

	config := DefaultAttestationConfig()
	session, _ := NewContinuousAttestationSession(config, tpm)

	// Stop without start should not panic
	session.Stop()
}

func TestCheckpointWithNilContentHash(t *testing.T) {
	tpm := NewMockTPM()

	config := DefaultAttestationConfig()
	config.KeystrokeThreshold = 100

	session, _ := NewContinuousAttestationSession(config, tpm)
	session.Start()

	// Force checkpoint with nil content hash
	err := session.ForceCheckpoint([32]byte{}, nil)
	if err != nil {
		t.Fatalf("ForceCheckpoint failed: %v", err)
	}

	chain := session.GetChain()
	if len(chain) < 2 {
		t.Error("Expected at least 2 checkpoints")
	}

	session.Stop()
}

func TestCheckpointWithoutPlatformState(t *testing.T) {
	tpm := NewMockTPM()

	config := DefaultAttestationConfig()
	config.IncludePlatformState = false
	config.KeystrokeThreshold = 5

	session, _ := NewContinuousAttestationSession(config, tpm)
	session.Start()

	for i := 0; i < 10; i++ {
		contentHash := sha256.Sum256([]byte{byte(i)})
		session.RecordKeystroke(contentHash, nil)
	}

	chain := session.GetChain()
	session.Stop()

	// Checkpoints should have nil PCRValues when platform state disabled
	for _, cp := range chain {
		if len(cp.PCRValues) > 0 {
			t.Error("Expected no PCR values when IncludePlatformState is false")
		}
	}
}

func TestRefreshQuoteDirectly(t *testing.T) {
	tpm := NewMockTPM()

	config := DefaultAttestationConfig()
	session, _ := NewContinuousAttestationSession(config, tpm)

	// Call refreshQuote directly
	err := session.refreshQuote()
	if err != nil {
		t.Fatalf("refreshQuote failed: %v", err)
	}

	session.mu.RLock()
	quote := session.lastQuote
	session.mu.RUnlock()

	if quote == nil {
		t.Error("Quote should be set after refresh")
	}
}

// FailingMockTPM is a TPM that fails on specific operations
type FailingMockTPM struct {
	*MockTPM
	mu          sync.RWMutex
	failCounter bool
	failQuote   bool
	failPCR     bool
	failEK      bool
}

func NewFailingMockTPM() *FailingMockTPM {
	return &FailingMockTPM{
		MockTPM: NewMockTPM(),
	}
}

func (f *FailingMockTPM) SetFailCounter(fail bool) {
	f.mu.Lock()
	f.failCounter = fail
	f.mu.Unlock()
}

func (f *FailingMockTPM) SetFailQuote(fail bool) {
	f.mu.Lock()
	f.failQuote = fail
	f.mu.Unlock()
}

func (f *FailingMockTPM) SetFailPCR(fail bool) {
	f.mu.Lock()
	f.failPCR = fail
	f.mu.Unlock()
}

func (f *FailingMockTPM) SetFailEK(fail bool) {
	f.mu.Lock()
	f.failEK = fail
	f.mu.Unlock()
}

func (f *FailingMockTPM) GetEndorsementKeyPublic() ([]byte, error) {
	f.mu.RLock()
	fail := f.failEK
	f.mu.RUnlock()
	if fail {
		return nil, errors.New("endorsement key failed")
	}
	return f.MockTPM.GetEndorsementKeyPublic()
}

func (f *FailingMockTPM) IncrementCounter(idx uint32) (uint64, error) {
	f.mu.RLock()
	fail := f.failCounter
	f.mu.RUnlock()
	if fail {
		return 0, errors.New("counter failed")
	}
	return f.MockTPM.IncrementCounter(idx)
}

func (f *FailingMockTPM) Quote(nonce []byte, pcrs []int) (*TPMQuote, error) {
	f.mu.RLock()
	fail := f.failQuote
	f.mu.RUnlock()
	if fail {
		return nil, errors.New("quote failed")
	}
	return f.MockTPM.Quote(nonce, pcrs)
}

func (f *FailingMockTPM) ReadPCR(idx int) ([]byte, error) {
	f.mu.RLock()
	fail := f.failPCR
	f.mu.RUnlock()
	if fail {
		return nil, errors.New("PCR read failed")
	}
	return f.MockTPM.ReadPCR(idx)
}

func TestNewSessionCounterError(t *testing.T) {
	tpm := NewFailingMockTPM()
	tpm.SetFailCounter(true)

	_, err := NewContinuousAttestationSession(DefaultAttestationConfig(), tpm)
	if err == nil {
		t.Error("Expected error when counter fails")
	}
}

func TestNewSessionQuoteError(t *testing.T) {
	tpm := NewFailingMockTPM()
	tpm.SetFailQuote(true)

	_, err := NewContinuousAttestationSession(DefaultAttestationConfig(), tpm)
	if err == nil {
		t.Error("Expected error when quote fails")
	}
}

func TestCreateCheckpointCounterError(t *testing.T) {
	tpm := NewFailingMockTPM()

	config := DefaultAttestationConfig()
	session, err := NewContinuousAttestationSession(config, tpm)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	session.Start()

	// Now make counter fail
	tpm.SetFailCounter(true)

	contentHash := sha256.Sum256([]byte("test"))
	err = session.ForceCheckpoint(contentHash, nil)
	if err == nil {
		t.Error("Expected error when counter fails during checkpoint")
	}

	session.Stop()
}

func TestCreateCheckpointQuoteRefreshError(t *testing.T) {
	tpm := NewFailingMockTPM()

	config := DefaultAttestationConfig()
	config.QuoteRefreshInterval = 1 * time.Millisecond // Very short interval

	session, err := NewContinuousAttestationSession(config, tpm)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Start session (creates initial checkpoint)
	session.Start()

	// Now make quote fail and set lastQuoteTime to past to force refresh on next checkpoint
	tpm.SetFailQuote(true)
	session.mu.Lock()
	session.lastQuoteTime = time.Now().Add(-time.Hour)
	session.mu.Unlock()

	contentHash := sha256.Sum256([]byte("test"))
	err = session.ForceCheckpoint(contentHash, nil)
	if err == nil {
		t.Error("Expected error when quote refresh fails during checkpoint")
	}

	session.Stop()
}

func TestCreateCheckpointPCRReadError(t *testing.T) {
	tpm := NewFailingMockTPM()

	config := DefaultAttestationConfig()
	config.IncludePlatformState = true

	session, err := NewContinuousAttestationSession(config, tpm)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	session.Start()

	// Make PCR read fail - checkpoint should still succeed (PCR read error is ignored)
	tpm.SetFailPCR(true)

	contentHash := sha256.Sum256([]byte("test"))
	err = session.ForceCheckpoint(contentHash, nil)
	if err != nil {
		t.Errorf("Checkpoint should succeed even if PCR read fails: %v", err)
	}

	chain := session.GetChain()
	// Last checkpoint should have empty PCRValues
	lastCP := chain[len(chain)-1]
	if len(lastCP.PCRValues) > 0 {
		t.Error("PCRValues should be empty when PCR read fails")
	}

	session.Stop()
}

func TestBackgroundRefreshError(t *testing.T) {
	tpm := NewFailingMockTPM()

	config := DefaultAttestationConfig()
	config.QuoteRefreshInterval = 20 * time.Millisecond

	session, err := NewContinuousAttestationSession(config, tpm)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	errorReceived := make(chan error, 1)
	session.SetErrorCallback(func(err error) {
		select {
		case errorReceived <- err:
		default:
		}
	})

	// Start with working TPM
	session.Start()

	// Now make quote fail and force lastQuoteTime to be stale
	// This ensures the background refresh will trigger and fail
	tpm.SetFailQuote(true)
	session.lastQuoteTime = time.Now().Add(-time.Hour)

	// Wait for background refresh to trigger
	select {
	case err := <-errorReceived:
		if err == nil {
			t.Error("Expected non-nil error")
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("Expected error callback to be called")
	}

	session.Stop()
}

func TestStartWithCheckpointError(t *testing.T) {
	tpm := NewFailingMockTPM()

	config := DefaultAttestationConfig()

	session, err := NewContinuousAttestationSession(config, tpm)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Make counter fail before Start creates initial checkpoint
	tpm.SetFailCounter(true)

	err = session.Start()
	if err == nil {
		t.Error("Expected error when initial checkpoint fails")
	}
}

func BenchmarkCheckpointCreation(b *testing.B) {
	tpm := NewMockTPM()

	config := DefaultAttestationConfig()
	config.KeystrokeThreshold = 1000000 // Don't auto-create

	session, _ := NewContinuousAttestationSession(config, tpm)
	session.Start()

	contentHash := sha256.Sum256([]byte("benchmark"))
	timingData := []byte("timing data")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		session.ForceCheckpoint(contentHash, timingData)
	}

	session.Stop()
}

func BenchmarkChainVerification(b *testing.B) {
	tpm := NewMockTPM()

	config := DefaultAttestationConfig()
	config.KeystrokeThreshold = 10

	session, _ := NewContinuousAttestationSession(config, tpm)
	session.Start()

	// Create 100 checkpoints
	for i := 0; i < 1000; i++ {
		contentHash := sha256.Sum256([]byte{byte(i)})
		session.RecordKeystroke(contentHash, nil)
	}

	export := session.ExportSession()
	session.Stop()

	verifier := NewAttestationVerifier()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		verifier.VerifyChain(export)
	}
}
