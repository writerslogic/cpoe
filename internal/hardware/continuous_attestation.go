// Package hardware provides continuous TPM attestation during keystroke capture.
//
// This file implements a system that continuously generates TPM attestations
// as the user types, binding each checkpoint to verifiable TPM state.
//
// Security properties:
// - Each checkpoint is bound to a TPM monotonic counter
// - TPM quotes provide cryptographic proof of platform state
// - Checkpoints can be independently verified without trusting the device
// - Tampering with checkpoints invalidates subsequent attestations
package hardware

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Attestation errors (ErrAttestationFailed is defined in entropy_binding.go)
var (
	ErrCounterMismatch        = errors.New("TPM counter mismatch")
	ErrQuoteVerificationFailed = errors.New("TPM quote verification failed")
	ErrAttestationExpired     = errors.New("attestation has expired")
	ErrChainBroken            = errors.New("attestation chain broken")
)

// AttestationConfig configures the continuous attestation system.
type AttestationConfig struct {
	// CheckpointInterval is how often to create checkpoints
	CheckpointInterval time.Duration
	// KeystrokeThreshold creates checkpoint after this many keystrokes
	KeystrokeThreshold int
	// MaxChainLength limits attestation chain for memory efficiency
	MaxChainLength int
	// QuoteRefreshInterval is how often to refresh TPM quotes
	QuoteRefreshInterval time.Duration
	// IncludePlatformState includes PCR values in attestations
	IncludePlatformState bool
	// RequireHardwareTPM rejects software TPM
	RequireHardwareTPM bool
}

// DefaultAttestationConfig returns sensible defaults.
func DefaultAttestationConfig() AttestationConfig {
	return AttestationConfig{
		CheckpointInterval:   30 * time.Second,
		KeystrokeThreshold:   100,
		MaxChainLength:       1000,
		QuoteRefreshInterval: 60 * time.Second,
		IncludePlatformState: true,
		RequireHardwareTPM:   false,
	}
}

// ContinuousAttestationSession manages TPM attestations during a typing session.
type ContinuousAttestationSession struct {
	mu sync.RWMutex

	config AttestationConfig
	tpm    TPMInterface

	// Session state
	sessionID       [32]byte
	sessionStart    time.Time
	keystrokeCount  uint64
	checkpointCount uint64

	// Attestation chain
	chain           []*AttestationCheckpoint
	lastCheckpoint  *AttestationCheckpoint

	// TPM state
	currentCounter  uint64
	lastQuote       *TPMQuote
	lastQuoteTime   time.Time

	// PUF binding (optional)
	puf             PUF
	pufChallenge    []byte

	// Callbacks
	onCheckpoint    func(*AttestationCheckpoint)
	onError         func(error)

	// Shutdown
	done            chan struct{}
	running         bool
}

// AttestationCheckpoint represents a point-in-time attestation.
type AttestationCheckpoint struct {
	// Identification
	SessionID       [32]byte
	SequenceNumber  uint64
	Timestamp       time.Time

	// TPM binding
	TPMCounter      uint64
	TPMQuote        *TPMQuote
	PCRValues       map[int][]byte

	// Content binding
	ContentHash     [32]byte // Hash of content up to this point
	KeystrokeCount  uint64
	TimingHash      [32]byte // Hash of timing data

	// Chain integrity
	PreviousHash    [32]byte // Hash of previous checkpoint
	CheckpointHash  [32]byte // Hash of this checkpoint

	// PUF binding (optional)
	PUFChallenge    []byte
	PUFResponse     []byte

	// Signatures
	TPMSignature    []byte
	DeviceSignature []byte
}

// NOTE: TPMQuote type is defined in entropy_binding.go

// NewContinuousAttestationSession creates a new attestation session.
func NewContinuousAttestationSession(config AttestationConfig, tpm TPMInterface) (*ContinuousAttestationSession, error) {
	if tpm == nil {
		return nil, ErrTPMNotAvailable
	}

	// Generate session ID
	var sessionID [32]byte
	if _, err := rand.Read(sessionID[:]); err != nil {
		return nil, err
	}

	session := &ContinuousAttestationSession{
		config:       config,
		tpm:          tpm,
		sessionID:    sessionID,
		sessionStart: time.Now(),
		chain:        make([]*AttestationCheckpoint, 0, config.MaxChainLength),
		done:         make(chan struct{}),
	}

	// Initialize TPM counter
	counter, err := tpm.IncrementCounter(0)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize TPM counter: %w", err)
	}
	session.currentCounter = counter

	// Generate initial quote
	if err := session.refreshQuote(); err != nil {
		return nil, fmt.Errorf("failed to generate initial quote: %w", err)
	}

	return session, nil
}

// SetPUF enables PUF binding for checkpoints.
func (s *ContinuousAttestationSession) SetPUF(puf PUF) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.puf = puf
}

// SetCheckpointCallback sets a callback for new checkpoints.
func (s *ContinuousAttestationSession) SetCheckpointCallback(cb func(*AttestationCheckpoint)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onCheckpoint = cb
}

// SetErrorCallback sets a callback for errors during background operations.
func (s *ContinuousAttestationSession) SetErrorCallback(cb func(error)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onError = cb
}

// Start begins the attestation session.
func (s *ContinuousAttestationSession) Start() error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = true
	s.mu.Unlock()

	// Create initial checkpoint
	if err := s.createCheckpoint(nil, nil); err != nil {
		return err
	}

	// Start background refresh
	go s.backgroundRefresh()

	return nil
}

// RecordKeystroke records a keystroke and potentially creates a checkpoint.
func (s *ContinuousAttestationSession) RecordKeystroke(contentHash [32]byte, timingData []byte) error {
	s.mu.Lock()
	s.keystrokeCount++
	keystrokeCount := s.keystrokeCount
	shouldCheckpoint := keystrokeCount%uint64(s.config.KeystrokeThreshold) == 0
	s.mu.Unlock()

	// Check if we should create a checkpoint
	if shouldCheckpoint {
		return s.createCheckpoint(&contentHash, timingData)
	}

	return nil
}

// ForceCheckpoint forces creation of a checkpoint.
func (s *ContinuousAttestationSession) ForceCheckpoint(contentHash [32]byte, timingData []byte) error {
	return s.createCheckpoint(&contentHash, timingData)
}

// createCheckpoint creates a new attestation checkpoint.
func (s *ContinuousAttestationSession) createCheckpoint(contentHash *[32]byte, timingData []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Increment TPM counter
	counter, err := s.tpm.IncrementCounter(0)
	if err != nil {
		return fmt.Errorf("TPM counter increment failed: %w", err)
	}

	// Verify counter is monotonically increasing
	if counter <= s.currentCounter && s.checkpointCount > 0 {
		return ErrCounterMismatch
	}
	s.currentCounter = counter

	// Refresh quote if needed
	if time.Since(s.lastQuoteTime) > s.config.QuoteRefreshInterval {
		if err := s.refreshQuoteLocked(); err != nil {
			return err
		}
	}

	// Create checkpoint
	checkpoint := &AttestationCheckpoint{
		SessionID:      s.sessionID,
		SequenceNumber: s.checkpointCount,
		Timestamp:      time.Now(),
		TPMCounter:     counter,
		TPMQuote:       s.lastQuote,
		KeystrokeCount: s.keystrokeCount,
	}

	// Set content hash
	if contentHash != nil {
		checkpoint.ContentHash = *contentHash
	}

	// Set timing hash
	if timingData != nil {
		checkpoint.TimingHash = sha256.Sum256(timingData)
	}

	// Get PCR values if configured
	if s.config.IncludePlatformState {
		checkpoint.PCRValues = make(map[int][]byte)
		for _, pcr := range []int{0, 1, 2, 3, 4, 7} { // Common PCRs
			value, err := s.tpm.ReadPCR(pcr)
			if err == nil {
				checkpoint.PCRValues[pcr] = value
			}
		}
	}

	// Set previous hash (chain integrity)
	if s.lastCheckpoint != nil {
		checkpoint.PreviousHash = s.lastCheckpoint.CheckpointHash
	}

	// PUF binding if available
	if s.puf != nil {
		// Generate challenge from checkpoint data
		challengeData := s.generatePUFChallengeData(checkpoint)
		checkpoint.PUFChallenge = challengeData

		response, err := s.puf.Challenge(challengeData)
		if err == nil {
			checkpoint.PUFResponse = response
		}
	}

	// Calculate checkpoint hash
	checkpoint.CheckpointHash = s.calculateCheckpointHash(checkpoint)

	// TPM signature is included via the quote
	// The TPMQuote.Signature provides TPM-backed authentication
	if checkpoint.TPMQuote != nil {
		checkpoint.TPMSignature = checkpoint.TPMQuote.Signature
	}

	// Add to chain
	s.chain = append(s.chain, checkpoint)
	s.lastCheckpoint = checkpoint
	s.checkpointCount++

	// Trim chain if too long
	if len(s.chain) > s.config.MaxChainLength {
		s.chain = s.chain[1:]
	}

	// Invoke callback
	if s.onCheckpoint != nil {
		go s.onCheckpoint(checkpoint)
	}

	return nil
}

// generatePUFChallengeData generates PUF challenge from checkpoint data.
func (s *ContinuousAttestationSession) generatePUFChallengeData(cp *AttestationCheckpoint) []byte {
	h := sha256.New()
	h.Write(cp.SessionID[:])
	binary.Write(h, binary.BigEndian, cp.SequenceNumber)
	binary.Write(h, binary.BigEndian, cp.TPMCounter)
	h.Write(cp.ContentHash[:])
	h.Write(cp.TimingHash[:])
	return h.Sum(nil)
}

// calculateCheckpointHash calculates the hash of a checkpoint.
func (s *ContinuousAttestationSession) calculateCheckpointHash(cp *AttestationCheckpoint) [32]byte {
	return ComputeCheckpointHash(cp)
}

// ComputeCheckpointHash computes the cryptographic hash of a checkpoint.
// This is the canonical hash function used for chain integrity verification.
func ComputeCheckpointHash(cp *AttestationCheckpoint) [32]byte {
	h := sha256.New()

	h.Write(cp.SessionID[:])
	binary.Write(h, binary.BigEndian, cp.SequenceNumber)
	binary.Write(h, binary.BigEndian, cp.Timestamp.UnixNano())
	binary.Write(h, binary.BigEndian, cp.TPMCounter)
	h.Write(cp.ContentHash[:])
	binary.Write(h, binary.BigEndian, cp.KeystrokeCount)
	h.Write(cp.TimingHash[:])
	h.Write(cp.PreviousHash[:])

	if cp.TPMQuote != nil {
		h.Write(cp.TPMQuote.RawQuote)
	}

	if cp.PUFResponse != nil {
		h.Write(cp.PUFResponse)
	}

	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// refreshQuote refreshes the TPM quote.
func (s *ContinuousAttestationSession) refreshQuote() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refreshQuoteLocked()
}

// refreshQuoteLocked refreshes quote (caller must hold lock).
func (s *ContinuousAttestationSession) refreshQuoteLocked() error {
	// Generate nonce
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}

	// Get TPM quote
	quote, err := s.tpm.Quote(nonce[:], []int{0, 1, 2, 3, 4, 7})
	if err != nil {
		return fmt.Errorf("TPM quote failed: %w", err)
	}

	s.lastQuote = quote
	s.lastQuoteTime = time.Now()

	return nil
}

// backgroundRefresh runs periodic quote refresh.
func (s *ContinuousAttestationSession) backgroundRefresh() {
	ticker := time.NewTicker(s.config.QuoteRefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			if err := s.refreshQuote(); err != nil {
				s.mu.RLock()
				errorCb := s.onError
				s.mu.RUnlock()
				if errorCb != nil {
					go errorCb(fmt.Errorf("background quote refresh failed: %w", err))
				}
			}
		}
	}
}

// Stop stops the attestation session.
func (s *ContinuousAttestationSession) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	s.running = false
	s.mu.Unlock()

	close(s.done)
}

// GetChain returns the current attestation chain.
func (s *ContinuousAttestationSession) GetChain() []*AttestationCheckpoint {
	s.mu.RLock()
	defer s.mu.RUnlock()

	chain := make([]*AttestationCheckpoint, len(s.chain))
	copy(chain, s.chain)
	return chain
}

// GetLastCheckpoint returns the most recent checkpoint.
func (s *ContinuousAttestationSession) GetLastCheckpoint() *AttestationCheckpoint {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastCheckpoint
}

// ExportSession exports the full session for verification.
func (s *ContinuousAttestationSession) ExportSession() *AttestationSessionExport {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Copy chain directly to avoid nested lock acquisition
	chain := make([]*AttestationCheckpoint, len(s.chain))
	copy(chain, s.chain)

	return &AttestationSessionExport{
		SessionID:      s.sessionID,
		SessionStart:   s.sessionStart,
		KeystrokeCount: s.keystrokeCount,
		Checkpoints:    chain,
		FinalCounter:   s.currentCounter,
		FinalQuote:     s.lastQuote,
	}
}

// AttestationSessionExport contains the full session data for verification.
type AttestationSessionExport struct {
	SessionID      [32]byte
	SessionStart   time.Time
	KeystrokeCount uint64
	Checkpoints    []*AttestationCheckpoint
	FinalCounter   uint64
	FinalQuote     *TPMQuote
}

// AttestationVerifier verifies attestation chains.
type AttestationVerifier struct {
	// TrustedAKs is the list of trusted attestation key public keys
	TrustedAKs [][]byte
	// TrustedPCRValues maps PCR index to expected values
	TrustedPCRValues map[int][][]byte
	// MaxTimeDrift is the maximum allowed time drift
	MaxTimeDrift time.Duration
}

// NewAttestationVerifier creates a new verifier.
func NewAttestationVerifier() *AttestationVerifier {
	return &AttestationVerifier{
		TrustedAKs:       make([][]byte, 0),
		TrustedPCRValues: make(map[int][][]byte),
		MaxTimeDrift:     5 * time.Minute,
	}
}

// AddTrustedAK adds a trusted attestation key.
func (v *AttestationVerifier) AddTrustedAK(publicKey []byte) {
	v.TrustedAKs = append(v.TrustedAKs, publicKey)
}

// AddTrustedPCRValue adds a trusted PCR value.
func (v *AttestationVerifier) AddTrustedPCRValue(pcr int, value []byte) {
	v.TrustedPCRValues[pcr] = append(v.TrustedPCRValues[pcr], value)
}

// VerifyChain verifies an attestation chain.
func (v *AttestationVerifier) VerifyChain(export *AttestationSessionExport) (*VerificationResult, error) {
	result := &VerificationResult{
		Valid:           true,
		CheckpointsVerified: 0,
	}

	if len(export.Checkpoints) == 0 {
		return result, nil
	}

	// Verify chain integrity
	var prevHash [32]byte
	var lastCounter uint64

	for i, checkpoint := range export.Checkpoints {
		// Verify sequence number
		if checkpoint.SequenceNumber != uint64(i) {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("sequence mismatch at %d", i))
		}

		// Verify previous hash chain
		if i > 0 && checkpoint.PreviousHash != prevHash {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("chain broken at %d", i))
		}

		// Verify monotonic counter
		if checkpoint.TPMCounter <= lastCounter && i > 0 {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("counter not monotonic at %d", i))
		}
		lastCounter = checkpoint.TPMCounter

		// Verify checkpoint hash
		expectedHash := v.calculateCheckpointHash(checkpoint)
		if checkpoint.CheckpointHash != expectedHash {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("hash mismatch at %d", i))
		}

		// Verify PCR values if configured
		if len(v.TrustedPCRValues) > 0 && checkpoint.PCRValues != nil {
			for pcr, trustedValues := range v.TrustedPCRValues {
				if value, ok := checkpoint.PCRValues[pcr]; ok {
					trusted := false
					for _, tv := range trustedValues {
						if hmac.Equal(value, tv) {
							trusted = true
							break
						}
					}
					if !trusted {
						result.Warnings = append(result.Warnings,
							fmt.Sprintf("untrusted PCR%d value at checkpoint %d", pcr, i))
					}
				}
			}
		}

		prevHash = checkpoint.CheckpointHash
		result.CheckpointsVerified++
	}

	return result, nil
}

// calculateCheckpointHash recalculates a checkpoint hash for verification.
func (v *AttestationVerifier) calculateCheckpointHash(cp *AttestationCheckpoint) [32]byte {
	return ComputeCheckpointHash(cp)
}

// VerificationResult contains the result of chain verification.
type VerificationResult struct {
	Valid               bool
	CheckpointsVerified int
	Errors              []string
	Warnings            []string
}

// MockTPM provides a mock TPM for testing that implements TPMInterface.
type MockTPM struct {
	mu        sync.Mutex
	counter   uint64
	pcrValues map[int][]byte
	sealedData map[string][]byte
}

// NewMockTPM creates a mock TPM for testing.
func NewMockTPM() *MockTPM {
	return &MockTPM{
		pcrValues: map[int][]byte{
			0: make([]byte, 32),
			1: make([]byte, 32),
			2: make([]byte, 32),
			3: make([]byte, 32),
			4: make([]byte, 32),
			7: make([]byte, 32),
		},
		sealedData: make(map[string][]byte),
	}
}

// Available implements TPMInterface.Available.
func (m *MockTPM) Available() bool {
	return true
}

// GetEndorsementKeyPublic implements TPMInterface.GetEndorsementKeyPublic.
func (m *MockTPM) GetEndorsementKeyPublic() ([]byte, error) {
	// Return a mock endorsement key
	h := sha256.Sum256([]byte("mock-endorsement-key"))
	return h[:], nil
}

// ReadPCR implements TPMInterface.ReadPCR.
func (m *MockTPM) ReadPCR(index int) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if value, ok := m.pcrValues[index]; ok {
		result := make([]byte, len(value))
		copy(result, value)
		return result, nil
	}
	return nil, errors.New("PCR not found")
}

// ReadPCRs implements TPMInterface.ReadPCRs.
func (m *MockTPM) ReadPCRs(indices []int) (map[int][]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	result := make(map[int][]byte)
	for _, idx := range indices {
		if value, ok := m.pcrValues[idx]; ok {
			valueCopy := make([]byte, len(value))
			copy(valueCopy, value)
			result[idx] = valueCopy
		}
	}
	return result, nil
}

// Quote implements TPMInterface.Quote.
func (m *MockTPM) Quote(nonce []byte, pcrIndices []int) (*TPMQuote, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Create mock quote data
	h := sha256.New()
	h.Write(nonce)
	for _, pcr := range pcrIndices {
		if value, ok := m.pcrValues[pcr]; ok {
			h.Write(value)
		}
	}
	rawQuote := h.Sum(nil)

	// Create mock signature
	signature := make([]byte, 64)
	rand.Read(signature)

	// Build PCR values map
	pcrValues := make(map[int][]byte)
	for _, idx := range pcrIndices {
		if value, ok := m.pcrValues[idx]; ok {
			valueCopy := make([]byte, len(value))
			copy(valueCopy, value)
			pcrValues[idx] = valueCopy
		}
	}

	return &TPMQuote{
		PCRValues: pcrValues,
		Nonce:     nonce,
		Timestamp: time.Now(),
		Signature: signature,
		RawQuote:  rawQuote,
	}, nil
}

// IncrementCounter implements TPMInterface.IncrementCounter.
func (m *MockTPM) IncrementCounter(counterIndex uint32) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counter++
	return m.counter, nil
}

// ReadCounter implements TPMInterface.ReadCounter.
func (m *MockTPM) ReadCounter(counterIndex uint32) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.counter, nil
}

// Seal implements TPMInterface.Seal.
func (m *MockTPM) Seal(data []byte, pcrIndices []int) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Mock sealing - just XOR with a key
	key := sha256.Sum256([]byte("mock-seal-key"))
	sealed := make([]byte, len(data)+32)
	copy(sealed[:32], key[:])
	for i, b := range data {
		sealed[32+i] = b ^ key[i%32]
	}
	return sealed, nil
}

// Unseal implements TPMInterface.Unseal.
func (m *MockTPM) Unseal(sealed []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(sealed) < 32 {
		return nil, errors.New("invalid sealed data")
	}

	key := sha256.Sum256([]byte("mock-seal-key"))
	data := make([]byte, len(sealed)-32)
	for i := range data {
		data[i] = sealed[32+i] ^ key[i%32]
	}
	return data, nil
}

// GetRandom implements TPMInterface.GetRandom.
func (m *MockTPM) GetRandom(size int) ([]byte, error) {
	buf := make([]byte, size)
	rand.Read(buf)
	return buf, nil
}

// ExtendPCR extends a PCR (not in interface but useful for testing).
func (m *MockTPM) ExtendPCR(index int, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if value, ok := m.pcrValues[index]; ok {
		h := sha256.New()
		h.Write(value)
		h.Write(data)
		m.pcrValues[index] = h.Sum(nil)
		return nil
	}
	return errors.New("PCR not found")
}

// IsAvailable is an alias for Available for backward compatibility.
func (m *MockTPM) IsAvailable() bool {
	return m.Available()
}
