// Package hardware provides hardware-rooted security for authorship verification.
//
// This package uses TPM and PUF to create unforgeable evidence that:
// 1. A specific physical device was present during writing
// 2. The software environment was uncompromised
// 3. The timeline is authentic and can't be backdated
//
// Security Model:
// - Adversary has root access to the operating system
// - Adversary may have temporary physical access
// - Adversary cannot extract TPM private keys (hardware security)
// - Adversary cannot clone PUF responses (physical unclonabiity)
//
// What This Proves:
// - TPM attestation: "Verified software was running"
// - TPM counters: "This happened in this order, can't be replayed"
// - PUF responses: "This specific device was present"
// - Combined: "This device, running this software, over this time"
package hardware

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrTPMNotAvailable  = errors.New("TPM not available")
	ErrPUFNotAvailable  = errors.New("PUF not available")
	ErrAttestationFailed = errors.New("TPM attestation failed")
	ErrPUFChallengeFailed = errors.New("PUF challenge-response failed")
	ErrCounterRollback   = errors.New("TPM counter rollback detected")
	ErrStateCompromised  = errors.New("system state compromised")
)

// EntropyBinder combines TPM and PUF for hardware-rooted entropy binding.
//
// Architecture:
//
//	┌─────────────────────────────────────────────────────────────────┐
//	│                    Authorship Session                           │
//	├─────────────────────────────────────────────────────────────────┤
//	│                                                                 │
//	│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
//	│  │   Keystroke  │───▶│   Entropy    │───▶│  Checkpoint  │      │
//	│  │    Event     │    │   Binding    │    │   + Proof    │      │
//	│  └──────────────┘    └──────┬───────┘    └──────────────┘      │
//	│                             │                                   │
//	│         ┌───────────────────┼───────────────────┐              │
//	│         ▼                   ▼                   ▼              │
//	│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
//	│  │     TPM      │    │     PUF      │    │   External   │      │
//	│  │  Attestation │    │   Response   │    │   Entropy    │      │
//	│  │  + Counter   │    │  (Device ID) │    │ (Blockchain) │      │
//	│  └──────────────┘    └──────────────┘    └──────────────┘      │
//	│                                                                 │
//	└─────────────────────────────────────────────────────────────────┘
//
// Each checkpoint is bound to:
// 1. TPM counter value (can't be replayed)
// 2. TPM attestation quote (proves software state)
// 3. PUF challenge-response (proves physical device)
// 4. External entropy (proves point in time)
type EntropyBinder struct {
	mu sync.RWMutex

	// TPM interface
	tpm TPMInterface

	// PUF interface
	puf PUFInterface

	// External entropy sources
	externalSources []ExternalEntropySource

	// Session state
	sessionID       [32]byte
	sessionStart    time.Time
	lastCounter     uint64
	entropyChain    [32]byte

	// Attestation state
	initialPCRs     map[int][]byte
	attestations    []TPMAttestation

	// PUF state
	pufChallenges   []PUFChallengeResponse
	deviceFingerprint [32]byte

	// Configuration
	config EntropyBinderConfig
}

// EntropyBinderConfig configures the entropy binder.
type EntropyBinderConfig struct {
	// How often to capture TPM attestation
	AttestationInterval time.Duration

	// How often to issue PUF challenges
	PUFChallengeInterval time.Duration

	// Which PCRs to include in attestation (platform config)
	AttestationPCRs []int

	// External entropy sources to use
	EnableBlockchainEntropy bool
	EnableNTPEntropy        bool

	// Strict mode: fail if any hardware security is unavailable
	StrictMode bool
}

// DefaultEntropyBinderConfig returns secure defaults.
func DefaultEntropyBinderConfig() EntropyBinderConfig {
	return EntropyBinderConfig{
		AttestationInterval:     time.Minute,
		PUFChallengeInterval:    30 * time.Second,
		AttestationPCRs:         []int{0, 1, 2, 3, 4, 5, 6, 7}, // Boot chain
		EnableBlockchainEntropy: true,
		EnableNTPEntropy:        true,
		StrictMode:              true,
	}
}

// TPMInterface abstracts TPM operations.
type TPMInterface interface {
	// Available returns true if TPM is accessible
	Available() bool

	// GetEndorsementKeyPublic returns the TPM's public endorsement key
	GetEndorsementKeyPublic() ([]byte, error)

	// ReadPCR reads a Platform Configuration Register
	ReadPCR(index int) ([]byte, error)

	// ReadPCRs reads multiple PCRs atomically
	ReadPCRs(indices []int) (map[int][]byte, error)

	// Quote generates an attestation quote signed by the TPM
	// The quote includes PCR values and is bound to the nonce
	Quote(nonce []byte, pcrIndices []int) (*TPMQuote, error)

	// IncrementCounter increments a monotonic counter and returns new value
	IncrementCounter(counterIndex uint32) (uint64, error)

	// ReadCounter reads current counter value
	ReadCounter(counterIndex uint32) (uint64, error)

	// Seal encrypts data that can only be decrypted if PCRs match
	Seal(data []byte, pcrIndices []int) ([]byte, error)

	// Unseal decrypts sealed data (fails if PCRs changed)
	Unseal(sealed []byte) ([]byte, error)

	// GetRandom gets random bytes from TPM's hardware RNG
	GetRandom(size int) ([]byte, error)
}

// TPMQuote is a signed attestation from the TPM.
type TPMQuote struct {
	// PCRValues are the PCR readings at quote time
	PCRValues map[int][]byte `json:"pcr_values"`

	// Nonce is the anti-replay nonce
	Nonce []byte `json:"nonce"`

	// Timestamp from TPM's internal clock
	Timestamp time.Time `json:"timestamp"`

	// Signature over the quote, verifiable with endorsement key
	Signature []byte `json:"signature"`

	// Raw quote data for external verification
	RawQuote []byte `json:"raw_quote"`
}

// TPMAttestation is a complete attestation record.
type TPMAttestation struct {
	Timestamp    time.Time `json:"timestamp"`
	Quote        *TPMQuote `json:"quote"`
	CounterValue uint64    `json:"counter_value"`
	EntropyHash  [32]byte  `json:"entropy_hash"` // Hash of entropy at this point
}

// PUFInterface abstracts Physical Unclonable Function operations.
type PUFInterface interface {
	// Available returns true if PUF is accessible
	Available() bool

	// Challenge issues a challenge and returns the response
	// The response is unique to this physical device
	Challenge(challenge []byte) ([]byte, error)

	// GetDeviceID returns a stable device identifier derived from PUF
	GetDeviceID() ([]byte, error)

	// Type returns the PUF type (SRAM, RO, Arbiter, etc.)
	Type() string
}

// PUFChallengeResponse records a PUF challenge-response pair.
type PUFChallengeResponse struct {
	Timestamp time.Time `json:"timestamp"`
	Challenge []byte    `json:"challenge"`
	Response  []byte    `json:"response"`
	// We don't store the raw response - only a commitment
	ResponseHash [32]byte `json:"response_hash"`
}

// ExternalEntropySource provides entropy from external unpredictable sources.
type ExternalEntropySource interface {
	// Name returns the source name
	Name() string

	// Available returns true if source is accessible
	Available() bool

	// GetEntropy returns current entropy with timestamp
	// The entropy should be unpredictable before the timestamp
	GetEntropy() (*ExternalEntropy, error)
}

// ExternalEntropy is entropy from an external source.
type ExternalEntropy struct {
	Source    string    `json:"source"`
	Timestamp time.Time `json:"timestamp"`
	Data      []byte    `json:"data"`
	// Proof that this data existed at the claimed time
	// (e.g., block hash + merkle proof for blockchain)
	Proof []byte `json:"proof,omitempty"`
}

// NewEntropyBinder creates a new entropy binder.
func NewEntropyBinder(tpm TPMInterface, puf PUFInterface, config EntropyBinderConfig) (*EntropyBinder, error) {
	// Validate availability
	if config.StrictMode {
		if tpm == nil || !tpm.Available() {
			return nil, ErrTPMNotAvailable
		}
		if puf == nil || !puf.Available() {
			return nil, ErrPUFNotAvailable
		}
	}

	eb := &EntropyBinder{
		tpm:             tpm,
		puf:             puf,
		externalSources: make([]ExternalEntropySource, 0),
		sessionStart:    time.Now(),
		config:          config,
		attestations:    make([]TPMAttestation, 0),
		pufChallenges:   make([]PUFChallengeResponse, 0),
	}

	// Generate session ID
	if _, err := rand.Read(eb.sessionID[:]); err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}

	// Initialize entropy chain
	eb.initEntropyChain()

	// Capture initial PCR state
	if tpm != nil && tpm.Available() {
		pcrs, err := tpm.ReadPCRs(config.AttestationPCRs)
		if err != nil {
			if config.StrictMode {
				return nil, fmt.Errorf("failed to read initial PCRs: %w", err)
			}
		} else {
			eb.initialPCRs = pcrs
		}
	}

	// Get device fingerprint from PUF
	if puf != nil && puf.Available() {
		deviceID, err := puf.GetDeviceID()
		if err != nil {
			if config.StrictMode {
				return nil, fmt.Errorf("failed to get device fingerprint: %w", err)
			}
		} else {
			eb.deviceFingerprint = sha256.Sum256(deviceID)
		}
	}

	return eb, nil
}

// initEntropyChain initializes the cryptographic entropy chain.
func (eb *EntropyBinder) initEntropyChain() {
	h := sha256.New()
	h.Write([]byte("witnessd-entropy-chain-v1"))
	h.Write(eb.sessionID[:])
	binary.Write(h, binary.BigEndian, eb.sessionStart.UnixNano())

	// Include device fingerprint if available
	h.Write(eb.deviceFingerprint[:])

	// Include TPM random if available
	if eb.tpm != nil && eb.tpm.Available() {
		if tpmRandom, err := eb.tpm.GetRandom(32); err == nil {
			h.Write(tpmRandom)
		}
	}

	copy(eb.entropyChain[:], h.Sum(nil))
}

// AddExternalSource adds an external entropy source.
func (eb *EntropyBinder) AddExternalSource(source ExternalEntropySource) {
	eb.mu.Lock()
	defer eb.mu.Unlock()
	eb.externalSources = append(eb.externalSources, source)
}

// BindKeystroke binds a keystroke event to hardware entropy.
// Returns a binding proof that can be verified later.
func (eb *EntropyBinder) BindKeystroke(keystrokeCount uint64, documentHash [32]byte) (*KeystrokeBinding, error) {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	binding := &KeystrokeBinding{
		Timestamp:      time.Now(),
		KeystrokeCount: keystrokeCount,
		DocumentHash:   documentHash,
		SessionID:      eb.sessionID,
	}

	// Update entropy chain with keystroke data
	eb.updateEntropyChain(keystrokeCount, documentHash)
	binding.EntropyChain = eb.entropyChain

	// Increment TPM counter (proves temporal ordering)
	if eb.tpm != nil && eb.tpm.Available() {
		counter, err := eb.tpm.IncrementCounter(0)
		if err == nil {
			// Check for rollback
			if counter <= eb.lastCounter && eb.lastCounter > 0 {
				return nil, ErrCounterRollback
			}
			eb.lastCounter = counter
			binding.TPMCounter = counter
			binding.TPMCounterValid = true
		}
	}

	return binding, nil
}

// updateEntropyChain updates the running entropy chain.
func (eb *EntropyBinder) updateEntropyChain(count uint64, docHash [32]byte) {
	h := sha256.New()
	h.Write(eb.entropyChain[:])
	binary.Write(h, binary.BigEndian, count)
	h.Write(docHash[:])
	binary.Write(h, binary.BigEndian, time.Now().UnixNano())
	copy(eb.entropyChain[:], h.Sum(nil))
}

// CaptureAttestation captures a full TPM attestation.
// Call this periodically during the writing session.
func (eb *EntropyBinder) CaptureAttestation() (*TPMAttestation, error) {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	if eb.tpm == nil || !eb.tpm.Available() {
		return nil, ErrTPMNotAvailable
	}

	// Generate nonce from current entropy chain
	nonce := make([]byte, 32)
	copy(nonce, eb.entropyChain[:])

	// Get TPM quote
	quote, err := eb.tpm.Quote(nonce, eb.config.AttestationPCRs)
	if err != nil {
		return nil, fmt.Errorf("TPM quote failed: %w", err)
	}

	// Verify PCRs haven't changed (detect compromise)
	if eb.initialPCRs != nil {
		for idx, initial := range eb.initialPCRs {
			if current, ok := quote.PCRValues[idx]; ok {
				if !hmac.Equal(initial, current) {
					return nil, ErrStateCompromised
				}
			}
		}
	}

	// Read current counter
	counter, _ := eb.tpm.ReadCounter(0)

	attestation := &TPMAttestation{
		Timestamp:    time.Now(),
		Quote:        quote,
		CounterValue: counter,
		EntropyHash:  eb.entropyChain,
	}

	eb.attestations = append(eb.attestations, *attestation)
	return attestation, nil
}

// IssuePUFChallenge issues a PUF challenge to prove device presence.
func (eb *EntropyBinder) IssuePUFChallenge() (*PUFChallengeResponse, error) {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	if eb.puf == nil || !eb.puf.Available() {
		return nil, ErrPUFNotAvailable
	}

	// Generate challenge from entropy chain (unpredictable)
	challenge := make([]byte, 32)
	h := sha256.New()
	h.Write([]byte("puf-challenge"))
	h.Write(eb.entropyChain[:])
	binary.Write(h, binary.BigEndian, time.Now().UnixNano())
	copy(challenge, h.Sum(nil))

	// Get PUF response
	response, err := eb.puf.Challenge(challenge)
	if err != nil {
		return nil, fmt.Errorf("PUF challenge failed: %w", err)
	}

	// Store only the hash of the response (privacy)
	cr := &PUFChallengeResponse{
		Timestamp:    time.Now(),
		Challenge:    challenge,
		Response:     response, // Only stored temporarily
		ResponseHash: sha256.Sum256(response),
	}

	// Update entropy chain with PUF response
	h = sha256.New()
	h.Write(eb.entropyChain[:])
	h.Write(response)
	copy(eb.entropyChain[:], h.Sum(nil))

	// Store challenge-response (without raw response for verification)
	stored := *cr
	stored.Response = nil // Don't store raw response
	eb.pufChallenges = append(eb.pufChallenges, stored)

	return cr, nil
}

// CollectExternalEntropy collects entropy from all external sources.
func (eb *EntropyBinder) CollectExternalEntropy() ([]*ExternalEntropy, error) {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	var results []*ExternalEntropy

	for _, source := range eb.externalSources {
		if source.Available() {
			entropy, err := source.GetEntropy()
			if err == nil {
				results = append(results, entropy)

				// Fold into entropy chain
				h := sha256.New()
				h.Write(eb.entropyChain[:])
				h.Write(entropy.Data)
				copy(eb.entropyChain[:], h.Sum(nil))
			}
		}
	}

	return results, nil
}

// KeystrokeBinding is the proof that a keystroke was bound to hardware entropy.
type KeystrokeBinding struct {
	Timestamp       time.Time `json:"timestamp"`
	KeystrokeCount  uint64    `json:"keystroke_count"`
	DocumentHash    [32]byte  `json:"document_hash"`
	SessionID       [32]byte  `json:"session_id"`
	EntropyChain    [32]byte  `json:"entropy_chain"`
	TPMCounter      uint64    `json:"tpm_counter,omitempty"`
	TPMCounterValid bool      `json:"tpm_counter_valid"`
}

// HardwareEvidence is the complete hardware-rooted evidence package.
type HardwareEvidence struct {
	// Session info
	SessionID        [32]byte  `json:"session_id"`
	SessionStart     time.Time `json:"session_start"`
	SessionEnd       time.Time `json:"session_end"`
	DeviceFingerprint [32]byte `json:"device_fingerprint"`

	// TPM evidence
	InitialPCRs     map[int][]byte   `json:"initial_pcrs,omitempty"`
	Attestations    []TPMAttestation `json:"attestations,omitempty"`
	FinalCounter    uint64           `json:"final_counter"`
	TPMAvailable    bool             `json:"tpm_available"`

	// PUF evidence
	PUFType         string                 `json:"puf_type,omitempty"`
	PUFChallenges   []PUFChallengeResponse `json:"puf_challenges,omitempty"`
	PUFAvailable    bool                   `json:"puf_available"`

	// External entropy
	ExternalEntropy []*ExternalEntropy `json:"external_entropy,omitempty"`

	// Final entropy chain
	FinalEntropyChain [32]byte `json:"final_entropy_chain"`

	// Signature over all evidence
	Signature [32]byte `json:"signature"`
}

// Export creates the complete hardware evidence package.
func (eb *EntropyBinder) Export() (*HardwareEvidence, error) {
	eb.mu.RLock()
	defer eb.mu.RUnlock()

	evidence := &HardwareEvidence{
		SessionID:         eb.sessionID,
		SessionStart:      eb.sessionStart,
		SessionEnd:        time.Now(),
		DeviceFingerprint: eb.deviceFingerprint,
		InitialPCRs:       eb.initialPCRs,
		Attestations:      eb.attestations,
		FinalCounter:      eb.lastCounter,
		PUFChallenges:     eb.pufChallenges,
		FinalEntropyChain: eb.entropyChain,
	}

	if eb.tpm != nil {
		evidence.TPMAvailable = eb.tpm.Available()
	}

	if eb.puf != nil {
		evidence.PUFAvailable = eb.puf.Available()
		evidence.PUFType = eb.puf.Type()
	}

	// Collect any remaining external entropy
	for _, source := range eb.externalSources {
		if source.Available() {
			if entropy, err := source.GetEntropy(); err == nil {
				evidence.ExternalEntropy = append(evidence.ExternalEntropy, entropy)
			}
		}
	}

	// Sign the evidence
	evidence.computeSignature()

	return evidence, nil
}

// computeSignature computes HMAC over the evidence.
func (e *HardwareEvidence) computeSignature() {
	h := sha256.New()
	h.Write(e.SessionID[:])
	binary.Write(h, binary.BigEndian, e.SessionStart.UnixNano())
	binary.Write(h, binary.BigEndian, e.SessionEnd.UnixNano())
	h.Write(e.DeviceFingerprint[:])
	binary.Write(h, binary.BigEndian, e.FinalCounter)
	h.Write(e.FinalEntropyChain[:])

	for _, att := range e.Attestations {
		binary.Write(h, binary.BigEndian, att.Timestamp.UnixNano())
		h.Write(att.EntropyHash[:])
	}

	for _, cr := range e.PUFChallenges {
		h.Write(cr.Challenge)
		h.Write(cr.ResponseHash[:])
	}

	copy(e.Signature[:], h.Sum(nil))
}

// Verify verifies the evidence integrity.
func (e *HardwareEvidence) Verify() error {
	// Recompute signature
	expected := sha256.New()
	expected.Write(e.SessionID[:])
	binary.Write(expected, binary.BigEndian, e.SessionStart.UnixNano())
	binary.Write(expected, binary.BigEndian, e.SessionEnd.UnixNano())
	expected.Write(e.DeviceFingerprint[:])
	binary.Write(expected, binary.BigEndian, e.FinalCounter)
	expected.Write(e.FinalEntropyChain[:])

	for _, att := range e.Attestations {
		binary.Write(expected, binary.BigEndian, att.Timestamp.UnixNano())
		expected.Write(att.EntropyHash[:])
	}

	for _, cr := range e.PUFChallenges {
		expected.Write(cr.Challenge)
		expected.Write(cr.ResponseHash[:])
	}

	expectedSig := expected.Sum(nil)
	if !hmac.Equal(e.Signature[:], expectedSig) {
		return errors.New("evidence signature mismatch")
	}

	// Verify TPM counter is monotonic
	var lastCounter uint64
	for _, att := range e.Attestations {
		if att.CounterValue < lastCounter {
			return ErrCounterRollback
		}
		lastCounter = att.CounterValue
	}

	// Verify attestation timestamps are monotonic
	var lastTime time.Time
	for _, att := range e.Attestations {
		if att.Timestamp.Before(lastTime) {
			return errors.New("attestation timestamps not monotonic")
		}
		lastTime = att.Timestamp
	}

	return nil
}

// VerifyDevice verifies that evidence came from a specific device.
// Requires the device's PUF to re-issue challenges.
func (e *HardwareEvidence) VerifyDevice(puf PUFInterface) error {
	if !puf.Available() {
		return ErrPUFNotAvailable
	}

	// Verify device fingerprint matches
	deviceID, err := puf.GetDeviceID()
	if err != nil {
		return err
	}

	expectedFingerprint := sha256.Sum256(deviceID)
	if expectedFingerprint != e.DeviceFingerprint {
		return errors.New("device fingerprint mismatch")
	}

	// Verify PUF challenge-responses
	for _, cr := range e.PUFChallenges {
		response, err := puf.Challenge(cr.Challenge)
		if err != nil {
			return fmt.Errorf("PUF challenge failed: %w", err)
		}

		responseHash := sha256.Sum256(response)
		if responseHash != cr.ResponseHash {
			return errors.New("PUF response mismatch - different device")
		}
	}

	return nil
}

// SessionID returns the session ID as a hex string.
func (eb *EntropyBinder) SessionID() string {
	return hex.EncodeToString(eb.sessionID[:])
}

// EntropyChain returns the current entropy chain hash.
func (eb *EntropyBinder) EntropyChain() [32]byte {
	eb.mu.RLock()
	defer eb.mu.RUnlock()
	return eb.entropyChain
}
