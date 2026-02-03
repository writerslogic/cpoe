// Package hardware provides remote verification of hardware attestations.
//
// This file implements a protocol that allows a remote verifier to:
// 1. Verify that attestation chains came from a specific device
// 2. Validate TPM quotes against known-good platform states
// 3. Verify temporal ordering using TPM monotonic counters
// 4. Confirm device identity through PUF challenge-response
//
// Protocol Overview:
//
//	┌──────────────┐                    ┌──────────────┐
//	│   Prover     │                    │   Verifier   │
//	│  (Device)    │                    │  (Remote)    │
//	└──────┬───────┘                    └──────┬───────┘
//	       │                                   │
//	       │──── 1. Enrollment Request ───────▶│
//	       │                                   │
//	       │◀─── 2. Enrollment Challenge ─────│
//	       │                                   │
//	       │──── 3. Enrollment Response ──────▶│
//	       │     (TPM EK, AK, PUF ID)         │
//	       │                                   │
//	       │◀─── 4. Enrollment Confirmation ──│
//	       │                                   │
//	       │ ... writing session ...           │
//	       │                                   │
//	       │──── 5. Verification Request ────▶│
//	       │     (Attestation Chain)          │
//	       │                                   │
//	       │◀─── 6. Verification Challenge ───│
//	       │     (Fresh nonce + PUF challenge)│
//	       │                                   │
//	       │──── 7. Verification Response ───▶│
//	       │     (TPM Quote + PUF Response)   │
//	       │                                   │
//	       │◀─── 8. Verification Result ──────│
//	       │                                   │
//
package hardware

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Remote verification errors
var (
	ErrDeviceNotEnrolled    = errors.New("device not enrolled")
	ErrEnrollmentExpired    = errors.New("enrollment has expired")
	ErrChallengeMismatch    = errors.New("challenge response mismatch")
	ErrInvalidQuote         = errors.New("invalid TPM quote")
	ErrPUFMismatch          = errors.New("PUF response mismatch")
	ErrTimelineTampering    = errors.New("timeline tampering detected")
	ErrPlatformStateChanged = errors.New("platform state changed")
)

// RemoteVerifier manages remote verification of device attestations.
type RemoteVerifier struct {
	mu sync.RWMutex

	// Enrolled devices
	enrolledDevices map[string]*DeviceEnrollment

	// Active challenges
	activeChallenges map[string]*VerificationChallenge

	// Configuration
	config RemoteVerifierConfig

	// Trusted PCR values (golden images)
	trustedPCRs map[int][][]byte

	// Verification callbacks
	onVerificationComplete func(*VerificationReport)
}

// RemoteVerifierConfig configures the remote verifier.
type RemoteVerifierConfig struct {
	// ChallengeTimeout is how long challenges are valid
	ChallengeTimeout time.Duration
	// EnrollmentTTL is how long enrollments last
	EnrollmentTTL time.Duration
	// RequireTPM requires TPM attestation
	RequireTPM bool
	// RequirePUF requires PUF verification
	RequirePUF bool
	// StrictPCRCheck fails on unknown PCR values
	StrictPCRCheck bool
	// MaxClockDrift is the maximum allowed time difference
	MaxClockDrift time.Duration
}

// DefaultRemoteVerifierConfig returns secure defaults.
func DefaultRemoteVerifierConfig() RemoteVerifierConfig {
	return RemoteVerifierConfig{
		ChallengeTimeout: 5 * time.Minute,
		EnrollmentTTL:    365 * 24 * time.Hour, // 1 year
		RequireTPM:       true,
		RequirePUF:       true,
		StrictPCRCheck:   false,
		MaxClockDrift:    5 * time.Minute,
	}
}

// DeviceEnrollment stores a device's enrollment data.
type DeviceEnrollment struct {
	// Device identification
	DeviceID       [32]byte  `json:"device_id"`
	EnrolledAt     time.Time `json:"enrolled_at"`
	ExpiresAt      time.Time `json:"expires_at"`

	// TPM data
	EndorsementKey []byte    `json:"endorsement_key"`
	AttestationKey []byte    `json:"attestation_key"`
	InitialPCRs    map[int][]byte `json:"initial_pcrs,omitempty"`

	// PUF data
	PUFFingerprint [32]byte  `json:"puf_fingerprint"`
	PUFType        string    `json:"puf_type,omitempty"`

	// Enrollment challenge-response
	EnrollmentNonce    [32]byte `json:"enrollment_nonce"`
	EnrollmentResponse []byte   `json:"enrollment_response"`

	// Metadata
	DeviceName string `json:"device_name,omitempty"`
	Platform   string `json:"platform,omitempty"`
}

// VerificationChallenge is an active challenge to a device.
type VerificationChallenge struct {
	ChallengeID  [32]byte  `json:"challenge_id"`
	DeviceID     [32]byte  `json:"device_id"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`

	// TPM challenge
	TPMNonce     [32]byte  `json:"tpm_nonce"`
	RequiredPCRs []int     `json:"required_pcrs"`

	// PUF challenge
	PUFChallenge []byte    `json:"puf_challenge"`

	// Expected counter range
	MinCounter   uint64    `json:"min_counter"`
}

// VerificationRequest is sent by a device to request verification.
type VerificationRequest struct {
	DeviceID        [32]byte                 `json:"device_id"`
	SessionExport   *AttestationSessionExport `json:"session_export"`
	RequestedAt     time.Time                `json:"requested_at"`
}

// VerificationResponse is sent by a device in response to a challenge.
type VerificationResponse struct {
	ChallengeID  [32]byte  `json:"challenge_id"`
	DeviceID     [32]byte  `json:"device_id"`

	// TPM quote with the challenge nonce
	TPMQuote     *TPMQuote `json:"tpm_quote"`

	// PUF response
	PUFResponse  []byte    `json:"puf_response"`

	// Current counter value
	CurrentCounter uint64  `json:"current_counter"`

	// Response timestamp
	RespondedAt    time.Time `json:"responded_at"`
}

// VerificationReport is the result of verification.
type VerificationReport struct {
	// Result
	Verified     bool      `json:"verified"`
	VerifiedAt   time.Time `json:"verified_at"`

	// Device info
	DeviceID     [32]byte  `json:"device_id"`
	DeviceName   string    `json:"device_name,omitempty"`

	// Session info
	SessionID    [32]byte  `json:"session_id"`
	SessionStart time.Time `json:"session_start"`
	KeystrokeCount uint64  `json:"keystroke_count"`
	CheckpointCount int    `json:"checkpoint_count"`

	// Verification details
	TPMVerified      bool     `json:"tpm_verified"`
	PUFVerified      bool     `json:"puf_verified"`
	ChainVerified    bool     `json:"chain_verified"`
	CounterVerified  bool     `json:"counter_verified"`
	TimelineVerified bool     `json:"timeline_verified"`

	// Issues found
	Errors   []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`

	// Confidence score (0-100)
	ConfidenceScore int `json:"confidence_score"`
}

// NewRemoteVerifier creates a new remote verifier.
func NewRemoteVerifier(config RemoteVerifierConfig) *RemoteVerifier {
	return &RemoteVerifier{
		enrolledDevices:  make(map[string]*DeviceEnrollment),
		activeChallenges: make(map[string]*VerificationChallenge),
		config:           config,
		trustedPCRs:      make(map[int][][]byte),
	}
}

// AddTrustedPCRValue adds a trusted (golden) PCR value.
func (rv *RemoteVerifier) AddTrustedPCRValue(pcr int, value []byte) {
	rv.mu.Lock()
	defer rv.mu.Unlock()
	rv.trustedPCRs[pcr] = append(rv.trustedPCRs[pcr], value)
}

// SetVerificationCallback sets a callback for completed verifications.
func (rv *RemoteVerifier) SetVerificationCallback(cb func(*VerificationReport)) {
	rv.mu.Lock()
	defer rv.mu.Unlock()
	rv.onVerificationComplete = cb
}

// EnrollmentChallenge creates a challenge for device enrollment.
func (rv *RemoteVerifier) EnrollmentChallenge() (*EnrollmentChallengeData, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	var pufChallenge [32]byte
	if _, err := rand.Read(pufChallenge[:]); err != nil {
		return nil, fmt.Errorf("failed to generate PUF challenge: %w", err)
	}

	return &EnrollmentChallengeData{
		Nonce:        nonce,
		PUFChallenge: pufChallenge[:],
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(rv.config.ChallengeTimeout),
		RequiredPCRs: []int{0, 1, 2, 3, 4, 7},
	}, nil
}

// EnrollmentChallengeData contains the enrollment challenge.
type EnrollmentChallengeData struct {
	Nonce        [32]byte  `json:"nonce"`
	PUFChallenge []byte    `json:"puf_challenge"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	RequiredPCRs []int     `json:"required_pcrs"`
}

// EnrollmentResponseData is the device's response to enrollment.
type EnrollmentResponseData struct {
	// TPM data
	EndorsementKey []byte         `json:"endorsement_key"`
	AttestationKey []byte         `json:"attestation_key"`
	TPMQuote       *TPMQuote      `json:"tpm_quote"`

	// PUF data
	PUFFingerprint [32]byte       `json:"puf_fingerprint"`
	PUFResponse    []byte         `json:"puf_response"`
	PUFType        string         `json:"puf_type"`

	// Metadata
	DeviceName     string         `json:"device_name,omitempty"`
	Platform       string         `json:"platform,omitempty"`
}

// CompleteEnrollment completes device enrollment.
func (rv *RemoteVerifier) CompleteEnrollment(
	challenge *EnrollmentChallengeData,
	response *EnrollmentResponseData,
) (*DeviceEnrollment, error) {
	rv.mu.Lock()
	defer rv.mu.Unlock()

	// Verify challenge hasn't expired
	if time.Now().After(challenge.ExpiresAt) {
		return nil, ErrEnrollmentExpired
	}

	// Verify TPM quote
	if rv.config.RequireTPM {
		if response.TPMQuote == nil {
			return nil, ErrInvalidQuote
		}

		// Verify nonce in quote
		if !bytes.Equal(response.TPMQuote.Nonce, challenge.Nonce[:]) {
			return nil, ErrChallengeMismatch
		}
	}

	// Generate device ID from TPM+PUF
	deviceID := rv.generateDeviceID(response.EndorsementKey, response.PUFFingerprint[:])

	// Create enrollment record
	enrollment := &DeviceEnrollment{
		DeviceID:           deviceID,
		EnrolledAt:         time.Now(),
		ExpiresAt:          time.Now().Add(rv.config.EnrollmentTTL),
		EndorsementKey:     response.EndorsementKey,
		AttestationKey:     response.AttestationKey,
		PUFFingerprint:     response.PUFFingerprint,
		PUFType:            response.PUFType,
		EnrollmentNonce:    challenge.Nonce,
		EnrollmentResponse: response.PUFResponse,
		DeviceName:         response.DeviceName,
		Platform:           response.Platform,
	}

	// Store initial PCR values
	if response.TPMQuote != nil && response.TPMQuote.PCRValues != nil {
		enrollment.InitialPCRs = response.TPMQuote.PCRValues
	}

	// Store enrollment
	rv.enrolledDevices[string(deviceID[:])] = enrollment

	return enrollment, nil
}

// generateDeviceID creates a unique device ID from TPM and PUF.
func (rv *RemoteVerifier) generateDeviceID(endorsementKey []byte, pufFingerprint []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte("witnessd-device-id-v1"))
	h.Write(endorsementKey)
	h.Write(pufFingerprint)
	var id [32]byte
	copy(id[:], h.Sum(nil))
	return id
}

// IsEnrolled checks if a device is enrolled.
func (rv *RemoteVerifier) IsEnrolled(deviceID [32]byte) bool {
	rv.mu.RLock()
	defer rv.mu.RUnlock()

	enrollment, ok := rv.enrolledDevices[string(deviceID[:])]
	if !ok {
		return false
	}

	return time.Now().Before(enrollment.ExpiresAt)
}

// CleanupExpiredChallenges removes expired challenges to prevent memory leaks.
// This should be called periodically by the application.
func (rv *RemoteVerifier) CleanupExpiredChallenges() int {
	rv.mu.Lock()
	defer rv.mu.Unlock()

	now := time.Now()
	removed := 0

	for id, challenge := range rv.activeChallenges {
		if now.After(challenge.ExpiresAt) {
			delete(rv.activeChallenges, id)
			removed++
		}
	}

	return removed
}

// CleanupExpiredEnrollments removes expired enrollments to prevent memory leaks.
// This should be called periodically by the application.
func (rv *RemoteVerifier) CleanupExpiredEnrollments() int {
	rv.mu.Lock()
	defer rv.mu.Unlock()

	now := time.Now()
	removed := 0

	for id, enrollment := range rv.enrolledDevices {
		if now.After(enrollment.ExpiresAt) {
			delete(rv.enrolledDevices, id)
			removed++
		}
	}

	return removed
}

// GetEnrollment returns a device's enrollment.
func (rv *RemoteVerifier) GetEnrollment(deviceID [32]byte) (*DeviceEnrollment, error) {
	rv.mu.RLock()
	defer rv.mu.RUnlock()

	enrollment, ok := rv.enrolledDevices[string(deviceID[:])]
	if !ok {
		return nil, ErrDeviceNotEnrolled
	}

	if time.Now().After(enrollment.ExpiresAt) {
		return nil, ErrEnrollmentExpired
	}

	return enrollment, nil
}

// CreateVerificationChallenge creates a challenge for verification.
func (rv *RemoteVerifier) CreateVerificationChallenge(
	request *VerificationRequest,
) (*VerificationChallenge, error) {
	rv.mu.Lock()
	defer rv.mu.Unlock()

	// Verify device is enrolled
	enrollment, ok := rv.enrolledDevices[string(request.DeviceID[:])]
	if !ok {
		return nil, ErrDeviceNotEnrolled
	}

	if time.Now().After(enrollment.ExpiresAt) {
		return nil, ErrEnrollmentExpired
	}

	// Generate challenge ID
	var challengeID [32]byte
	if _, err := rand.Read(challengeID[:]); err != nil {
		return nil, err
	}

	// Generate TPM nonce
	var tpmNonce [32]byte
	if _, err := rand.Read(tpmNonce[:]); err != nil {
		return nil, err
	}

	// Generate PUF challenge
	pufChallenge := make([]byte, 32)
	if _, err := rand.Read(pufChallenge); err != nil {
		return nil, err
	}

	// Get minimum expected counter
	var minCounter uint64
	if request.SessionExport != nil {
		minCounter = request.SessionExport.FinalCounter
	}

	challenge := &VerificationChallenge{
		ChallengeID:  challengeID,
		DeviceID:     request.DeviceID,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(rv.config.ChallengeTimeout),
		TPMNonce:     tpmNonce,
		RequiredPCRs: []int{0, 1, 2, 3, 4, 7},
		PUFChallenge: pufChallenge,
		MinCounter:   minCounter,
	}

	// Store challenge
	rv.activeChallenges[string(challengeID[:])] = challenge

	return challenge, nil
}

// Verify completes verification with the device's response.
func (rv *RemoteVerifier) Verify(
	request *VerificationRequest,
	challenge *VerificationChallenge,
	response *VerificationResponse,
) (*VerificationReport, error) {
	rv.mu.Lock()
	defer rv.mu.Unlock()

	report := &VerificationReport{
		Verified:     true,
		VerifiedAt:   time.Now(),
		DeviceID:     request.DeviceID,
		ConfidenceScore: 100,
	}

	// Verify challenge exists and hasn't been used (replay protection)
	if _, ok := rv.activeChallenges[string(challenge.ChallengeID[:])]; !ok {
		report.Verified = false
		report.Errors = append(report.Errors, "invalid or already used challenge")
		report.ConfidenceScore = 0
		return report, nil
	}

	// Get enrollment
	enrollment, ok := rv.enrolledDevices[string(request.DeviceID[:])]
	if !ok {
		report.Verified = false
		report.Errors = append(report.Errors, "device not enrolled")
		report.ConfidenceScore = 0
		// Clean up challenge on failure
		delete(rv.activeChallenges, string(challenge.ChallengeID[:]))
		return report, nil
	}
	report.DeviceName = enrollment.DeviceName

	// Fill in session info
	if request.SessionExport != nil {
		report.SessionID = request.SessionExport.SessionID
		report.SessionStart = request.SessionExport.SessionStart
		report.KeystrokeCount = request.SessionExport.KeystrokeCount
		report.CheckpointCount = len(request.SessionExport.Checkpoints)
	}

	// Verify challenge hasn't expired - fail immediately on expired challenges
	if time.Now().After(challenge.ExpiresAt) {
		report.Verified = false
		report.Errors = append(report.Errors, "challenge expired")
		report.ConfidenceScore = 0
		// Clean up expired challenge
		delete(rv.activeChallenges, string(challenge.ChallengeID[:]))
		return report, nil
	}

	// Verify TPM quote
	report.TPMVerified = rv.verifyTPMQuote(enrollment, challenge, response, report)
	if !report.TPMVerified {
		report.Verified = false
		report.ConfidenceScore -= 30
	}

	// Verify PUF response
	report.PUFVerified = rv.verifyPUFResponse(enrollment, challenge, response, report)
	if !report.PUFVerified {
		report.Verified = false
		report.ConfidenceScore -= 30
	}

	// Verify counter
	report.CounterVerified = rv.verifyCounter(challenge, response, report)
	if !report.CounterVerified {
		report.Verified = false
		report.ConfidenceScore -= 20
	}

	// Verify attestation chain
	if request.SessionExport != nil {
		report.ChainVerified = rv.verifyChain(request.SessionExport, report)
		if !report.ChainVerified {
			report.Verified = false
			report.ConfidenceScore -= 20
		}

		// Verify timeline
		report.TimelineVerified = rv.verifyTimeline(request.SessionExport, report)
		if !report.TimelineVerified {
			report.Warnings = append(report.Warnings, "timeline inconsistencies detected")
			report.ConfidenceScore -= 10
		}
	}

	// Ensure confidence score is in valid range
	if report.ConfidenceScore < 0 {
		report.ConfidenceScore = 0
	}

	// Invoke callback
	if rv.onVerificationComplete != nil {
		go rv.onVerificationComplete(report)
	}

	// Clean up challenge
	delete(rv.activeChallenges, string(challenge.ChallengeID[:]))

	return report, nil
}

// verifyTPMQuote verifies the TPM quote.
func (rv *RemoteVerifier) verifyTPMQuote(
	enrollment *DeviceEnrollment,
	challenge *VerificationChallenge,
	response *VerificationResponse,
	report *VerificationReport,
) bool {
	if !rv.config.RequireTPM {
		return true
	}

	if response.TPMQuote == nil {
		report.Errors = append(report.Errors, "missing TPM quote")
		return false
	}

	// Verify nonce matches challenge
	if !bytes.Equal(response.TPMQuote.Nonce, challenge.TPMNonce[:]) {
		report.Errors = append(report.Errors, "TPM nonce mismatch")
		return false
	}

	// Verify PCR values against enrollment
	if enrollment.InitialPCRs != nil && response.TPMQuote.PCRValues != nil {
		for pcr, expected := range enrollment.InitialPCRs {
			if actual, ok := response.TPMQuote.PCRValues[pcr]; ok {
				if !hmac.Equal(expected, actual) {
					report.Errors = append(report.Errors,
						fmt.Sprintf("PCR%d value changed since enrollment", pcr))
					return false
				}
			}
		}
	}

	// Verify PCR values against trusted values
	if rv.config.StrictPCRCheck && len(rv.trustedPCRs) > 0 {
		for pcr, trustedValues := range rv.trustedPCRs {
			if actual, ok := response.TPMQuote.PCRValues[pcr]; ok {
				trusted := false
				for _, tv := range trustedValues {
					if hmac.Equal(actual, tv) {
						trusted = true
						break
					}
				}
				if !trusted {
					report.Warnings = append(report.Warnings,
						fmt.Sprintf("PCR%d has untrusted value", pcr))
				}
			}
		}
	}

	return true
}

// verifyPUFResponse verifies the PUF response.
func (rv *RemoteVerifier) verifyPUFResponse(
	enrollment *DeviceEnrollment,
	challenge *VerificationChallenge,
	response *VerificationResponse,
	report *VerificationReport,
) bool {
	if !rv.config.RequirePUF {
		return true
	}

	if len(response.PUFResponse) == 0 {
		report.Errors = append(report.Errors, "missing PUF response")
		return false
	}

	// For PUF verification, we can't compare exact responses due to noise
	// Instead, we verify:
	// 1. Response has expected length
	// 2. Response is not all zeros
	// 3. Response is not identical to enrollment (would indicate replay attack)

	if len(response.PUFResponse) < 16 {
		report.Errors = append(report.Errors, "PUF response too short")
		return false
	}

	// Check not all zeros
	allZero := true
	for _, b := range response.PUFResponse {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		report.Errors = append(report.Errors, "PUF response is all zeros")
		return false
	}

	// Check not identical to enrollment response (replay attack detection)
	// An identical response to a different challenge indicates replay
	if bytes.Equal(response.PUFResponse, enrollment.EnrollmentResponse) {
		report.Errors = append(report.Errors, "PUF response replay detected")
		return false
	}

	return true
}

// verifyCounter verifies the TPM counter value.
func (rv *RemoteVerifier) verifyCounter(
	challenge *VerificationChallenge,
	response *VerificationResponse,
	report *VerificationReport,
) bool {
	// Counter must be >= minimum expected
	if response.CurrentCounter < challenge.MinCounter {
		report.Errors = append(report.Errors,
			fmt.Sprintf("counter rollback: expected >= %d, got %d",
				challenge.MinCounter, response.CurrentCounter))
		return false
	}

	return true
}

// verifyChain verifies the attestation chain integrity.
func (rv *RemoteVerifier) verifyChain(
	export *AttestationSessionExport,
	report *VerificationReport,
) bool {
	verifier := NewAttestationVerifier()

	// Pass trusted PCR values to the verifier
	for pcr, values := range rv.trustedPCRs {
		for _, value := range values {
			verifier.AddTrustedPCRValue(pcr, value)
		}
	}

	result, err := verifier.VerifyChain(export)
	if err != nil {
		report.Errors = append(report.Errors, fmt.Sprintf("chain verification error: %v", err))
		return false
	}

	if !result.Valid {
		for _, e := range result.Errors {
			report.Errors = append(report.Errors, e)
		}
		return false
	}

	for _, w := range result.Warnings {
		report.Warnings = append(report.Warnings, w)
	}

	return true
}

// verifyTimeline verifies the timeline is consistent.
func (rv *RemoteVerifier) verifyTimeline(
	export *AttestationSessionExport,
	report *VerificationReport,
) bool {
	if len(export.Checkpoints) == 0 {
		return true
	}

	// Verify timestamps are monotonically increasing
	var lastTime time.Time
	for i, cp := range export.Checkpoints {
		if i > 0 && cp.Timestamp.Before(lastTime) {
			report.Warnings = append(report.Warnings,
				fmt.Sprintf("timestamp regression at checkpoint %d", i))
			return false
		}
		lastTime = cp.Timestamp
	}

	// Verify reasonable typing speed
	if len(export.Checkpoints) >= 2 {
		first := export.Checkpoints[0]
		last := export.Checkpoints[len(export.Checkpoints)-1]
		duration := last.Timestamp.Sub(first.Timestamp)

		if duration > 0 {
			keystrokesPerSecond := float64(export.KeystrokeCount) / duration.Seconds()
			// Typical typing: 5-10 characters per second
			// Very fast: up to 15-20
			// Suspicious: > 50
			if keystrokesPerSecond > 50 {
				report.Warnings = append(report.Warnings,
					fmt.Sprintf("unusually fast typing: %.1f keystrokes/sec", keystrokesPerSecond))
			}
		}
	}

	// Verify session start is reasonable
	now := time.Now()
	if export.SessionStart.After(now) {
		report.Errors = append(report.Errors, "session start is in the future")
		return false
	}

	// Check for excessive clock drift
	if export.SessionStart.Before(now.Add(-365 * 24 * time.Hour)) {
		report.Warnings = append(report.Warnings, "session started more than a year ago")
	}

	return true
}

// ExportEnrollments exports all enrollments for backup.
func (rv *RemoteVerifier) ExportEnrollments() ([]byte, error) {
	rv.mu.RLock()
	defer rv.mu.RUnlock()

	enrollments := make([]*DeviceEnrollment, 0, len(rv.enrolledDevices))
	for _, e := range rv.enrolledDevices {
		enrollments = append(enrollments, e)
	}

	return json.Marshal(enrollments)
}

// ImportEnrollments imports enrollments from backup.
func (rv *RemoteVerifier) ImportEnrollments(data []byte) error {
	var enrollments []*DeviceEnrollment
	if err := json.Unmarshal(data, &enrollments); err != nil {
		return err
	}

	rv.mu.Lock()
	defer rv.mu.Unlock()

	for _, e := range enrollments {
		rv.enrolledDevices[string(e.DeviceID[:])] = e
	}

	return nil
}

// DeviceProver handles the prover side of verification.
type DeviceProver struct {
	mu sync.RWMutex

	// Device identity
	deviceID [32]byte

	// TPM interface
	tpm TPMInterface

	// PUF interface
	puf PUF

	// Enrollment data
	enrollment *DeviceEnrollment
}

// NewDeviceProver creates a new device prover.
func NewDeviceProver(tpm TPMInterface, puf PUF) (*DeviceProver, error) {
	dp := &DeviceProver{
		tpm: tpm,
		puf: puf,
	}

	// Generate device ID
	if err := dp.computeDeviceID(); err != nil {
		return nil, err
	}

	return dp, nil
}

// computeDeviceID computes the device's unique ID.
// Returns an error if neither TPM nor PUF can provide identity data.
func (dp *DeviceProver) computeDeviceID() error {
	h := sha256.New()
	h.Write([]byte("witnessd-device-id-v1"))

	var hasTPMIdentity, hasPUFIdentity bool
	var tpmErr, pufErr error

	// Include TPM endorsement key
	if dp.tpm != nil && dp.tpm.Available() {
		ek, err := dp.tpm.GetEndorsementKeyPublic()
		if err == nil {
			h.Write(ek)
			hasTPMIdentity = true
		} else {
			tpmErr = err
		}
	}

	// Include PUF fingerprint (hashed to match enrollment)
	if dp.puf != nil {
		response, err := dp.puf.Challenge([]byte("device-fingerprint"))
		if err == nil {
			// Hash the PUF response to create fingerprint (matches enrollment)
			fingerprint := sha256.Sum256(response)
			h.Write(fingerprint[:])
			hasPUFIdentity = true
		} else {
			pufErr = err
		}
	}

	// Require at least one identity source for a unique device ID
	if !hasTPMIdentity && !hasPUFIdentity {
		if tpmErr != nil && pufErr != nil {
			return fmt.Errorf("failed to compute device ID: TPM error: %v, PUF error: %v", tpmErr, pufErr)
		}
		if dp.tpm == nil && dp.puf == nil {
			return errors.New("failed to compute device ID: no TPM or PUF available")
		}
		// One or both unavailable without error (e.g., TPM not available)
		return errors.New("failed to compute device ID: no identity source available")
	}

	copy(dp.deviceID[:], h.Sum(nil))
	return nil
}

// DeviceID returns the device's unique identifier.
func (dp *DeviceProver) DeviceID() [32]byte {
	return dp.deviceID
}

// SetEnrollment stores the enrollment data and updates device ID.
// This should be called after successful enrollment.
func (dp *DeviceProver) SetEnrollment(enrollment *DeviceEnrollment) {
	dp.mu.Lock()
	defer dp.mu.Unlock()
	dp.enrollment = enrollment
	dp.deviceID = enrollment.DeviceID
}

// RespondToEnrollmentChallenge responds to an enrollment challenge.
func (dp *DeviceProver) RespondToEnrollmentChallenge(
	challenge *EnrollmentChallengeData,
) (*EnrollmentResponseData, error) {
	dp.mu.Lock()
	defer dp.mu.Unlock()

	response := &EnrollmentResponseData{}

	// Get TPM data
	if dp.tpm != nil && dp.tpm.Available() {
		// Get endorsement key
		ek, err := dp.tpm.GetEndorsementKeyPublic()
		if err != nil {
			return nil, fmt.Errorf("failed to get endorsement key: %w", err)
		}
		response.EndorsementKey = ek
		response.AttestationKey = ek // In real TPM, this would be different

		// Get quote
		quote, err := dp.tpm.Quote(challenge.Nonce[:], challenge.RequiredPCRs)
		if err != nil {
			return nil, fmt.Errorf("failed to get TPM quote: %w", err)
		}
		response.TPMQuote = quote
	}

	// Get PUF data
	if dp.puf != nil {
		// Get fingerprint
		fingerprint, err := dp.puf.Challenge([]byte("device-fingerprint"))
		if err == nil {
			response.PUFFingerprint = sha256.Sum256(fingerprint)
		}

		// Respond to challenge
		pufResponse, err := dp.puf.Challenge(challenge.PUFChallenge)
		if err != nil {
			return nil, fmt.Errorf("failed to respond to PUF challenge: %w", err)
		}
		response.PUFResponse = pufResponse
		response.PUFType = dp.puf.Type().String()
	}

	return response, nil
}

// RespondToVerificationChallenge responds to a verification challenge.
func (dp *DeviceProver) RespondToVerificationChallenge(
	challenge *VerificationChallenge,
) (*VerificationResponse, error) {
	dp.mu.Lock()
	defer dp.mu.Unlock()

	response := &VerificationResponse{
		ChallengeID: challenge.ChallengeID,
		DeviceID:    dp.deviceID,
		RespondedAt: time.Now(),
	}

	// Get TPM quote
	if dp.tpm != nil && dp.tpm.Available() {
		quote, err := dp.tpm.Quote(challenge.TPMNonce[:], challenge.RequiredPCRs)
		if err != nil {
			return nil, fmt.Errorf("failed to get TPM quote: %w", err)
		}
		response.TPMQuote = quote

		// Get current counter
		counter, err := dp.tpm.ReadCounter(0)
		if err == nil {
			response.CurrentCounter = counter
		}
	}

	// Get PUF response
	if dp.puf != nil {
		pufResponse, err := dp.puf.Challenge(challenge.PUFChallenge)
		if err != nil {
			return nil, fmt.Errorf("failed to respond to PUF challenge: %w", err)
		}
		response.PUFResponse = pufResponse
	}

	return response, nil
}

// VerificationSession handles a complete verification flow.
type VerificationSession struct {
	prover   *DeviceProver
	verifier *RemoteVerifier

	// Session state
	request   *VerificationRequest
	challenge *VerificationChallenge
	response  *VerificationResponse
	report    *VerificationReport
}

// NewVerificationSession creates a new verification session.
func NewVerificationSession(prover *DeviceProver, verifier *RemoteVerifier) *VerificationSession {
	return &VerificationSession{
		prover:   prover,
		verifier: verifier,
	}
}

// StartVerification initiates verification with a session export.
func (vs *VerificationSession) StartVerification(export *AttestationSessionExport) error {
	vs.request = &VerificationRequest{
		DeviceID:      vs.prover.DeviceID(),
		SessionExport: export,
		RequestedAt:   time.Now(),
	}

	// Get challenge from verifier
	challenge, err := vs.verifier.CreateVerificationChallenge(vs.request)
	if err != nil {
		return err
	}
	vs.challenge = challenge

	return nil
}

// RespondToChallenge responds to the verification challenge.
func (vs *VerificationSession) RespondToChallenge() error {
	if vs.challenge == nil {
		return errors.New("no active challenge")
	}

	response, err := vs.prover.RespondToVerificationChallenge(vs.challenge)
	if err != nil {
		return err
	}
	vs.response = response

	return nil
}

// CompleteVerification completes the verification.
func (vs *VerificationSession) CompleteVerification() (*VerificationReport, error) {
	if vs.response == nil {
		return nil, errors.New("no response")
	}

	report, err := vs.verifier.Verify(vs.request, vs.challenge, vs.response)
	if err != nil {
		return nil, err
	}
	vs.report = report

	return report, nil
}

// SerializeVerificationReport serializes a report to JSON.
func SerializeVerificationReport(report *VerificationReport) ([]byte, error) {
	return json.MarshalIndent(report, "", "  ")
}

// VerificationEvidence bundles all evidence for independent verification.
type VerificationEvidence struct {
	// Device identity
	DeviceEnrollment *DeviceEnrollment `json:"device_enrollment"`

	// Session data
	SessionExport *AttestationSessionExport `json:"session_export"`

	// Challenge-response
	Challenge *VerificationChallenge `json:"challenge"`
	Response  *VerificationResponse  `json:"response"`

	// Verification result
	Report *VerificationReport `json:"report"`

	// Metadata
	CreatedAt time.Time `json:"created_at"`
	Version   string    `json:"version"`
}

// PackageEvidence packages all evidence for archival.
func PackageEvidence(
	enrollment *DeviceEnrollment,
	export *AttestationSessionExport,
	challenge *VerificationChallenge,
	response *VerificationResponse,
	report *VerificationReport,
) *VerificationEvidence {
	return &VerificationEvidence{
		DeviceEnrollment: enrollment,
		SessionExport:    export,
		Challenge:        challenge,
		Response:         response,
		Report:           report,
		CreatedAt:        time.Now(),
		Version:          "1.0",
	}
}

// SerializeEvidence serializes evidence to JSON.
func (e *VerificationEvidence) Serialize() ([]byte, error) {
	return json.MarshalIndent(e, "", "  ")
}

// ComputeEvidenceHash computes a hash of the evidence for signing.
func (e *VerificationEvidence) ComputeEvidenceHash() [32]byte {
	h := sha256.New()

	h.Write([]byte("witnessd-evidence-v1"))
	h.Write(e.DeviceEnrollment.DeviceID[:])
	h.Write(e.SessionExport.SessionID[:])
	binary.Write(h, binary.BigEndian, e.SessionExport.KeystrokeCount)
	binary.Write(h, binary.BigEndian, e.Report.ConfidenceScore)
	binary.Write(h, binary.BigEndian, e.CreatedAt.UnixNano())

	var hash [32]byte
	copy(hash[:], h.Sum(nil))
	return hash
}
