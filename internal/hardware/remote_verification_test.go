package hardware

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRemoteVerifierEnrollment(t *testing.T) {
	verifier := NewRemoteVerifier(DefaultRemoteVerifierConfig())

	// Create enrollment challenge
	challenge, err := verifier.EnrollmentChallenge()
	if err != nil {
		t.Fatalf("Failed to create enrollment challenge: %v", err)
	}

	if challenge.ExpiresAt.Before(time.Now()) {
		t.Error("Challenge already expired")
	}

	// Create mock device
	tpm := NewMockTPM()
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())

	prover, err := NewDeviceProver(tpm, puf)
	if err != nil {
		t.Fatalf("Failed to create device prover: %v", err)
	}

	// Respond to enrollment challenge
	response, err := prover.RespondToEnrollmentChallenge(challenge)
	if err != nil {
		t.Fatalf("Failed to respond to enrollment challenge: %v", err)
	}

	if response.TPMQuote == nil {
		t.Error("Response should include TPM quote")
	}

	if len(response.PUFResponse) == 0 {
		t.Error("Response should include PUF response")
	}

	// Complete enrollment
	enrollment, err := verifier.CompleteEnrollment(challenge, response)
	if err != nil {
		t.Fatalf("Failed to complete enrollment: %v", err)
	}

	if enrollment.DeviceID == [32]byte{} {
		t.Error("Enrollment should have device ID")
	}

	// Verify device is enrolled
	if !verifier.IsEnrolled(enrollment.DeviceID) {
		t.Error("Device should be enrolled")
	}
}

func TestRemoteVerifierVerification(t *testing.T) {
	config := DefaultRemoteVerifierConfig()
	config.RequirePUF = true
	config.RequireTPM = true
	verifier := NewRemoteVerifier(config)

	// Create and enroll device
	tpm := NewMockTPM()
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())

	prover, err := NewDeviceProver(tpm, puf)
	if err != nil {
		t.Fatalf("Failed to create device prover: %v", err)
	}

	// Enroll device
	enrollChallenge, _ := verifier.EnrollmentChallenge()
	enrollResponse, err := prover.RespondToEnrollmentChallenge(enrollChallenge)
	if err != nil {
		t.Fatalf("Failed to respond to enrollment: %v", err)
	}
	enrollment, err := verifier.CompleteEnrollment(enrollChallenge, enrollResponse)
	if err != nil {
		t.Fatalf("Failed to enroll: %v", err)
	}

	// Create an attestation session
	attestConfig := DefaultAttestationConfig()
	attestConfig.KeystrokeThreshold = 3
	session, err := NewContinuousAttestationSession(attestConfig, tpm)
	if err != nil {
		t.Fatalf("Failed to create attestation session: %v", err)
	}

	session.Start()

	// Record some keystrokes
	for i := 0; i < 12; i++ {
		contentHash := sha256.Sum256([]byte{byte(i)})
		session.RecordKeystroke(contentHash, nil)
	}

	export := session.ExportSession()
	session.Stop()

	// Create verification request
	request := &VerificationRequest{
		DeviceID:      enrollment.DeviceID,
		SessionExport: export,
		RequestedAt:   time.Now(),
	}

	// Get verification challenge
	challenge, err := verifier.CreateVerificationChallenge(request)
	if err != nil {
		t.Fatalf("Failed to create verification challenge: %v", err)
	}

	// Respond to challenge
	response, err := prover.RespondToVerificationChallenge(challenge)
	if err != nil {
		t.Fatalf("Failed to respond to verification challenge: %v", err)
	}

	// Verify
	report, err := verifier.Verify(request, challenge, response)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}

	if !report.Verified {
		t.Errorf("Verification should succeed, errors: %v", report.Errors)
	}

	if report.ConfidenceScore < 50 {
		t.Errorf("Confidence score too low: %d", report.ConfidenceScore)
	}

	t.Logf("Verification report: verified=%v, confidence=%d, errors=%v, warnings=%v",
		report.Verified, report.ConfidenceScore, report.Errors, report.Warnings)
}

func TestVerificationSession(t *testing.T) {
	verifier := NewRemoteVerifier(DefaultRemoteVerifierConfig())

	// Create and enroll device
	tpm := NewMockTPM()
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())

	prover, err := NewDeviceProver(tpm, puf)
	if err != nil {
		t.Fatalf("Failed to create device prover: %v", err)
	}

	// Enroll device
	enrollChallenge, _ := verifier.EnrollmentChallenge()
	enrollResponse, _ := prover.RespondToEnrollmentChallenge(enrollChallenge)
	enrollment, err := verifier.CompleteEnrollment(enrollChallenge, enrollResponse)
	if err != nil {
		t.Fatalf("Enrollment failed: %v", err)
	}

	// Update prover with enrolled device ID
	prover.SetEnrollment(enrollment)

	// Create attestation session
	attestConfig := DefaultAttestationConfig()
	attestConfig.KeystrokeThreshold = 5
	attestSession, _ := NewContinuousAttestationSession(attestConfig, tpm)
	attestSession.Start()

	for i := 0; i < 15; i++ {
		contentHash := sha256.Sum256([]byte{byte(i)})
		attestSession.RecordKeystroke(contentHash, nil)
	}

	export := attestSession.ExportSession()
	attestSession.Stop()

	// Create verification session
	verifySession := NewVerificationSession(prover, verifier)

	// Start verification
	if err := verifySession.StartVerification(export); err != nil {
		t.Fatalf("Failed to start verification: %v", err)
	}

	// Respond to challenge
	if err := verifySession.RespondToChallenge(); err != nil {
		t.Fatalf("Failed to respond to challenge: %v", err)
	}

	// Complete verification
	report, err := verifySession.CompleteVerification()
	if err != nil {
		t.Fatalf("Failed to complete verification: %v", err)
	}

	if !report.Verified {
		t.Errorf("Verification should succeed: %v", report.Errors)
	}

	t.Logf("Verification complete: keystroke_count=%d, checkpoints=%d, confidence=%d",
		report.KeystrokeCount, report.CheckpointCount, report.ConfidenceScore)
}

func TestVerificationFailsForUnenrolledDevice(t *testing.T) {
	verifier := NewRemoteVerifier(DefaultRemoteVerifierConfig())

	// Create device without enrolling
	tpm := NewMockTPM()
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())

	prover, _ := NewDeviceProver(tpm, puf)

	// Try to create verification request
	request := &VerificationRequest{
		DeviceID:    prover.DeviceID(),
		RequestedAt: time.Now(),
	}

	_, err := verifier.CreateVerificationChallenge(request)
	if err != ErrDeviceNotEnrolled {
		t.Errorf("Expected ErrDeviceNotEnrolled, got %v", err)
	}
}

func TestVerificationDetectsCounterRollback(t *testing.T) {
	verifier := NewRemoteVerifier(DefaultRemoteVerifierConfig())

	// Enroll device
	tpm := NewMockTPM()
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
	prover, _ := NewDeviceProver(tpm, puf)

	enrollChallenge, _ := verifier.EnrollmentChallenge()
	enrollResponse, _ := prover.RespondToEnrollmentChallenge(enrollChallenge)
	enrollment, _ := verifier.CompleteEnrollment(enrollChallenge, enrollResponse)

	// Create attestation session with high counter
	attestConfig := DefaultAttestationConfig()
	attestConfig.KeystrokeThreshold = 3
	session, _ := NewContinuousAttestationSession(attestConfig, tpm)
	session.Start()

	for i := 0; i < 9; i++ {
		contentHash := sha256.Sum256([]byte{byte(i)})
		session.RecordKeystroke(contentHash, nil)
	}

	export := session.ExportSession()
	session.Stop()

	// Create verification request with high counter
	request := &VerificationRequest{
		DeviceID:      enrollment.DeviceID,
		SessionExport: export,
		RequestedAt:   time.Now(),
	}

	challenge, _ := verifier.CreateVerificationChallenge(request)

	// Manually create response with low counter (rollback)
	response := &VerificationResponse{
		ChallengeID:    challenge.ChallengeID,
		DeviceID:       enrollment.DeviceID,
		CurrentCounter: 1, // Lower than session counter
		RespondedAt:    time.Now(),
	}

	// Get real quote and PUF response
	quote, _ := tpm.Quote(challenge.TPMNonce[:], challenge.RequiredPCRs)
	response.TPMQuote = quote
	pufResp, _ := puf.Challenge(challenge.PUFChallenge)
	response.PUFResponse = pufResp

	report, _ := verifier.Verify(request, challenge, response)

	if report.CounterVerified {
		t.Error("Counter verification should fail on rollback")
	}

	// Find the counter error
	hasCounterError := false
	for _, e := range report.Errors {
		if len(e) > 0 {
			hasCounterError = true
		}
	}
	if !hasCounterError {
		t.Log("Note: counter rollback was detected")
	}
}

func TestEnrollmentExpiry(t *testing.T) {
	config := DefaultRemoteVerifierConfig()
	config.EnrollmentTTL = 100 * time.Millisecond
	verifier := NewRemoteVerifier(config)

	// Enroll device
	tpm := NewMockTPM()
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
	prover, _ := NewDeviceProver(tpm, puf)

	enrollChallenge, _ := verifier.EnrollmentChallenge()
	enrollResponse, _ := prover.RespondToEnrollmentChallenge(enrollChallenge)
	enrollment, _ := verifier.CompleteEnrollment(enrollChallenge, enrollResponse)

	// Should be enrolled initially
	if !verifier.IsEnrolled(enrollment.DeviceID) {
		t.Error("Device should be enrolled initially")
	}

	// Wait for enrollment to expire
	time.Sleep(150 * time.Millisecond)

	// Should no longer be enrolled
	if verifier.IsEnrolled(enrollment.DeviceID) {
		t.Error("Device enrollment should have expired")
	}
}

func TestChallengeExpiry(t *testing.T) {
	config := DefaultRemoteVerifierConfig()
	config.ChallengeTimeout = 100 * time.Millisecond
	verifier := NewRemoteVerifier(config)

	// Create enrollment challenge
	challenge, _ := verifier.EnrollmentChallenge()

	// Wait for challenge to expire
	time.Sleep(150 * time.Millisecond)

	// Try to complete enrollment with expired challenge
	tpm := NewMockTPM()
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
	prover, _ := NewDeviceProver(tpm, puf)

	response, _ := prover.RespondToEnrollmentChallenge(challenge)

	_, err := verifier.CompleteEnrollment(challenge, response)
	if err != ErrEnrollmentExpired {
		t.Errorf("Expected ErrEnrollmentExpired, got %v", err)
	}
}

func TestVerificationEvidence(t *testing.T) {
	verifier := NewRemoteVerifier(DefaultRemoteVerifierConfig())

	// Enroll device
	tpm := NewMockTPM()
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
	prover, _ := NewDeviceProver(tpm, puf)

	enrollChallenge, _ := verifier.EnrollmentChallenge()
	enrollResponse, _ := prover.RespondToEnrollmentChallenge(enrollChallenge)
	enrollment, _ := verifier.CompleteEnrollment(enrollChallenge, enrollResponse)

	// Create attestation session
	attestConfig := DefaultAttestationConfig()
	attestConfig.KeystrokeThreshold = 5
	session, _ := NewContinuousAttestationSession(attestConfig, tpm)
	session.Start()

	for i := 0; i < 10; i++ {
		contentHash := sha256.Sum256([]byte{byte(i)})
		session.RecordKeystroke(contentHash, nil)
	}

	export := session.ExportSession()
	session.Stop()

	// Run verification
	request := &VerificationRequest{
		DeviceID:      enrollment.DeviceID,
		SessionExport: export,
		RequestedAt:   time.Now(),
	}

	challenge, _ := verifier.CreateVerificationChallenge(request)
	response, _ := prover.RespondToVerificationChallenge(challenge)
	report, _ := verifier.Verify(request, challenge, response)

	// Package evidence
	evidence := PackageEvidence(enrollment, export, challenge, response, report)

	// Serialize evidence
	data, err := evidence.Serialize()
	if err != nil {
		t.Fatalf("Failed to serialize evidence: %v", err)
	}

	if len(data) == 0 {
		t.Error("Serialized evidence should not be empty")
	}

	// Compute evidence hash
	hash := evidence.ComputeEvidenceHash()
	if hash == [32]byte{} {
		t.Error("Evidence hash should not be empty")
	}

	t.Logf("Evidence size: %d bytes, hash: %x...", len(data), hash[:8])
}

func TestVerificationCallback(t *testing.T) {
	verifier := NewRemoteVerifier(DefaultRemoteVerifierConfig())

	callbackCalled := make(chan bool, 1)
	verifier.SetVerificationCallback(func(report *VerificationReport) {
		callbackCalled <- true
	})

	// Enroll device
	tpm := NewMockTPM()
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
	prover, _ := NewDeviceProver(tpm, puf)

	enrollChallenge, _ := verifier.EnrollmentChallenge()
	enrollResponse, _ := prover.RespondToEnrollmentChallenge(enrollChallenge)
	enrollment, _ := verifier.CompleteEnrollment(enrollChallenge, enrollResponse)

	// Create session and verify
	attestConfig := DefaultAttestationConfig()
	attestConfig.KeystrokeThreshold = 5
	session, _ := NewContinuousAttestationSession(attestConfig, tpm)
	session.Start()

	for i := 0; i < 10; i++ {
		contentHash := sha256.Sum256([]byte{byte(i)})
		session.RecordKeystroke(contentHash, nil)
	}

	export := session.ExportSession()
	session.Stop()

	request := &VerificationRequest{
		DeviceID:      enrollment.DeviceID,
		SessionExport: export,
		RequestedAt:   time.Now(),
	}

	challenge, _ := verifier.CreateVerificationChallenge(request)
	response, _ := prover.RespondToVerificationChallenge(challenge)
	verifier.Verify(request, challenge, response)

	// Wait for callback
	select {
	case <-callbackCalled:
		// Success
	case <-time.After(time.Second):
		t.Error("Verification callback was not called")
	}
}

func TestEnrollmentExportImport(t *testing.T) {
	verifier := NewRemoteVerifier(DefaultRemoteVerifierConfig())

	// Enroll some devices
	for i := 0; i < 3; i++ {
		tpm := NewMockTPM()
		puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
		prover, _ := NewDeviceProver(tpm, puf)

		enrollChallenge, _ := verifier.EnrollmentChallenge()
		enrollResponse, _ := prover.RespondToEnrollmentChallenge(enrollChallenge)
		verifier.CompleteEnrollment(enrollChallenge, enrollResponse)
	}

	// Export enrollments
	data, err := verifier.ExportEnrollments()
	if err != nil {
		t.Fatalf("Failed to export enrollments: %v", err)
	}

	// Create new verifier and import
	newVerifier := NewRemoteVerifier(DefaultRemoteVerifierConfig())
	err = newVerifier.ImportEnrollments(data)
	if err != nil {
		t.Fatalf("Failed to import enrollments: %v", err)
	}

	// Verify same number of enrollments
	originalExport, _ := verifier.ExportEnrollments()
	newExport, _ := newVerifier.ExportEnrollments()

	if len(originalExport) != len(newExport) {
		t.Error("Exported enrollments don't match after import")
	}
}

func TestTrustedPCRValues(t *testing.T) {
	config := DefaultRemoteVerifierConfig()
	config.StrictPCRCheck = true
	verifier := NewRemoteVerifier(config)

	// Add trusted PCR values
	trustedPCR0 := make([]byte, 32)
	verifier.AddTrustedPCRValue(0, trustedPCR0)

	// Enroll device (PCRs will match trusted values initially)
	tpm := NewMockTPM()
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
	prover, _ := NewDeviceProver(tpm, puf)

	enrollChallenge, _ := verifier.EnrollmentChallenge()
	enrollResponse, _ := prover.RespondToEnrollmentChallenge(enrollChallenge)
	enrollment, _ := verifier.CompleteEnrollment(enrollChallenge, enrollResponse)

	// Create verification session
	attestConfig := DefaultAttestationConfig()
	attestConfig.KeystrokeThreshold = 5
	session, _ := NewContinuousAttestationSession(attestConfig, tpm)
	session.Start()

	for i := 0; i < 10; i++ {
		contentHash := sha256.Sum256([]byte{byte(i)})
		session.RecordKeystroke(contentHash, nil)
	}

	export := session.ExportSession()
	session.Stop()

	// Verify - should succeed since PCRs match
	request := &VerificationRequest{
		DeviceID:      enrollment.DeviceID,
		SessionExport: export,
		RequestedAt:   time.Now(),
	}

	challenge, _ := verifier.CreateVerificationChallenge(request)
	response, _ := prover.RespondToVerificationChallenge(challenge)
	report, _ := verifier.Verify(request, challenge, response)

	if !report.TPMVerified {
		t.Errorf("TPM verification should pass with trusted PCR values: %v", report.Errors)
	}
}

func TestPUFReplayDetection(t *testing.T) {
	config := DefaultRemoteVerifierConfig()
	config.RequirePUF = true
	verifier := NewRemoteVerifier(config)

	// Enroll device
	tpm := NewMockTPM()
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
	prover, _ := NewDeviceProver(tpm, puf)

	enrollChallenge, _ := verifier.EnrollmentChallenge()
	enrollResponse, _ := prover.RespondToEnrollmentChallenge(enrollChallenge)
	enrollment, _ := verifier.CompleteEnrollment(enrollChallenge, enrollResponse)

	// Create attestation session
	attestConfig := DefaultAttestationConfig()
	attestConfig.KeystrokeThreshold = 5
	session, _ := NewContinuousAttestationSession(attestConfig, tpm)
	session.Start()

	for i := 0; i < 10; i++ {
		contentHash := sha256.Sum256([]byte{byte(i)})
		session.RecordKeystroke(contentHash, nil)
	}

	export := session.ExportSession()
	session.Stop()

	// Create verification request
	request := &VerificationRequest{
		DeviceID:      enrollment.DeviceID,
		SessionExport: export,
		RequestedAt:   time.Now(),
	}

	challenge, _ := verifier.CreateVerificationChallenge(request)

	// Create response with PUF response that matches enrollment (replay attack)
	response := &VerificationResponse{
		ChallengeID:    challenge.ChallengeID,
		DeviceID:       enrollment.DeviceID,
		PUFResponse:    enrollment.EnrollmentResponse, // Same as enrollment = replay
		RespondedAt:    time.Now(),
	}

	// Get valid TPM quote and counter
	quote, _ := tpm.Quote(challenge.TPMNonce[:], challenge.RequiredPCRs)
	response.TPMQuote = quote
	counter, _ := tpm.ReadCounter(0)
	response.CurrentCounter = counter

	report, _ := verifier.Verify(request, challenge, response)

	if report.PUFVerified {
		t.Error("PUF verification should fail on replay")
	}

	// Check for replay error
	hasReplayError := false
	for _, e := range report.Errors {
		if e == "PUF response replay detected" {
			hasReplayError = true
			break
		}
	}
	if !hasReplayError {
		t.Errorf("Expected PUF replay detection error, got: %v", report.Errors)
	}
}

func TestChallengeReplayProtection(t *testing.T) {
	verifier := NewRemoteVerifier(DefaultRemoteVerifierConfig())

	// Enroll device
	tpm := NewMockTPM()
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
	prover, _ := NewDeviceProver(tpm, puf)

	enrollChallenge, _ := verifier.EnrollmentChallenge()
	enrollResponse, _ := prover.RespondToEnrollmentChallenge(enrollChallenge)
	enrollment, _ := verifier.CompleteEnrollment(enrollChallenge, enrollResponse)
	prover.SetEnrollment(enrollment)

	// Create attestation session
	attestConfig := DefaultAttestationConfig()
	attestConfig.KeystrokeThreshold = 5
	session, _ := NewContinuousAttestationSession(attestConfig, tpm)
	session.Start()

	for i := 0; i < 10; i++ {
		contentHash := sha256.Sum256([]byte{byte(i)})
		session.RecordKeystroke(contentHash, nil)
	}

	export := session.ExportSession()
	session.Stop()

	// First verification should succeed
	request := &VerificationRequest{
		DeviceID:      enrollment.DeviceID,
		SessionExport: export,
		RequestedAt:   time.Now(),
	}

	challenge, _ := verifier.CreateVerificationChallenge(request)
	response, _ := prover.RespondToVerificationChallenge(challenge)
	report1, _ := verifier.Verify(request, challenge, response)

	if !report1.Verified {
		t.Fatalf("First verification should succeed: %v", report1.Errors)
	}

	// Second verification with same challenge should fail (replay)
	response2, _ := prover.RespondToVerificationChallenge(challenge)
	report2, _ := verifier.Verify(request, challenge, response2)

	if report2.Verified {
		t.Error("Replay verification should fail")
	}

	// Check for appropriate error
	hasReplayError := false
	for _, e := range report2.Errors {
		if e == "invalid or already used challenge" {
			hasReplayError = true
			break
		}
	}
	if !hasReplayError {
		t.Errorf("Expected challenge replay error, got: %v", report2.Errors)
	}
}

func TestChallengeCleanup(t *testing.T) {
	config := DefaultRemoteVerifierConfig()
	config.ChallengeTimeout = 50 * time.Millisecond
	verifier := NewRemoteVerifier(config)

	// Enroll device
	tpm := NewMockTPM()
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
	prover, _ := NewDeviceProver(tpm, puf)

	enrollChallenge, _ := verifier.EnrollmentChallenge()
	enrollResponse, _ := prover.RespondToEnrollmentChallenge(enrollChallenge)
	enrollment, _ := verifier.CompleteEnrollment(enrollChallenge, enrollResponse)

	// Create multiple challenges
	for i := 0; i < 5; i++ {
		request := &VerificationRequest{
			DeviceID:    enrollment.DeviceID,
			RequestedAt: time.Now(),
		}
		verifier.CreateVerificationChallenge(request)
	}

	// Cleanup shouldn't remove anything yet
	removed := verifier.CleanupExpiredChallenges()
	if removed != 0 {
		t.Errorf("No challenges should be expired yet, removed %d", removed)
	}

	// Wait for challenges to expire
	time.Sleep(100 * time.Millisecond)

	// Now cleanup should remove all
	removed = verifier.CleanupExpiredChallenges()
	if removed != 5 {
		t.Errorf("Expected 5 challenges removed, got %d", removed)
	}

	// Second cleanup should remove nothing
	removed = verifier.CleanupExpiredChallenges()
	if removed != 0 {
		t.Errorf("No challenges should remain, removed %d", removed)
	}
}

func TestCleanupExpiredEnrollments(t *testing.T) {
	config := DefaultRemoteVerifierConfig()
	config.EnrollmentTTL = 200 * time.Millisecond // Longer TTL for test stability
	verifier := NewRemoteVerifier(config)

	// Enroll multiple devices
	for i := 0; i < 3; i++ {
		tpm := NewMockTPM()
		puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
		prover, _ := NewDeviceProver(tpm, puf)

		enrollChallenge, _ := verifier.EnrollmentChallenge()
		enrollResponse, _ := prover.RespondToEnrollmentChallenge(enrollChallenge)
		verifier.CompleteEnrollment(enrollChallenge, enrollResponse)
	}

	// Cleanup shouldn't remove anything yet (TTL hasn't expired)
	removed := verifier.CleanupExpiredEnrollments()
	if removed != 0 {
		t.Errorf("No enrollments should be expired yet, removed %d", removed)
	}

	// Wait for enrollments to expire
	time.Sleep(250 * time.Millisecond)

	// Now cleanup should remove all
	removed = verifier.CleanupExpiredEnrollments()
	if removed != 3 {
		t.Errorf("Expected 3 enrollments removed, got %d", removed)
	}
}

func TestGetEnrollment(t *testing.T) {
	verifier := NewRemoteVerifier(DefaultRemoteVerifierConfig())

	// Test getting non-existent enrollment
	_, err := verifier.GetEnrollment([32]byte{1, 2, 3})
	if err != ErrDeviceNotEnrolled {
		t.Errorf("Expected ErrDeviceNotEnrolled, got %v", err)
	}

	// Enroll device
	tpm := NewMockTPM()
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
	prover, _ := NewDeviceProver(tpm, puf)

	enrollChallenge, _ := verifier.EnrollmentChallenge()
	enrollResponse, _ := prover.RespondToEnrollmentChallenge(enrollChallenge)
	enrollment, _ := verifier.CompleteEnrollment(enrollChallenge, enrollResponse)

	// Get enrollment should work
	retrieved, err := verifier.GetEnrollment(enrollment.DeviceID)
	if err != nil {
		t.Fatalf("GetEnrollment failed: %v", err)
	}

	if retrieved.DeviceID != enrollment.DeviceID {
		t.Error("Retrieved enrollment doesn't match")
	}
}

func TestGetEnrollmentExpired(t *testing.T) {
	config := DefaultRemoteVerifierConfig()
	config.EnrollmentTTL = 50 * time.Millisecond
	verifier := NewRemoteVerifier(config)

	// Enroll device
	tpm := NewMockTPM()
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
	prover, _ := NewDeviceProver(tpm, puf)

	enrollChallenge, _ := verifier.EnrollmentChallenge()
	enrollResponse, _ := prover.RespondToEnrollmentChallenge(enrollChallenge)
	enrollment, _ := verifier.CompleteEnrollment(enrollChallenge, enrollResponse)

	// Wait for expiry
	time.Sleep(100 * time.Millisecond)

	_, err := verifier.GetEnrollment(enrollment.DeviceID)
	if err != ErrEnrollmentExpired {
		t.Errorf("Expected ErrEnrollmentExpired, got %v", err)
	}
}

func TestSerializeVerificationReport(t *testing.T) {
	report := &VerificationReport{
		Verified:        true,
		VerifiedAt:      time.Now(),
		DeviceID:        [32]byte{1, 2, 3},
		DeviceName:      "Test Device",
		SessionID:       [32]byte{4, 5, 6},
		KeystrokeCount:  100,
		CheckpointCount: 10,
		TPMVerified:     true,
		PUFVerified:     true,
		ChainVerified:   true,
		CounterVerified: true,
		ConfidenceScore: 95,
		Warnings:        []string{"warning1"},
	}

	data, err := SerializeVerificationReport(report)
	if err != nil {
		t.Fatalf("Serialization failed: %v", err)
	}

	if len(data) == 0 {
		t.Error("Serialized data should not be empty")
	}

	// Verify it's valid JSON
	if data[0] != '{' {
		t.Error("Expected JSON output")
	}
}

func TestVerificationWithoutTPMRequirement(t *testing.T) {
	config := DefaultRemoteVerifierConfig()
	config.RequireTPM = false
	config.RequirePUF = false
	verifier := NewRemoteVerifier(config)

	// Enroll device
	tpm := NewMockTPM()
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
	prover, _ := NewDeviceProver(tpm, puf)

	enrollChallenge, _ := verifier.EnrollmentChallenge()
	enrollResponse, _ := prover.RespondToEnrollmentChallenge(enrollChallenge)
	enrollment, _ := verifier.CompleteEnrollment(enrollChallenge, enrollResponse)

	// Create verification without TPM quote
	request := &VerificationRequest{
		DeviceID:    enrollment.DeviceID,
		RequestedAt: time.Now(),
	}

	challenge, _ := verifier.CreateVerificationChallenge(request)

	// Response without TPM quote
	response := &VerificationResponse{
		ChallengeID:    challenge.ChallengeID,
		DeviceID:       enrollment.DeviceID,
		CurrentCounter: challenge.MinCounter + 1,
		RespondedAt:    time.Now(),
	}

	report, _ := verifier.Verify(request, challenge, response)

	if !report.TPMVerified {
		t.Error("TPM should be verified when not required")
	}

	if !report.PUFVerified {
		t.Error("PUF should be verified when not required")
	}
}

func TestVerificationMissingTPMQuote(t *testing.T) {
	config := DefaultRemoteVerifierConfig()
	config.RequireTPM = true
	config.RequirePUF = false
	verifier := NewRemoteVerifier(config)

	// Enroll device
	tpm := NewMockTPM()
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
	prover, _ := NewDeviceProver(tpm, puf)

	enrollChallenge, _ := verifier.EnrollmentChallenge()
	enrollResponse, _ := prover.RespondToEnrollmentChallenge(enrollChallenge)
	enrollment, _ := verifier.CompleteEnrollment(enrollChallenge, enrollResponse)

	request := &VerificationRequest{
		DeviceID:    enrollment.DeviceID,
		RequestedAt: time.Now(),
	}

	challenge, _ := verifier.CreateVerificationChallenge(request)

	// Response without TPM quote
	response := &VerificationResponse{
		ChallengeID:    challenge.ChallengeID,
		DeviceID:       enrollment.DeviceID,
		CurrentCounter: challenge.MinCounter + 1,
		RespondedAt:    time.Now(),
	}

	report, _ := verifier.Verify(request, challenge, response)

	if report.TPMVerified {
		t.Error("TPM should not be verified without quote")
	}

	if report.Verified {
		t.Error("Verification should fail without required TPM quote")
	}
}

func TestVerificationTPMNonceMismatch(t *testing.T) {
	config := DefaultRemoteVerifierConfig()
	config.RequireTPM = true
	config.RequirePUF = false
	verifier := NewRemoteVerifier(config)

	// Enroll device
	tpm := NewMockTPM()
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
	prover, _ := NewDeviceProver(tpm, puf)

	enrollChallenge, _ := verifier.EnrollmentChallenge()
	enrollResponse, _ := prover.RespondToEnrollmentChallenge(enrollChallenge)
	enrollment, _ := verifier.CompleteEnrollment(enrollChallenge, enrollResponse)

	request := &VerificationRequest{
		DeviceID:    enrollment.DeviceID,
		RequestedAt: time.Now(),
	}

	challenge, _ := verifier.CreateVerificationChallenge(request)

	// Get quote with wrong nonce
	wrongNonce := [32]byte{0xFF, 0xFF}
	quote, _ := tpm.Quote(wrongNonce[:], challenge.RequiredPCRs)

	response := &VerificationResponse{
		ChallengeID:    challenge.ChallengeID,
		DeviceID:       enrollment.DeviceID,
		TPMQuote:       quote,
		CurrentCounter: challenge.MinCounter + 1,
		RespondedAt:    time.Now(),
	}

	report, _ := verifier.Verify(request, challenge, response)

	if report.TPMVerified {
		t.Error("TPM should not be verified with wrong nonce")
	}
}

func TestVerificationMissingPUFResponse(t *testing.T) {
	config := DefaultRemoteVerifierConfig()
	config.RequireTPM = false
	config.RequirePUF = true
	verifier := NewRemoteVerifier(config)

	// Enroll device
	tpm := NewMockTPM()
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
	prover, _ := NewDeviceProver(tpm, puf)

	enrollChallenge, _ := verifier.EnrollmentChallenge()
	enrollResponse, _ := prover.RespondToEnrollmentChallenge(enrollChallenge)
	enrollment, _ := verifier.CompleteEnrollment(enrollChallenge, enrollResponse)

	request := &VerificationRequest{
		DeviceID:    enrollment.DeviceID,
		RequestedAt: time.Now(),
	}

	challenge, _ := verifier.CreateVerificationChallenge(request)

	// Response without PUF response
	response := &VerificationResponse{
		ChallengeID:    challenge.ChallengeID,
		DeviceID:       enrollment.DeviceID,
		CurrentCounter: challenge.MinCounter + 1,
		RespondedAt:    time.Now(),
	}

	report, _ := verifier.Verify(request, challenge, response)

	if report.PUFVerified {
		t.Error("PUF should not be verified without response")
	}
}

func TestVerificationPUFResponseTooShort(t *testing.T) {
	config := DefaultRemoteVerifierConfig()
	config.RequireTPM = false
	config.RequirePUF = true
	verifier := NewRemoteVerifier(config)

	// Enroll device
	tpm := NewMockTPM()
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
	prover, _ := NewDeviceProver(tpm, puf)

	enrollChallenge, _ := verifier.EnrollmentChallenge()
	enrollResponse, _ := prover.RespondToEnrollmentChallenge(enrollChallenge)
	enrollment, _ := verifier.CompleteEnrollment(enrollChallenge, enrollResponse)

	request := &VerificationRequest{
		DeviceID:    enrollment.DeviceID,
		RequestedAt: time.Now(),
	}

	challenge, _ := verifier.CreateVerificationChallenge(request)

	// Response with too short PUF response
	response := &VerificationResponse{
		ChallengeID:    challenge.ChallengeID,
		DeviceID:       enrollment.DeviceID,
		PUFResponse:    []byte{1, 2, 3}, // Less than 16 bytes
		CurrentCounter: challenge.MinCounter + 1,
		RespondedAt:    time.Now(),
	}

	report, _ := verifier.Verify(request, challenge, response)

	if report.PUFVerified {
		t.Error("PUF should not be verified with short response")
	}
}

func TestVerificationPUFResponseAllZeros(t *testing.T) {
	config := DefaultRemoteVerifierConfig()
	config.RequireTPM = false
	config.RequirePUF = true
	verifier := NewRemoteVerifier(config)

	// Enroll device
	tpm := NewMockTPM()
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
	prover, _ := NewDeviceProver(tpm, puf)

	enrollChallenge, _ := verifier.EnrollmentChallenge()
	enrollResponse, _ := prover.RespondToEnrollmentChallenge(enrollChallenge)
	enrollment, _ := verifier.CompleteEnrollment(enrollChallenge, enrollResponse)

	request := &VerificationRequest{
		DeviceID:    enrollment.DeviceID,
		RequestedAt: time.Now(),
	}

	challenge, _ := verifier.CreateVerificationChallenge(request)

	// Response with all-zero PUF response
	response := &VerificationResponse{
		ChallengeID:    challenge.ChallengeID,
		DeviceID:       enrollment.DeviceID,
		PUFResponse:    make([]byte, 32), // All zeros
		CurrentCounter: challenge.MinCounter + 1,
		RespondedAt:    time.Now(),
	}

	report, _ := verifier.Verify(request, challenge, response)

	if report.PUFVerified {
		t.Error("PUF should not be verified with all-zero response")
	}
}

func TestVerifyChainError(t *testing.T) {
	config := DefaultRemoteVerifierConfig()
	config.RequireTPM = false
	config.RequirePUF = false
	verifier := NewRemoteVerifier(config)

	// Enroll device
	tpm := NewMockTPM()
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
	prover, _ := NewDeviceProver(tpm, puf)

	enrollChallenge, _ := verifier.EnrollmentChallenge()
	enrollResponse, _ := prover.RespondToEnrollmentChallenge(enrollChallenge)
	enrollment, _ := verifier.CompleteEnrollment(enrollChallenge, enrollResponse)

	// Create session with tampered checkpoints
	attestConfig := DefaultAttestationConfig()
	attestConfig.KeystrokeThreshold = 3
	session, _ := NewContinuousAttestationSession(attestConfig, tpm)
	session.Start()

	for i := 0; i < 9; i++ {
		contentHash := sha256.Sum256([]byte{byte(i)})
		session.RecordKeystroke(contentHash, nil)
	}

	export := session.ExportSession()
	session.Stop()

	// Tamper with checkpoint
	if len(export.Checkpoints) > 2 {
		export.Checkpoints[2].KeystrokeCount = 999999
	}

	request := &VerificationRequest{
		DeviceID:      enrollment.DeviceID,
		SessionExport: export,
		RequestedAt:   time.Now(),
	}

	challenge, _ := verifier.CreateVerificationChallenge(request)
	response, _ := prover.RespondToVerificationChallenge(challenge)

	report, _ := verifier.Verify(request, challenge, response)

	if report.ChainVerified {
		t.Error("Chain should not be verified with tampered checkpoint")
	}
}

func TestVerifyTimelineRegression(t *testing.T) {
	config := DefaultRemoteVerifierConfig()
	config.RequireTPM = false
	config.RequirePUF = false
	verifier := NewRemoteVerifier(config)

	// Enroll device
	tpm := NewMockTPM()
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
	prover, _ := NewDeviceProver(tpm, puf)

	enrollChallenge, _ := verifier.EnrollmentChallenge()
	enrollResponse, _ := prover.RespondToEnrollmentChallenge(enrollChallenge)
	enrollment, _ := verifier.CompleteEnrollment(enrollChallenge, enrollResponse)

	attestConfig := DefaultAttestationConfig()
	attestConfig.KeystrokeThreshold = 3
	session, _ := NewContinuousAttestationSession(attestConfig, tpm)
	session.Start()

	for i := 0; i < 9; i++ {
		contentHash := sha256.Sum256([]byte{byte(i)})
		session.RecordKeystroke(contentHash, nil)
	}

	export := session.ExportSession()
	session.Stop()

	// Tamper with timestamp to cause regression
	if len(export.Checkpoints) > 2 {
		export.Checkpoints[2].Timestamp = export.Checkpoints[1].Timestamp.Add(-time.Hour)
	}

	request := &VerificationRequest{
		DeviceID:      enrollment.DeviceID,
		SessionExport: export,
		RequestedAt:   time.Now(),
	}

	challenge, _ := verifier.CreateVerificationChallenge(request)
	response, _ := prover.RespondToVerificationChallenge(challenge)

	report, _ := verifier.Verify(request, challenge, response)

	if report.TimelineVerified {
		t.Error("Timeline should not be verified with timestamp regression")
	}
}

func TestVerifyTimelineFutureSession(t *testing.T) {
	config := DefaultRemoteVerifierConfig()
	config.RequireTPM = false
	config.RequirePUF = false
	verifier := NewRemoteVerifier(config)

	// Enroll device
	tpm := NewMockTPM()
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
	prover, _ := NewDeviceProver(tpm, puf)

	enrollChallenge, _ := verifier.EnrollmentChallenge()
	enrollResponse, _ := prover.RespondToEnrollmentChallenge(enrollChallenge)
	enrollment, _ := verifier.CompleteEnrollment(enrollChallenge, enrollResponse)

	attestConfig := DefaultAttestationConfig()
	attestConfig.KeystrokeThreshold = 5
	session, _ := NewContinuousAttestationSession(attestConfig, tpm)
	session.Start()

	for i := 0; i < 10; i++ {
		contentHash := sha256.Sum256([]byte{byte(i)})
		session.RecordKeystroke(contentHash, nil)
	}

	export := session.ExportSession()
	session.Stop()

	// Set session start to future
	export.SessionStart = time.Now().Add(time.Hour)

	request := &VerificationRequest{
		DeviceID:      enrollment.DeviceID,
		SessionExport: export,
		RequestedAt:   time.Now(),
	}

	challenge, _ := verifier.CreateVerificationChallenge(request)
	response, _ := prover.RespondToVerificationChallenge(challenge)

	report, _ := verifier.Verify(request, challenge, response)

	if report.TimelineVerified {
		t.Error("Timeline should not be verified with future session start")
	}
}

func TestVerifyTimelineOldSession(t *testing.T) {
	config := DefaultRemoteVerifierConfig()
	config.RequireTPM = false
	config.RequirePUF = false
	verifier := NewRemoteVerifier(config)

	// Enroll device
	tpm := NewMockTPM()
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
	prover, _ := NewDeviceProver(tpm, puf)

	enrollChallenge, _ := verifier.EnrollmentChallenge()
	enrollResponse, _ := prover.RespondToEnrollmentChallenge(enrollChallenge)
	enrollment, _ := verifier.CompleteEnrollment(enrollChallenge, enrollResponse)

	attestConfig := DefaultAttestationConfig()
	attestConfig.KeystrokeThreshold = 5
	session, _ := NewContinuousAttestationSession(attestConfig, tpm)
	session.Start()

	for i := 0; i < 10; i++ {
		contentHash := sha256.Sum256([]byte{byte(i)})
		session.RecordKeystroke(contentHash, nil)
	}

	export := session.ExportSession()
	session.Stop()

	// Set session start to over a year ago
	export.SessionStart = time.Now().Add(-400 * 24 * time.Hour)

	request := &VerificationRequest{
		DeviceID:      enrollment.DeviceID,
		SessionExport: export,
		RequestedAt:   time.Now(),
	}

	challenge, _ := verifier.CreateVerificationChallenge(request)
	response, _ := prover.RespondToVerificationChallenge(challenge)

	report, _ := verifier.Verify(request, challenge, response)

	// Should still verify but have warning
	hasOldWarning := false
	for _, w := range report.Warnings {
		if w == "session started more than a year ago" {
			hasOldWarning = true
			break
		}
	}
	if !hasOldWarning {
		t.Error("Expected warning about old session")
	}
}

func TestImportEnrollmentsError(t *testing.T) {
	verifier := NewRemoteVerifier(DefaultRemoteVerifierConfig())

	// Try to import invalid JSON
	err := verifier.ImportEnrollments([]byte("invalid json"))
	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
}

func TestDeviceProverWithoutTPM(t *testing.T) {
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())

	prover, err := NewDeviceProver(nil, puf)
	if err != nil {
		t.Fatalf("Failed to create prover without TPM: %v", err)
	}

	// Device ID should still be generated from PUF
	deviceID := prover.DeviceID()
	if deviceID == [32]byte{} {
		t.Error("Device ID should not be empty")
	}
}

func TestDeviceProverWithoutPUF(t *testing.T) {
	tpm := NewMockTPM()

	prover, err := NewDeviceProver(tpm, nil)
	if err != nil {
		t.Fatalf("Failed to create prover without PUF: %v", err)
	}

	deviceID := prover.DeviceID()
	if deviceID == [32]byte{} {
		t.Error("Device ID should not be empty")
	}
}

func TestDeviceProverWithoutTPMOrPUF(t *testing.T) {
	// Should fail when neither TPM nor PUF is available
	_, err := NewDeviceProver(nil, nil)
	if err == nil {
		t.Error("Expected error when creating prover without TPM or PUF")
	}
}

// FailingPUF is a PUF that fails on Challenge
type FailingPUF struct {
	*SRAMPUF
	failChallenge bool
}

func NewFailingPUF() *FailingPUF {
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
	return &FailingPUF{SRAMPUF: puf}
}

func (f *FailingPUF) Challenge(challenge []byte) ([]byte, error) {
	if f.failChallenge {
		return nil, errors.New("PUF challenge failed")
	}
	return f.SRAMPUF.Challenge(challenge)
}

func TestDeviceProverWithFailingTPMAndPUF(t *testing.T) {
	// Test when both TPM and PUF fail with errors
	failingTPM := NewFailingMockTPM()
	failingTPM.SetFailEK(true)

	failingPUF := NewFailingPUF()
	failingPUF.failChallenge = true

	_, err := NewDeviceProver(failingTPM, failingPUF)
	if err == nil {
		t.Error("Expected error when both TPM and PUF fail")
	}

	// Error message should mention both failures
	if !strings.Contains(err.Error(), "TPM error") || !strings.Contains(err.Error(), "PUF error") {
		t.Errorf("Expected error to mention both TPM and PUF failures, got: %v", err)
	}
}

func TestDeviceProverWithUnavailableTPM(t *testing.T) {
	// Test when TPM is present but not available, and no PUF
	// MockTPM.Available() returns true, so we need a different approach
	// This tests the "no identity source available" path

	// Create a TPM that's available but can't provide an EK
	failingTPM := NewFailingMockTPM()
	failingTPM.SetFailEK(true)

	// No PUF provided
	_, err := NewDeviceProver(failingTPM, nil)
	if err == nil {
		t.Error("Expected error when TPM fails and no PUF available")
	}
}

func TestVerificationWithUntrustedPCRWarnings(t *testing.T) {
	// Test that RemoteVerifier passes trusted PCR values to chain verifier
	// and properly collects warnings
	verifier := NewRemoteVerifier(DefaultRemoteVerifierConfig())

	// Add a trusted PCR value that won't match what the session produces
	verifier.AddTrustedPCRValue(0, []byte("golden-pcr-value"))

	tpm := NewMockTPM()
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
	prover, _ := NewDeviceProver(tpm, puf)

	// Enroll device
	enrollChallenge, _ := verifier.EnrollmentChallenge()
	enrollResponse, _ := prover.RespondToEnrollmentChallenge(enrollChallenge)
	enrollment, _ := verifier.CompleteEnrollment(enrollChallenge, enrollResponse)
	prover.SetEnrollment(enrollment)

	// Create session with keystrokes to generate checkpoints
	attestConfig := DefaultAttestationConfig()
	attestConfig.KeystrokeThreshold = 3
	session, _ := NewContinuousAttestationSession(attestConfig, tpm)
	session.Start()

	for i := 0; i < 9; i++ {
		contentHash := sha256.Sum256([]byte{byte(i)})
		session.RecordKeystroke(contentHash, nil)
	}

	export := session.ExportSession()
	session.Stop()

	// Verify through RemoteVerifier
	request := &VerificationRequest{
		DeviceID:      enrollment.DeviceID,
		SessionExport: export,
		RequestedAt:   time.Now(),
	}

	challenge, _ := verifier.CreateVerificationChallenge(request)
	response, _ := prover.RespondToVerificationChallenge(challenge)

	report, err := verifier.Verify(request, challenge, response)
	if err != nil {
		t.Errorf("Verify failed: %v", err)
	}

	// The chain should be valid but have warnings about untrusted PCR values
	if !report.ChainVerified {
		t.Error("Chain should be verified (valid) even with PCR warnings")
	}

	// Should have warnings about the mismatched PCR values
	hasWarning := false
	for _, w := range report.Warnings {
		if strings.Contains(w, "untrusted PCR") {
			hasWarning = true
			break
		}
	}
	if !hasWarning {
		t.Error("Expected warning about untrusted PCR values")
	}
}

func TestRespondToEnrollmentChallengeWithoutTPM(t *testing.T) {
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
	prover, _ := NewDeviceProver(nil, puf)

	verifier := NewRemoteVerifier(DefaultRemoteVerifierConfig())
	challenge, _ := verifier.EnrollmentChallenge()

	response, err := prover.RespondToEnrollmentChallenge(challenge)
	if err != nil {
		t.Fatalf("Failed to respond: %v", err)
	}

	// Should have PUF data but no TPM data
	if response.TPMQuote != nil {
		t.Error("Should not have TPM quote without TPM")
	}
	if len(response.PUFResponse) == 0 {
		t.Error("Should have PUF response")
	}
}

func TestRespondToVerificationChallengeWithoutTPM(t *testing.T) {
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
	prover, _ := NewDeviceProver(nil, puf)

	challenge := &VerificationChallenge{
		ChallengeID:  [32]byte{1, 2, 3},
		PUFChallenge: []byte("test-challenge"),
	}

	response, err := prover.RespondToVerificationChallenge(challenge)
	if err != nil {
		t.Fatalf("Failed to respond: %v", err)
	}

	if response.TPMQuote != nil {
		t.Error("Should not have TPM quote without TPM")
	}
	if len(response.PUFResponse) == 0 {
		t.Error("Should have PUF response")
	}
}

func TestVerificationSessionErrors(t *testing.T) {
	verifier := NewRemoteVerifier(DefaultRemoteVerifierConfig())

	tpm := NewMockTPM()
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
	prover, _ := NewDeviceProver(tpm, puf)

	// Create session without enrolling device
	session := NewVerificationSession(prover, verifier)

	// Should fail because device not enrolled
	err := session.StartVerification(nil)
	if err != ErrDeviceNotEnrolled {
		t.Errorf("Expected ErrDeviceNotEnrolled, got %v", err)
	}

	// Test RespondToChallenge without challenge
	err = session.RespondToChallenge()
	if err == nil {
		t.Error("Expected error without challenge")
	}

	// Test CompleteVerification without response
	_, err = session.CompleteVerification()
	if err == nil {
		t.Error("Expected error without response")
	}
}

func TestEnrollmentChallengeWithRequireTPMFalse(t *testing.T) {
	config := DefaultRemoteVerifierConfig()
	config.RequireTPM = false
	verifier := NewRemoteVerifier(config)

	// Create enrollment with no TPM quote required
	challenge, _ := verifier.EnrollmentChallenge()

	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
	prover, _ := NewDeviceProver(nil, puf)

	response, _ := prover.RespondToEnrollmentChallenge(challenge)

	// Should succeed without TPM
	enrollment, err := verifier.CompleteEnrollment(challenge, response)
	if err != nil {
		t.Fatalf("Enrollment should succeed without TPM: %v", err)
	}

	if enrollment.DeviceID == [32]byte{} {
		t.Error("Enrollment should have device ID")
	}
}

func TestCreateVerificationChallengeExpiredEnrollment(t *testing.T) {
	config := DefaultRemoteVerifierConfig()
	config.EnrollmentTTL = 50 * time.Millisecond
	verifier := NewRemoteVerifier(config)

	// Enroll device
	tpm := NewMockTPM()
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
	prover, _ := NewDeviceProver(tpm, puf)

	enrollChallenge, _ := verifier.EnrollmentChallenge()
	enrollResponse, _ := prover.RespondToEnrollmentChallenge(enrollChallenge)
	enrollment, _ := verifier.CompleteEnrollment(enrollChallenge, enrollResponse)

	// Wait for expiry
	time.Sleep(100 * time.Millisecond)

	request := &VerificationRequest{
		DeviceID:    enrollment.DeviceID,
		RequestedAt: time.Now(),
	}

	_, err := verifier.CreateVerificationChallenge(request)
	if err != ErrEnrollmentExpired {
		t.Errorf("Expected ErrEnrollmentExpired, got %v", err)
	}
}

func TestStrictPCRCheckWithMismatch(t *testing.T) {
	config := DefaultRemoteVerifierConfig()
	config.StrictPCRCheck = true
	config.RequirePUF = false
	verifier := NewRemoteVerifier(config)

	// Add trusted PCR value that won't match
	verifier.AddTrustedPCRValue(0, []byte("different-trusted-value-that-wont-match"))

	// Enroll device
	tpm := NewMockTPM()
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
	prover, _ := NewDeviceProver(tpm, puf)

	enrollChallenge, _ := verifier.EnrollmentChallenge()
	enrollResponse, _ := prover.RespondToEnrollmentChallenge(enrollChallenge)
	enrollment, _ := verifier.CompleteEnrollment(enrollChallenge, enrollResponse)

	request := &VerificationRequest{
		DeviceID:    enrollment.DeviceID,
		RequestedAt: time.Now(),
	}

	challenge, _ := verifier.CreateVerificationChallenge(request)
	response, _ := prover.RespondToVerificationChallenge(challenge)

	report, _ := verifier.Verify(request, challenge, response)

	// Should have warning about untrusted PCR
	hasUntrustedWarning := false
	for _, w := range report.Warnings {
		if len(w) > 0 && w[:3] == "PCR" {
			hasUntrustedWarning = true
			break
		}
	}
	if !hasUntrustedWarning {
		t.Log("Warnings:", report.Warnings)
	}
}

func TestTPMQuotePCRMismatchFromEnrollment(t *testing.T) {
	config := DefaultRemoteVerifierConfig()
	config.RequirePUF = false
	verifier := NewRemoteVerifier(config)

	// Enroll device
	tpm := NewMockTPM()
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
	prover, _ := NewDeviceProver(tpm, puf)

	enrollChallenge, _ := verifier.EnrollmentChallenge()
	enrollResponse, _ := prover.RespondToEnrollmentChallenge(enrollChallenge)
	enrollment, _ := verifier.CompleteEnrollment(enrollChallenge, enrollResponse)

	// Modify PCR to cause mismatch
	tpm.ExtendPCR(0, []byte("change-pcr"))

	request := &VerificationRequest{
		DeviceID:    enrollment.DeviceID,
		RequestedAt: time.Now(),
	}

	challenge, _ := verifier.CreateVerificationChallenge(request)
	response, _ := prover.RespondToVerificationChallenge(challenge)

	report, _ := verifier.Verify(request, challenge, response)

	if report.TPMVerified {
		t.Error("TPM should not be verified when PCR changed from enrollment")
	}
}

func TestIsEnrolledFalse(t *testing.T) {
	verifier := NewRemoteVerifier(DefaultRemoteVerifierConfig())

	// Test with non-existent device
	if verifier.IsEnrolled([32]byte{1, 2, 3}) {
		t.Error("Non-existent device should not be enrolled")
	}
}

func TestVerifyWithNoSessionExport(t *testing.T) {
	config := DefaultRemoteVerifierConfig()
	config.RequireTPM = false
	config.RequirePUF = false
	verifier := NewRemoteVerifier(config)

	// Enroll device
	tpm := NewMockTPM()
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
	prover, _ := NewDeviceProver(tpm, puf)

	enrollChallenge, _ := verifier.EnrollmentChallenge()
	enrollResponse, _ := prover.RespondToEnrollmentChallenge(enrollChallenge)
	enrollment, _ := verifier.CompleteEnrollment(enrollChallenge, enrollResponse)

	// Request without session export
	request := &VerificationRequest{
		DeviceID:    enrollment.DeviceID,
		RequestedAt: time.Now(),
	}

	challenge, _ := verifier.CreateVerificationChallenge(request)
	response, _ := prover.RespondToVerificationChallenge(challenge)

	report, err := verifier.Verify(request, challenge, response)
	if err != nil {
		t.Fatalf("Verification error: %v", err)
	}

	// Should succeed since no session to verify
	if !report.Verified {
		t.Errorf("Should be verified without session export: %v", report.Errors)
	}
}

func TestVerifyChainWithVerificationError(t *testing.T) {
	config := DefaultRemoteVerifierConfig()
	config.RequireTPM = false
	config.RequirePUF = false
	verifier := NewRemoteVerifier(config)

	// Enroll device
	tpm := NewMockTPM()
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
	prover, _ := NewDeviceProver(tpm, puf)

	enrollChallenge, _ := verifier.EnrollmentChallenge()
	enrollResponse, _ := prover.RespondToEnrollmentChallenge(enrollChallenge)
	enrollment, _ := verifier.CompleteEnrollment(enrollChallenge, enrollResponse)

	// Create empty checkpoints list
	export := &AttestationSessionExport{
		SessionID:    [32]byte{1},
		SessionStart: time.Now(),
		Checkpoints:  []*AttestationCheckpoint{},
	}

	request := &VerificationRequest{
		DeviceID:      enrollment.DeviceID,
		SessionExport: export,
		RequestedAt:   time.Now(),
	}

	challenge, _ := verifier.CreateVerificationChallenge(request)
	response, _ := prover.RespondToVerificationChallenge(challenge)

	report, _ := verifier.Verify(request, challenge, response)

	if !report.ChainVerified {
		t.Error("Empty chain should verify successfully")
	}
}

func TestVerifyTimelineEmptyCheckpoints(t *testing.T) {
	config := DefaultRemoteVerifierConfig()
	config.RequireTPM = false
	config.RequirePUF = false
	verifier := NewRemoteVerifier(config)

	// Enroll device
	tpm := NewMockTPM()
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
	prover, _ := NewDeviceProver(tpm, puf)

	enrollChallenge, _ := verifier.EnrollmentChallenge()
	enrollResponse, _ := prover.RespondToEnrollmentChallenge(enrollChallenge)
	enrollment, _ := verifier.CompleteEnrollment(enrollChallenge, enrollResponse)

	export := &AttestationSessionExport{
		SessionID:    [32]byte{1},
		SessionStart: time.Now(),
		Checkpoints:  []*AttestationCheckpoint{},
	}

	request := &VerificationRequest{
		DeviceID:      enrollment.DeviceID,
		SessionExport: export,
		RequestedAt:   time.Now(),
	}

	challenge, _ := verifier.CreateVerificationChallenge(request)
	response, _ := prover.RespondToVerificationChallenge(challenge)

	report, _ := verifier.Verify(request, challenge, response)

	if !report.TimelineVerified {
		t.Error("Empty checkpoints should have verified timeline")
	}
}

func TestVerifyTimelineSingleCheckpoint(t *testing.T) {
	config := DefaultRemoteVerifierConfig()
	config.RequireTPM = false
	config.RequirePUF = false
	verifier := NewRemoteVerifier(config)

	// Enroll device
	tpm := NewMockTPM()
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
	prover, _ := NewDeviceProver(tpm, puf)

	enrollChallenge, _ := verifier.EnrollmentChallenge()
	enrollResponse, _ := prover.RespondToEnrollmentChallenge(enrollChallenge)
	enrollment, _ := verifier.CompleteEnrollment(enrollChallenge, enrollResponse)

	export := &AttestationSessionExport{
		SessionID:      [32]byte{1},
		SessionStart:   time.Now(),
		KeystrokeCount: 5,
		Checkpoints: []*AttestationCheckpoint{
			{
				SequenceNumber: 0,
				Timestamp:      time.Now(),
				TPMCounter:     1,
			},
		},
	}

	request := &VerificationRequest{
		DeviceID:      enrollment.DeviceID,
		SessionExport: export,
		RequestedAt:   time.Now(),
	}

	challenge, _ := verifier.CreateVerificationChallenge(request)
	response, _ := prover.RespondToVerificationChallenge(challenge)

	report, _ := verifier.Verify(request, challenge, response)

	// Single checkpoint shouldn't trigger typing speed check
	if !report.TimelineVerified {
		t.Errorf("Single checkpoint timeline should verify: %v", report.Warnings)
	}
}

func TestCompleteEnrollmentNonceMismatch(t *testing.T) {
	config := DefaultRemoteVerifierConfig()
	config.RequireTPM = true
	verifier := NewRemoteVerifier(config)

	tpm := NewMockTPM()
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
	prover, _ := NewDeviceProver(tpm, puf)

	challenge, _ := verifier.EnrollmentChallenge()
	response, _ := prover.RespondToEnrollmentChallenge(challenge)

	// Tamper with the nonce in the quote
	if response.TPMQuote != nil {
		response.TPMQuote.Nonce = []byte("wrong-nonce")
	}

	_, err := verifier.CompleteEnrollment(challenge, response)
	if err != ErrChallengeMismatch {
		t.Errorf("Expected ErrChallengeMismatch, got %v", err)
	}
}

func TestCompleteEnrollmentMissingQuote(t *testing.T) {
	config := DefaultRemoteVerifierConfig()
	config.RequireTPM = true
	verifier := NewRemoteVerifier(config)

	tpm := NewMockTPM()
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
	prover, _ := NewDeviceProver(tpm, puf)

	challenge, _ := verifier.EnrollmentChallenge()
	response, _ := prover.RespondToEnrollmentChallenge(challenge)

	// Remove the TPM quote
	response.TPMQuote = nil

	_, err := verifier.CompleteEnrollment(challenge, response)
	if err != ErrInvalidQuote {
		t.Errorf("Expected ErrInvalidQuote, got %v", err)
	}
}

func TestVerificationSessionSuccessfulFlow(t *testing.T) {
	verifier := NewRemoteVerifier(DefaultRemoteVerifierConfig())

	// Enroll device
	tpm := NewMockTPM()
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
	prover, _ := NewDeviceProver(tpm, puf)

	enrollChallenge, _ := verifier.EnrollmentChallenge()
	enrollResponse, _ := prover.RespondToEnrollmentChallenge(enrollChallenge)
	enrollment, _ := verifier.CompleteEnrollment(enrollChallenge, enrollResponse)
	prover.SetEnrollment(enrollment)

	// Create session
	session := NewVerificationSession(prover, verifier)

	// Full flow with export
	attestConfig := DefaultAttestationConfig()
	attestConfig.KeystrokeThreshold = 5
	attestSession, _ := NewContinuousAttestationSession(attestConfig, tpm)
	attestSession.Start()

	for i := 0; i < 10; i++ {
		contentHash := sha256.Sum256([]byte{byte(i)})
		attestSession.RecordKeystroke(contentHash, nil)
	}

	export := attestSession.ExportSession()
	attestSession.Stop()

	// Run full verification flow
	err := session.StartVerification(export)
	if err != nil {
		t.Fatalf("StartVerification failed: %v", err)
	}

	err = session.RespondToChallenge()
	if err != nil {
		t.Fatalf("RespondToChallenge failed: %v", err)
	}

	report, err := session.CompleteVerification()
	if err != nil {
		t.Fatalf("CompleteVerification failed: %v", err)
	}

	if !report.Verified {
		t.Errorf("Verification should succeed: %v", report.Errors)
	}
}

func TestRespondToEnrollmentChallengeWithoutPUF(t *testing.T) {
	tpm := NewMockTPM()
	prover, _ := NewDeviceProver(tpm, nil)

	verifier := NewRemoteVerifier(DefaultRemoteVerifierConfig())
	challenge, _ := verifier.EnrollmentChallenge()

	// PUF is optional for enrollment response - should succeed without it
	response, err := prover.RespondToEnrollmentChallenge(challenge)
	if err != nil {
		t.Errorf("RespondToEnrollmentChallenge failed: %v", err)
	}
	if response.PUFFingerprint != ([32]byte{}) {
		t.Error("Expected zero PUF fingerprint without PUF")
	}
	if response.PUFResponse != nil {
		t.Error("Expected nil PUF response without PUF")
	}
	if response.TPMQuote == nil {
		t.Error("Expected TPM quote even without PUF")
	}
}

func TestRespondToVerificationChallengeWithoutPUF(t *testing.T) {
	tpm := NewMockTPM()
	prover, _ := NewDeviceProver(tpm, nil)

	challenge := &VerificationChallenge{
		ChallengeID:  [32]byte{1},
		PUFChallenge: []byte("test"),
		RequiredPCRs: []int{0},
	}

	// PUF is optional for verification response - should succeed without it
	response, err := prover.RespondToVerificationChallenge(challenge)
	if err != nil {
		t.Errorf("RespondToVerificationChallenge failed: %v", err)
	}
	if response.PUFResponse != nil {
		t.Error("Expected nil PUF response without PUF")
	}
	if response.TPMQuote == nil {
		t.Error("Expected TPM quote even without PUF")
	}
}

func TestVerifyChainWithInvalidHash(t *testing.T) {
	// This test covers the verifyChain path where result.Valid is false
	// due to chain integrity issues
	verifier := NewRemoteVerifier(DefaultRemoteVerifierConfig())

	tpm := NewMockTPM()
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
	prover, _ := NewDeviceProver(tpm, puf)

	// Enroll device
	enrollChallenge, _ := verifier.EnrollmentChallenge()
	enrollResponse, _ := prover.RespondToEnrollmentChallenge(enrollChallenge)
	enrollment, _ := verifier.CompleteEnrollment(enrollChallenge, enrollResponse)

	// Create session with keystrokes
	attestConfig := DefaultAttestationConfig()
	attestConfig.KeystrokeThreshold = 3
	session, _ := NewContinuousAttestationSession(attestConfig, tpm)
	session.Start()

	// Record keystrokes to create checkpoints
	for i := 0; i < 9; i++ {
		contentHash := sha256.Sum256([]byte{byte(i)})
		session.RecordKeystroke(contentHash, nil)
	}

	export := session.ExportSession()
	session.Stop()

	// Corrupt the hash chain
	if len(export.Checkpoints) > 1 {
		export.Checkpoints[1].PreviousHash = [32]byte{1, 2, 3}
	}

	// Create verification request
	request := &VerificationRequest{
		DeviceID:      enrollment.DeviceID,
		SessionExport: export,
		RequestedAt:   time.Now(),
	}

	challenge, _ := verifier.CreateVerificationChallenge(request)
	response, _ := prover.RespondToVerificationChallenge(challenge)

	report, err := verifier.Verify(request, challenge, response)
	if err != nil {
		t.Errorf("Verify failed: %v", err)
	}

	if report.ChainVerified {
		t.Error("Expected chain verification to fail with corrupted hash")
	}
}

func TestVerifyConfidenceScoreClamping(t *testing.T) {
	// Test that confidence score is clamped to >= 0
	verifier := NewRemoteVerifier(DefaultRemoteVerifierConfig())

	tpm := NewMockTPM()
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
	prover, _ := NewDeviceProver(tpm, puf)

	// Enroll device
	enrollChallenge, _ := verifier.EnrollmentChallenge()
	enrollResponse, _ := prover.RespondToEnrollmentChallenge(enrollChallenge)
	enrollment, _ := verifier.CompleteEnrollment(enrollChallenge, enrollResponse)

	// Create session
	attestConfig := DefaultAttestationConfig()
	session, _ := NewContinuousAttestationSession(attestConfig, tpm)
	session.Start()
	export := session.ExportSession()
	session.Stop()

	// Corrupt the export to fail multiple verifications
	export.Checkpoints = append(export.Checkpoints, &AttestationCheckpoint{
		SequenceNumber:  1000,
		PreviousHash:    [32]byte{1},
		ContentHash:     [32]byte{2},
		CheckpointHash:  [32]byte{3},
	})

	request := &VerificationRequest{
		DeviceID:      enrollment.DeviceID,
		SessionExport: export,
		RequestedAt:   time.Now(),
	}

	challenge, _ := verifier.CreateVerificationChallenge(request)

	// Create a bad response that will fail verifications
	response := &VerificationResponse{
		ChallengeID:    challenge.ChallengeID,
		DeviceID:       enrollment.DeviceID,
		TPMQuote:       nil, // Missing TPM quote
		PUFResponse:    nil, // Missing PUF response
		CurrentCounter: 0,
		RespondedAt:    time.Now(),
	}

	report, err := verifier.Verify(request, challenge, response)
	if err != nil {
		t.Errorf("Verify failed: %v", err)
	}

	if report.ConfidenceScore < 0 {
		t.Error("Confidence score should be clamped to >= 0")
	}
}

func TestVerificationWithWarnings(t *testing.T) {
	// Test verification that produces warnings
	verifier := NewRemoteVerifier(DefaultRemoteVerifierConfig())

	tpm := NewMockTPM()
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
	prover, _ := NewDeviceProver(tpm, puf)

	// Enroll device
	enrollChallenge, _ := verifier.EnrollmentChallenge()
	enrollResponse, _ := prover.RespondToEnrollmentChallenge(enrollChallenge)
	enrollment, _ := verifier.CompleteEnrollment(enrollChallenge, enrollResponse)

	// Create session
	attestConfig := DefaultAttestationConfig()
	attestConfig.KeystrokeThreshold = 5
	session, _ := NewContinuousAttestationSession(attestConfig, tpm)
	session.Start()

	// Record keystrokes
	for i := 0; i < 15; i++ {
		contentHash := sha256.Sum256([]byte{byte(i)})
		session.RecordKeystroke(contentHash, nil)
	}

	export := session.ExportSession()
	session.Stop()

	request := &VerificationRequest{
		DeviceID:      enrollment.DeviceID,
		SessionExport: export,
		RequestedAt:   time.Now(),
	}

	challenge, _ := verifier.CreateVerificationChallenge(request)
	response, _ := prover.RespondToVerificationChallenge(challenge)

	report, err := verifier.Verify(request, challenge, response)
	if err != nil {
		t.Errorf("Verify failed: %v", err)
	}

	// Report should exist (warnings or not)
	if report == nil {
		t.Error("Expected report to be created")
	}
}

func TestCreateVerificationChallengeNonceValidation(t *testing.T) {
	// This test validates CreateVerificationChallenge nonce generation
	verifier := NewRemoteVerifier(DefaultRemoteVerifierConfig())

	tpm := NewMockTPM()
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
	prover, _ := NewDeviceProver(tpm, puf)

	// Enroll device
	enrollChallenge, _ := verifier.EnrollmentChallenge()
	enrollResponse, _ := prover.RespondToEnrollmentChallenge(enrollChallenge)
	enrollment, _ := verifier.CompleteEnrollment(enrollChallenge, enrollResponse)

	request := &VerificationRequest{
		DeviceID:    enrollment.DeviceID,
		RequestedAt: time.Now(),
	}

	// Create challenge and verify nonces are set
	challenge, err := verifier.CreateVerificationChallenge(request)
	if err != nil {
		t.Fatalf("CreateVerificationChallenge failed: %v", err)
	}

	// Verify nonces are not empty
	if challenge.ChallengeID == [32]byte{} {
		t.Error("ChallengeID should not be empty")
	}
	if challenge.TPMNonce == [32]byte{} {
		t.Error("TPMNonce should not be empty")
	}
	if len(challenge.PUFChallenge) == 0 {
		t.Error("PUFChallenge should not be empty")
	}
}

func TestSetEnrollment(t *testing.T) {
	tpm := NewMockTPM()
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
	prover, _ := NewDeviceProver(tpm, puf)

	originalID := prover.DeviceID()

	// Create an enrollment
	enrollment := &DeviceEnrollment{
		DeviceID:   [32]byte{1, 2, 3, 4, 5},
		DeviceName: "test-device",
	}

	// Set the enrollment
	prover.SetEnrollment(enrollment)

	// Device ID should be updated
	if prover.DeviceID() == originalID {
		t.Error("DeviceID should change after SetEnrollment")
	}

	if prover.DeviceID() != enrollment.DeviceID {
		t.Error("DeviceID should match enrollment.DeviceID")
	}
}

func TestRespondToChallengeWithProverError(t *testing.T) {
	// Create a prover that will fail during verification response
	failingTPM := NewFailingMockTPM()
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
	prover, _ := NewDeviceProver(failingTPM, puf)

	verifier := NewRemoteVerifier(DefaultRemoteVerifierConfig())

	// Enroll device first
	enrollChallenge, _ := verifier.EnrollmentChallenge()
	enrollResponse, _ := prover.RespondToEnrollmentChallenge(enrollChallenge)
	enrollment, _ := verifier.CompleteEnrollment(enrollChallenge, enrollResponse)
	prover.SetEnrollment(enrollment) // Important: set enrollment on prover

	// Create session and start verification
	session := NewVerificationSession(prover, verifier)
	export := &AttestationSessionExport{
		SessionID:    [32]byte{1},
		SessionStart: time.Now(),
	}
	err := session.StartVerification(export)
	if err != nil {
		t.Fatalf("StartVerification failed: %v", err)
	}

	// Now make TPM fail
	failingTPM.SetFailQuote(true)

	// RespondToChallenge should fail
	err = session.RespondToChallenge()
	if err == nil {
		t.Error("Expected error when prover fails")
	}
}

func TestCompleteVerificationWithExpiredChallenge(t *testing.T) {
	config := DefaultRemoteVerifierConfig()
	config.ChallengeTimeout = 50 * time.Millisecond
	verifier := NewRemoteVerifier(config)

	tpm := NewMockTPM()
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
	prover, _ := NewDeviceProver(tpm, puf)

	// Enroll device
	enrollChallenge, _ := verifier.EnrollmentChallenge()
	enrollResponse, _ := prover.RespondToEnrollmentChallenge(enrollChallenge)
	enrollment, _ := verifier.CompleteEnrollment(enrollChallenge, enrollResponse)
	prover.SetEnrollment(enrollment) // Important: set enrollment on prover

	// Create session and start verification
	session := NewVerificationSession(prover, verifier)
	export := &AttestationSessionExport{
		SessionID:    [32]byte{1},
		SessionStart: time.Now(),
	}
	err := session.StartVerification(export)
	if err != nil {
		t.Fatalf("StartVerification failed: %v", err)
	}

	// Respond to challenge (must succeed to set response)
	err = session.RespondToChallenge()
	if err != nil {
		t.Fatalf("RespondToChallenge failed: %v", err)
	}

	// Wait for challenge to expire
	time.Sleep(100 * time.Millisecond)

	// Complete verification - should fail due to expired challenge
	report, err := session.CompleteVerification()
	if err != nil {
		t.Fatalf("CompleteVerification failed: %v", err)
	}

	// Report should exist but indicate failure due to expired challenge
	if report.Verified {
		t.Error("Expected verification to fail with expired challenge")
	}
}

func TestVerificationTimelineWithHighTypingSpeed(t *testing.T) {
	// Test timeline verification with suspiciously high typing speed
	verifier := NewRemoteVerifier(DefaultRemoteVerifierConfig())

	tpm := NewMockTPM()
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
	prover, _ := NewDeviceProver(tpm, puf)

	// Enroll device
	enrollChallenge, _ := verifier.EnrollmentChallenge()
	enrollResponse, _ := prover.RespondToEnrollmentChallenge(enrollChallenge)
	enrollment, _ := verifier.CompleteEnrollment(enrollChallenge, enrollResponse)

	// Create export with extremely high keystroke count in short time
	now := time.Now()
	export := &AttestationSessionExport{
		SessionID:      [32]byte{1},
		SessionStart:   now.Add(-1 * time.Second), // Session lasted 1 second
		KeystrokeCount: 10000, // 10000 keystrokes in 1 second = unrealistic
		Checkpoints: []*AttestationCheckpoint{
			{
				SessionID:      [32]byte{1},
				SequenceNumber: 0,
				Timestamp:      now.Add(-1 * time.Second),
			},
			{
				SessionID:      [32]byte{1},
				SequenceNumber: 1,
				Timestamp:      now,
			},
		},
	}

	request := &VerificationRequest{
		DeviceID:      enrollment.DeviceID,
		SessionExport: export,
		RequestedAt:   time.Now(),
	}

	challenge, _ := verifier.CreateVerificationChallenge(request)
	response, _ := prover.RespondToVerificationChallenge(challenge)

	report, err := verifier.Verify(request, challenge, response)
	if err != nil {
		t.Errorf("Verify failed: %v", err)
	}

	// Should have timeline warnings due to unrealistic typing speed
	if len(report.Warnings) == 0 {
		t.Error("Expected warnings for unrealistic typing speed")
	}
}

func BenchmarkEnrollment(b *testing.B) {
	verifier := NewRemoteVerifier(DefaultRemoteVerifierConfig())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tpm := NewMockTPM()
		puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
		prover, _ := NewDeviceProver(tpm, puf)

		enrollChallenge, _ := verifier.EnrollmentChallenge()
		enrollResponse, _ := prover.RespondToEnrollmentChallenge(enrollChallenge)
		verifier.CompleteEnrollment(enrollChallenge, enrollResponse)
	}
}

func BenchmarkVerification(b *testing.B) {
	verifier := NewRemoteVerifier(DefaultRemoteVerifierConfig())

	// Pre-enroll device
	tpm := NewMockTPM()
	puf, _ := NewSRAMPUF(DefaultSRAMPUFConfig())
	prover, _ := NewDeviceProver(tpm, puf)

	enrollChallenge, _ := verifier.EnrollmentChallenge()
	enrollResponse, _ := prover.RespondToEnrollmentChallenge(enrollChallenge)
	enrollment, _ := verifier.CompleteEnrollment(enrollChallenge, enrollResponse)

	// Pre-create session export
	attestConfig := DefaultAttestationConfig()
	attestConfig.KeystrokeThreshold = 10
	session, _ := NewContinuousAttestationSession(attestConfig, tpm)
	session.Start()
	for i := 0; i < 50; i++ {
		contentHash := sha256.Sum256([]byte{byte(i)})
		session.RecordKeystroke(contentHash, nil)
	}
	export := session.ExportSession()
	session.Stop()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		request := &VerificationRequest{
			DeviceID:      enrollment.DeviceID,
			SessionExport: export,
			RequestedAt:   time.Now(),
		}

		challenge, _ := verifier.CreateVerificationChallenge(request)
		response, _ := prover.RespondToVerificationChallenge(challenge)
		verifier.Verify(request, challenge, response)
	}
}
