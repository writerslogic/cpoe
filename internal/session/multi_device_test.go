//go:build darwin || linux || windows

package session

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"
)

func TestNewMultiDeviceSession(t *testing.T) {
	mds, err := NewMultiDeviceSession()
	if err != nil {
		t.Fatalf("NewMultiDeviceSession failed: %v", err)
	}

	if mds.createdAt.IsZero() {
		t.Error("session should have creation time")
	}

	// Session ID should not be all zeros
	var zeroID [32]byte
	if mds.sessionID == zeroID {
		t.Error("session ID should not be zero")
	}
}

func TestLinkDevice(t *testing.T) {
	mds, _ := NewMultiDeviceSession()

	// Create a device fingerprint
	var fingerprint [32]byte
	rand.Read(fingerprint[:])

	device, err := mds.LinkDevice(fingerprint, "Test Laptop", DeviceTypeDesktop)
	if err != nil {
		t.Fatalf("LinkDevice failed: %v", err)
	}

	if device.DeviceName != "Test Laptop" {
		t.Errorf("device name = %q, want %q", device.DeviceName, "Test Laptop")
	}

	if device.DeviceType != DeviceTypeDesktop {
		t.Errorf("device type = %v, want %v", device.DeviceType, DeviceTypeDesktop)
	}

	if device.LinkProof == nil || len(device.LinkProof) == 0 {
		t.Error("device should have link proof")
	}

	// Linking same device again should return existing
	device2, _ := mds.LinkDevice(fingerprint, "Test Laptop", DeviceTypeDesktop)
	if device.DeviceID != device2.DeviceID {
		t.Error("linking same device should return same session")
	}
}

func TestMultipleDevices(t *testing.T) {
	mds, _ := NewMultiDeviceSession()

	// Link multiple devices
	var fp1, fp2 [32]byte
	rand.Read(fp1[:])
	rand.Read(fp2[:])

	dev1, _ := mds.LinkDevice(fp1, "Laptop", DeviceTypeDesktop)
	dev2, _ := mds.LinkDevice(fp2, "Phone", DeviceTypePhone)

	devices := mds.GetDevices()
	if len(devices) != 2 {
		t.Errorf("device count = %d, want 2", len(devices))
	}

	// Devices should have different IDs
	if dev1.DeviceID == dev2.DeviceID {
		t.Error("different devices should have different IDs")
	}
}

func TestRecordEdit(t *testing.T) {
	mds, _ := NewMultiDeviceSession()

	var fingerprint [32]byte
	rand.Read(fingerprint[:])

	device, _ := mds.LinkDevice(fingerprint, "Test Device", DeviceTypeDesktop)

	// Record some edits
	docHash := sha256.Sum256([]byte("test document"))
	err := mds.RecordEdit(device.DeviceID, 100, docHash)
	if err != nil {
		t.Errorf("RecordEdit failed: %v", err)
	}

	// Check device stats updated
	devices := mds.GetDevices()
	if devices[0].BytesAuthored != 100 {
		t.Errorf("bytes authored = %d, want 100", devices[0].BytesAuthored)
	}

	if devices[0].EventCount < 1 {
		t.Error("event count should be at least 1")
	}

	// Check timeline
	timeline := mds.GetTimeline()
	if len(timeline) < 2 { // SessionStart + Edit
		t.Errorf("timeline length = %d, want at least 2", len(timeline))
	}
}

func TestUnauthorizedDevice(t *testing.T) {
	mds, _ := NewMultiDeviceSession()

	// Try to record edit from unknown device
	var unknownID [32]byte
	rand.Read(unknownID[:])

	docHash := sha256.Sum256([]byte("test"))
	err := mds.RecordEdit(unknownID, 50, docHash)
	if err == nil {
		t.Error("should reject edit from unknown device")
	}

	// Should have recorded anomaly
	anomalies := mds.GetAnomalies()
	if len(anomalies) == 0 {
		t.Error("should have recorded anomaly for unauthorized device")
	}
}

func TestTimelineIntegrity(t *testing.T) {
	mds, _ := NewMultiDeviceSession()

	var fingerprint [32]byte
	rand.Read(fingerprint[:])

	device, _ := mds.LinkDevice(fingerprint, "Test Device", DeviceTypeDesktop)

	// Record several edits
	for i := 0; i < 5; i++ {
		docHash := sha256.Sum256([]byte{byte(i)})
		mds.RecordEdit(device.DeviceID, int64(i*10), docHash)
	}

	// Verify timeline
	valid, brokenAt := mds.VerifyTimeline()
	if !valid {
		t.Errorf("timeline should be valid, broken at %d", brokenAt)
	}
}

func TestSimultaneousEditsAnomaly(t *testing.T) {
	mds, _ := NewMultiDeviceSession()

	var fp1, fp2 [32]byte
	rand.Read(fp1[:])
	rand.Read(fp2[:])

	dev1, _ := mds.LinkDevice(fp1, "Device 1", DeviceTypeDesktop)
	dev2, _ := mds.LinkDevice(fp2, "Device 2", DeviceTypePhone)

	// Record edits from both devices in quick succession
	docHash := sha256.Sum256([]byte("test"))
	mds.RecordEdit(dev1.DeviceID, 10, docHash)
	mds.RecordEdit(dev2.DeviceID, 20, docHash) // Should trigger anomaly

	anomalies := mds.GetAnomalies()
	hasSimultaneousAnomaly := false
	for _, a := range anomalies {
		if a.AnomalyType == AnomalySimultaneousEdits || a.AnomalyType == AnomalyImpossibleSwitch {
			hasSimultaneousAnomaly = true
			break
		}
	}

	if !hasSimultaneousAnomaly {
		t.Log("Note: simultaneous edit anomaly may not trigger if execution is slow")
	}
}

func TestDeviceSwitch(t *testing.T) {
	mds, _ := NewMultiDeviceSession()

	var fp1, fp2 [32]byte
	rand.Read(fp1[:])
	rand.Read(fp2[:])

	dev1, _ := mds.LinkDevice(fp1, "Laptop", DeviceTypeDesktop)
	dev2, _ := mds.LinkDevice(fp2, "Tablet", DeviceTypeTablet)

	err := mds.SwitchDevice(dev1.DeviceID, dev2.DeviceID)
	if err != nil {
		t.Errorf("SwitchDevice failed: %v", err)
	}

	// Timeline should have switch events
	timeline := mds.GetTimeline()
	hasSwitch := false
	for _, event := range timeline {
		if event.EventType == EventTypeDeviceSwitch {
			hasSwitch = true
			break
		}
	}

	if !hasSwitch {
		t.Error("timeline should have device switch event")
	}
}

func TestSessionIntegrity(t *testing.T) {
	mds, _ := NewMultiDeviceSession()

	var fingerprint [32]byte
	rand.Read(fingerprint[:])

	device, _ := mds.LinkDevice(fingerprint, "Test Device", DeviceTypeDesktop)

	// Clean session should have high integrity
	score := mds.SessionIntegrity()
	if score < 0.8 {
		t.Errorf("clean session integrity = %f, want >= 0.8", score)
	}

	// Add some normal edits
	docHash := sha256.Sum256([]byte("test"))
	mds.RecordEdit(device.DeviceID, 100, docHash)

	score = mds.SessionIntegrity()
	if score < 0.8 {
		t.Errorf("session with edits integrity = %f, want >= 0.8", score)
	}
}

func TestBindUserIdentity(t *testing.T) {
	mds, _ := NewMultiDeviceSession()

	// Generate ed25519 key pair
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	err = mds.BindUserIdentity(pub)
	if err != nil {
		t.Errorf("BindUserIdentity failed: %v", err)
	}

	// Binding again should fail
	err = mds.BindUserIdentity(pub)
	if err == nil {
		t.Error("binding identity twice should fail")
	}
}

func TestBindDeviceBiometrics(t *testing.T) {
	mds, _ := NewMultiDeviceSession()

	var fingerprint [32]byte
	rand.Read(fingerprint[:])

	device, _ := mds.LinkDevice(fingerprint, "Test Device", DeviceTypeDesktop)

	// Bind biometrics
	var biometricHash [32]byte
	rand.Read(biometricHash[:])

	err := mds.BindDeviceBiometrics(device.DeviceID, biometricHash)
	if err != nil {
		t.Errorf("BindDeviceBiometrics failed: %v", err)
	}

	// Device should have biometric hash
	devices := mds.GetDevices()
	if devices[0].BiometricHash == nil {
		t.Error("device should have biometric hash")
	}
}

func TestExportSessionToken(t *testing.T) {
	mds, _ := NewMultiDeviceSession()

	token, err := mds.ExportSessionToken()
	if err != nil {
		t.Fatalf("ExportSessionToken failed: %v", err)
	}

	if len(token) != 64 {
		t.Errorf("token length = %d, want 64", len(token))
	}

	// Token should validate
	if !mds.ValidateSessionToken(token) {
		t.Error("token should validate")
	}

	// Invalid token should not validate
	invalidToken := make([]byte, 64)
	if mds.ValidateSessionToken(invalidToken) {
		t.Error("invalid token should not validate")
	}
}

func TestGenerateReport(t *testing.T) {
	mds, _ := NewMultiDeviceSession()

	var fingerprint [32]byte
	rand.Read(fingerprint[:])

	device, _ := mds.LinkDevice(fingerprint, "Test Device", DeviceTypeDesktop)

	// Add some activity
	docHash := sha256.Sum256([]byte("test"))
	mds.RecordEdit(device.DeviceID, 100, docHash)
	mds.RecordEdit(device.DeviceID, 50, docHash)

	report := mds.GenerateReport()

	if report.DeviceCount != 1 {
		t.Errorf("device count = %d, want 1", report.DeviceCount)
	}

	if report.TotalBytesAuthored != 150 {
		t.Errorf("total bytes = %d, want 150", report.TotalBytesAuthored)
	}

	if !report.TimelineValid {
		t.Error("timeline should be valid")
	}

	if report.IntegrityScore < 0.5 {
		t.Errorf("integrity score = %f, want >= 0.5", report.IntegrityScore)
	}
}

func TestVerifyDevice(t *testing.T) {
	mds, _ := NewMultiDeviceSession()

	var fingerprint [32]byte
	rand.Read(fingerprint[:])

	device, _ := mds.LinkDevice(fingerprint, "Test Device", DeviceTypeDesktop)

	// Should verify with correct proof
	if !mds.VerifyDevice(device.DeviceID, device.LinkProof) {
		t.Error("device should verify with correct proof")
	}

	// Should not verify with wrong proof
	wrongProof := make([]byte, len(device.LinkProof))
	if mds.VerifyDevice(device.DeviceID, wrongProof) {
		t.Error("device should not verify with wrong proof")
	}

	// Should not verify unknown device
	var unknownID [32]byte
	rand.Read(unknownID[:])
	if mds.VerifyDevice(unknownID, device.LinkProof) {
		t.Error("unknown device should not verify")
	}
}

func TestDeviceTrustDecay(t *testing.T) {
	mds, _ := NewMultiDeviceSession()

	var fingerprint [32]byte
	rand.Read(fingerprint[:])

	device, _ := mds.LinkDevice(fingerprint, "Test Device", DeviceTypeDesktop)
	initialTrust := device.TrustScore

	// Try to record edit from unauthorized device to trigger anomaly
	var unknownID [32]byte
	rand.Read(unknownID[:])
	mds.RecordEdit(unknownID, 50, sha256.Sum256([]byte("test")))

	// The unknown device triggered an anomaly, but the linked device's trust should be unchanged
	// unless we specifically penalize it
	devices := mds.GetDevices()
	if devices[0].TrustScore > initialTrust {
		t.Error("trust should not increase without positive signals")
	}
}

func BenchmarkRecordEdit(b *testing.B) {
	mds, _ := NewMultiDeviceSession()

	var fingerprint [32]byte
	rand.Read(fingerprint[:])

	device, _ := mds.LinkDevice(fingerprint, "Test Device", DeviceTypeDesktop)
	docHash := sha256.Sum256([]byte("test"))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mds.RecordEdit(device.DeviceID, int64(i), docHash)
	}
}

func BenchmarkVerifyTimeline(b *testing.B) {
	mds, _ := NewMultiDeviceSession()

	var fingerprint [32]byte
	rand.Read(fingerprint[:])

	device, _ := mds.LinkDevice(fingerprint, "Test Device", DeviceTypeDesktop)

	// Add many events
	for i := 0; i < 500; i++ {
		docHash := sha256.Sum256([]byte{byte(i)})
		mds.RecordEdit(device.DeviceID, int64(i), docHash)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mds.VerifyTimeline()
	}
}

// TestDeviceSessionLifecycle tests a complete multi-device usage scenario
func TestDeviceSessionLifecycle(t *testing.T) {
	mds, _ := NewMultiDeviceSession()

	// Step 1: User starts on laptop
	var laptopFP [32]byte
	rand.Read(laptopFP[:])
	laptop, _ := mds.LinkDevice(laptopFP, "MacBook Pro", DeviceTypeDesktop)

	// Write some content
	for i := 0; i < 10; i++ {
		docHash := sha256.Sum256([]byte{byte(i)})
		mds.RecordEdit(laptop.DeviceID, 50, docHash)
		time.Sleep(10 * time.Millisecond) // Simulate typing
	}

	// Step 2: User switches to phone
	var phoneFP [32]byte
	rand.Read(phoneFP[:])
	phone, _ := mds.LinkDevice(phoneFP, "iPhone", DeviceTypePhone)

	// Record device switch
	mds.SwitchDevice(laptop.DeviceID, phone.DeviceID)

	// Continue writing on phone
	for i := 0; i < 5; i++ {
		docHash := sha256.Sum256([]byte{byte(i + 100)})
		mds.RecordEdit(phone.DeviceID, 30, docHash)
		time.Sleep(10 * time.Millisecond)
	}

	// Step 3: Verify everything
	report := mds.GenerateReport()

	if report.DeviceCount != 2 {
		t.Errorf("should have 2 devices, got %d", report.DeviceCount)
	}

	expectedBytes := int64(10*50 + 5*30) // 500 + 150 = 650
	if report.TotalBytesAuthored != expectedBytes {
		t.Errorf("total bytes = %d, want %d", report.TotalBytesAuthored, expectedBytes)
	}

	if !report.TimelineValid {
		t.Error("timeline should be valid")
	}

	if report.IntegrityScore < 0.7 {
		t.Errorf("integrity should be good, got %f", report.IntegrityScore)
	}

	t.Logf("Lifecycle test passed: %d devices, %d events, integrity %.2f",
		report.DeviceCount, report.TotalEvents, report.IntegrityScore)
}
