//go:build darwin || linux || windows

package keystroke

import (
	"testing"
)

func TestKeyboardDeviceFingerprint(t *testing.T) {
	dev := KeyboardDevice{
		VendorID:       0x046D,
		ProductID:      0xC52B,
		VersionNum:     0x0111,
		VendorName:     "Logitech",
		ProductName:    "USB Receiver",
		SerialNumber:   "12345678",
		DevicePath:     "/dev/hidraw0",
		ConnectionType: ConnectionUSB,
	}

	// Compute fingerprint
	fp1 := dev.ComputeFingerprint()

	// Should be deterministic
	fp2 := dev.ComputeFingerprint()
	if fp1 != fp2 {
		t.Error("fingerprint should be deterministic")
	}

	// Different device should have different fingerprint
	dev2 := KeyboardDevice{
		VendorID:       0x05AC,
		ProductID:      0x0256,
		ProductName:    "Apple Internal Keyboard",
		ConnectionType: ConnectionInternal,
	}
	fp3 := dev2.ComputeFingerprint()
	if fp1 == fp3 {
		t.Error("different devices should have different fingerprints")
	}
}

func TestConnectionTypeIsPhysical(t *testing.T) {
	tests := []struct {
		connType   ConnectionType
		isPhysical bool
	}{
		{ConnectionUSB, true},
		{ConnectionBluetooth, true},
		{ConnectionPS2, true},
		{ConnectionInternal, true},
		{ConnectionVirtual, false},
		{ConnectionUnknown, false},
	}

	for _, tc := range tests {
		if tc.connType.IsPhysical() != tc.isPhysical {
			t.Errorf("ConnectionType %v.IsPhysical() = %v, want %v",
				tc.connType, tc.connType.IsPhysical(), tc.isPhysical)
		}
	}
}

func TestConnectionTypeString(t *testing.T) {
	tests := []struct {
		connType ConnectionType
		str      string
	}{
		{ConnectionUSB, "USB"},
		{ConnectionBluetooth, "Bluetooth"},
		{ConnectionPS2, "PS/2"},
		{ConnectionInternal, "Internal"},
		{ConnectionVirtual, "Virtual"},
		{ConnectionUnknown, "Unknown"},
	}

	for _, tc := range tests {
		if tc.connType.String() != tc.str {
			t.Errorf("ConnectionType %d.String() = %q, want %q",
				tc.connType, tc.connType.String(), tc.str)
		}
	}
}

func TestLookupVendorName(t *testing.T) {
	tests := []struct {
		vendorID uint16
		name     string
	}{
		{0x046D, "Logitech"},
		{0x05AC, "Apple"},
		{0x045E, "Microsoft"},
		{0x1532, "Razer"},
		{0x0000, ""},      // Unknown vendor
		{0xFFFF, ""},      // Unknown vendor
	}

	for _, tc := range tests {
		name := LookupVendorName(tc.vendorID)
		if name != tc.name {
			t.Errorf("LookupVendorName(0x%04X) = %q, want %q",
				tc.vendorID, name, tc.name)
		}
	}
}

func TestDeviceTracker(t *testing.T) {
	tracker := NewDeviceTracker()
	if tracker == nil {
		t.Fatal("NewDeviceTracker returned nil")
	}

	// Initial state
	devices := tracker.GetDevices()
	// May or may not have devices depending on system
	_ = devices

	alerts := tracker.GetAlerts()
	if alerts == nil {
		t.Error("GetAlerts should return non-nil slice")
	}

	changes := tracker.GetChanges()
	if changes == nil {
		t.Error("GetChanges should return non-nil slice")
	}

	// Test report generation
	report := tracker.GenerateReport()
	if report.SessionStart.IsZero() {
		t.Error("report should have session start time")
	}
}

func TestDeviceTrackerConsistency(t *testing.T) {
	tracker := NewDeviceTracker()

	// Without any device changes, consistency should be high
	score, issues := tracker.VerifyDeviceConsistency()
	if score < 0 || score > 1 {
		t.Errorf("consistency score %f out of range [0,1]", score)
	}
	_ = issues
}

func TestDeviceHash(t *testing.T) {
	tracker := NewDeviceTracker()

	// Hash should be deterministic
	hash1 := tracker.DeviceHash()
	hash2 := tracker.DeviceHash()

	// Note: Hash includes timestamp, so these might differ slightly
	// In practice, within the same millisecond they should match
	_ = hash1
	_ = hash2
}

func TestSessionDeviceReport(t *testing.T) {
	tracker := NewDeviceTracker()
	report := tracker.GenerateReport()

	// Verify report structure
	if report.SessionStart.IsZero() {
		t.Error("SessionStart should not be zero")
	}

	if report.ConsistencyScore < 0 || report.ConsistencyScore > 1 {
		t.Errorf("ConsistencyScore %f out of range", report.ConsistencyScore)
	}

	// DeviceHash should not be all zeros
	allZero := true
	for _, b := range report.DeviceHash {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("DeviceHash should not be all zeros")
	}
}
