//go:build linux

package keystroke

import (
	"testing"
)

// =============================================================================
// Tests for Linux HID Monitoring
// =============================================================================

func TestHIDMonitorNew(t *testing.T) {
	h := NewHIDMonitor()
	if h == nil {
		t.Fatal("NewHIDMonitor returned nil")
	}

	if h.IsRunning() {
		t.Error("new HID monitor should not be running")
	}
}

func TestHIDMonitorCount(t *testing.T) {
	h := NewHIDMonitor()

	// Count should be 0 before starting
	if h.Count() != 0 {
		t.Errorf("expected count 0, got %d", h.Count())
	}
}

func TestHIDMonitorReset(t *testing.T) {
	h := NewHIDMonitor()

	// Reset should not panic even when not running
	h.Reset()

	if h.Count() != 0 {
		t.Errorf("count should be 0 after reset, got %d", h.Count())
	}
}

// =============================================================================
// Tests for Cross-Validation
// =============================================================================

func TestCrossValidateNoSynthetic(t *testing.T) {
	result := CrossValidate(100, 100)

	if result.SyntheticDetected {
		t.Error("should not detect synthetic when counts match")
	}
	if result.Discrepancy != 0 {
		t.Errorf("expected discrepancy 0, got %d", result.Discrepancy)
	}
	if result.SyntheticPercentage != 0 {
		t.Errorf("expected 0%% synthetic, got %.2f%%", result.SyntheticPercentage)
	}
}

func TestCrossValidateSyntheticDetected(t *testing.T) {
	result := CrossValidate(150, 100)

	if !result.SyntheticDetected {
		t.Error("should detect synthetic events")
	}
	if result.Discrepancy != 50 {
		t.Errorf("expected discrepancy 50, got %d", result.Discrepancy)
	}
	if result.SyntheticPercentage < 33.0 || result.SyntheticPercentage > 34.0 {
		t.Errorf("expected ~33%% synthetic, got %.2f%%", result.SyntheticPercentage)
	}
}

func TestCrossValidateAllSynthetic(t *testing.T) {
	result := CrossValidate(100, 0)

	if !result.SyntheticDetected {
		t.Error("should detect all synthetic events")
	}
	if result.Discrepancy != 100 {
		t.Errorf("expected discrepancy 100, got %d", result.Discrepancy)
	}
	if result.SyntheticPercentage != 100 {
		t.Errorf("expected 100%% synthetic, got %.2f%%", result.SyntheticPercentage)
	}
}

func TestCrossValidateNegativeDiscrepancy(t *testing.T) {
	result := CrossValidate(100, 120)

	if result.SyntheticDetected {
		t.Error("negative discrepancy should not indicate synthetic")
	}
	if result.Discrepancy != -20 {
		t.Errorf("expected discrepancy -20, got %d", result.Discrepancy)
	}
}

func TestCrossValidateZeroCounts(t *testing.T) {
	result := CrossValidate(0, 0)

	if result.SyntheticDetected {
		t.Error("zero counts should not indicate synthetic")
	}
	if result.SyntheticPercentage != 0 {
		t.Errorf("expected 0%% synthetic with zero counts, got %.2f%%", result.SyntheticPercentage)
	}
}

// =============================================================================
// Tests for ValidatedCounter
// =============================================================================

func TestValidatedCounterNew(t *testing.T) {
	vc := NewValidatedCounter()
	if vc == nil {
		t.Fatal("NewValidatedCounter returned nil")
	}

	if vc.IsRunning() {
		t.Error("new ValidatedCounter should not be running")
	}
}

func TestValidatedCounterAvailable(t *testing.T) {
	vc := NewValidatedCounter()

	available, msg := vc.Available()
	t.Logf("Available: %v, Message: %s", available, msg)

	if msg == "" {
		t.Error("should have availability message")
	}
}

func TestValidatedCounterSetStrictValidation(t *testing.T) {
	vc := NewValidatedCounter()

	// Default should be strict
	vc.mu.RLock()
	if !vc.strictValidation {
		t.Error("default should be strict validation")
	}
	vc.mu.RUnlock()

	// Set to permissive
	vc.SetStrictValidation(false)
	vc.mu.RLock()
	if vc.strictValidation {
		t.Error("should be permissive after SetStrictValidation(false)")
	}
	vc.mu.RUnlock()
}

func TestValidatedCounterSyntheticDetected(t *testing.T) {
	vc := NewValidatedCounter()

	// Should be false initially
	if vc.SyntheticDetected() {
		t.Error("should not detect synthetic events initially")
	}
}

func TestValidatedCounterValidationStats(t *testing.T) {
	vc := NewValidatedCounter()

	stats := vc.ValidationStats()

	if stats.CGEventTapCount != 0 {
		t.Errorf("expected 0 InputCount, got %d", stats.CGEventTapCount)
	}
	if stats.HIDCount != 0 {
		t.Errorf("expected 0 HIDCount, got %d", stats.HIDCount)
	}
	if stats.TotalSyntheticDetected != 0 {
		t.Errorf("expected 0 TotalSyntheticDetected, got %d", stats.TotalSyntheticDetected)
	}

	t.Logf("ValidationStats: %+v", stats)
}

func TestNewSecureCounter(t *testing.T) {
	sc := NewSecureCounter()
	if sc == nil {
		t.Fatal("NewSecureCounter returned nil")
	}

	if _, ok := sc.(*ValidatedCounter); !ok {
		t.Error("NewSecureCounter should return *ValidatedCounter")
	}
}

// =============================================================================
// Tests for HIDInputMonitor (alternative approach)
// =============================================================================

func TestHIDInputMonitorNew(t *testing.T) {
	h := NewHIDInputMonitor()
	if h == nil {
		t.Fatal("NewHIDInputMonitor returned nil")
	}

	if h.IsRunning() {
		t.Error("new HIDInputMonitor should not be running")
	}
}

func TestHIDInputMonitorCount(t *testing.T) {
	h := NewHIDInputMonitor()

	if h.Count() != 0 {
		t.Errorf("expected count 0, got %d", h.Count())
	}
}

func TestHIDInputMonitorReset(t *testing.T) {
	h := NewHIDInputMonitor()

	h.Reset()

	if h.Count() != 0 {
		t.Errorf("count should be 0 after reset, got %d", h.Count())
	}
}

// =============================================================================
// Documentation Tests
// =============================================================================

func TestDualLayerDocumentation(t *testing.T) {
	t.Log("Dual-Layer Keystroke Monitoring (Linux):")
	t.Log("")
	t.Log("Layer 1: hidraw (Hardware HID Reports)")
	t.Log("  - Monitors raw USB/Bluetooth HID reports")
	t.Log("  - Cannot be faked by uinput/xdotool/ydotool")
	t.Log("  - Requires access to /dev/hidraw* devices")
	t.Log("")
	t.Log("Layer 2: evdev (Input Subsystem)")
	t.Log("  - Kernel input event interface")
	t.Log("  - uinput/xdotool CAN inject here")
	t.Log("  - Always available with input group access")
	t.Log("")
	t.Log("Cross-Validation:")
	t.Log("  - Compare counts between layers")
	t.Log("  - evdev > hidraw = Synthetic events detected")
	t.Log("  - evdev = hidraw = All events are hardware")
	t.Log("")
	t.Log("Attack Detection:")
	t.Log("  - xdotool type attacks: 100% detected (when hidraw available)")
	t.Log("  - ydotool injection: 100% detected (when hidraw available)")
	t.Log("  - uinput virtual devices: 100% detected (when hidraw available)")
	t.Log("  - evemu replay: 100% detected (when hidraw available)")
	t.Log("  - USB HID emulation (BadUSB): NOT detected (hardware level)")
	t.Log("")
	t.Log("Fallback Mode (no hidraw access):")
	t.Log("  - Uses physical device heuristics")
	t.Log("  - Filters out known virtual devices")
	t.Log("  - Less reliable than full cross-validation")
}

// =============================================================================
// Benchmark Tests
// =============================================================================

func BenchmarkCrossValidate(b *testing.B) {
	for i := 0; i < b.N; i++ {
		CrossValidate(1000, 950)
	}
}

func BenchmarkValidationStats(b *testing.B) {
	vc := NewValidatedCounter()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = vc.ValidationStats()
	}
}
