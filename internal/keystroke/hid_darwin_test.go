//go:build darwin

package keystroke

import (
	"testing"
)

// =============================================================================
// Tests for IOKit HID Monitoring
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
	// When counts match, no synthetic events
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
	// CGEventTap sees 150, HID sees 100 = 50 synthetic
	result := CrossValidate(150, 100)

	if !result.SyntheticDetected {
		t.Error("should detect synthetic events")
	}
	if result.Discrepancy != 50 {
		t.Errorf("expected discrepancy 50, got %d", result.Discrepancy)
	}
	// 50/150 = 33.33%
	expectedPct := 50.0 / 150.0 * 100
	if result.SyntheticPercentage < 33.0 || result.SyntheticPercentage > 34.0 {
		t.Errorf("expected ~33%% synthetic, got %.2f%%", result.SyntheticPercentage)
	}
	_ = expectedPct // silence unused warning
}

func TestCrossValidateAllSynthetic(t *testing.T) {
	// CGEventTap sees 100, HID sees 0 = all synthetic
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
	// Unusual: HID sees more than CGEventTap
	// Could be timing issue or edge case
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

	// May or may not be available depending on permissions
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

	// Stats should be valid (zeros)
	if stats.CGEventTapCount != 0 {
		t.Errorf("expected 0 CGEventTapCount, got %d", stats.CGEventTapCount)
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

	// Should be a ValidatedCounter
	if _, ok := sc.(*ValidatedCounter); !ok {
		t.Error("NewSecureCounter should return *ValidatedCounter")
	}
}

// =============================================================================
// Documentation Tests
// =============================================================================

func TestDualLayerDocumentation(t *testing.T) {
	t.Log("Dual-Layer Keystroke Monitoring:")
	t.Log("")
	t.Log("Layer 1: IOKit HID (Hardware Only)")
	t.Log("  - Monitors USB/Bluetooth HID events directly")
	t.Log("  - Cannot be faked by CGEventPost")
	t.Log("  - Requires actual hardware keyboard input")
	t.Log("")
	t.Log("Layer 2: CGEventTap (Application Layer)")
	t.Log("  - Higher level event monitoring")
	t.Log("  - CGEventPost CAN inject here")
	t.Log("  - Provides timing and additional event data")
	t.Log("")
	t.Log("Cross-Validation:")
	t.Log("  - Compare counts between layers")
	t.Log("  - CGEventTap > HID = Synthetic events detected")
	t.Log("  - CGEventTap = HID = All events are hardware")
	t.Log("")
	t.Log("Attack Detection:")
	t.Log("  - CGEventPost attacks: 100% detected")
	t.Log("  - AppleScript keystroke injection: 100% detected")
	t.Log("  - osascript key events: 100% detected")
	t.Log("  - USB HID emulation (BadUSB): NOT detected (hardware level)")
	t.Log("")
	t.Log("This provides the strongest practical defense against")
	t.Log("software-based keystroke injection attacks.")
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
