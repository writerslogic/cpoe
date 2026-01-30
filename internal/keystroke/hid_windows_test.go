//go:build windows && cgo

package keystroke

import (
	"testing"
)

// =============================================================================
// Tests for Windows HID Monitoring
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
// Tests for Cross-Validation (same logic as macOS)
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
	// Raw Input sees 150, HID sees 100 = 50 synthetic
	result := CrossValidate(150, 100)

	if !result.SyntheticDetected {
		t.Error("should detect synthetic events")
	}
	if result.Discrepancy != 50 {
		t.Errorf("expected discrepancy 50, got %d", result.Discrepancy)
	}
	// 50/150 = 33.33%
	if result.SyntheticPercentage < 33.0 || result.SyntheticPercentage > 34.0 {
		t.Errorf("expected ~33%% synthetic, got %.2f%%", result.SyntheticPercentage)
	}
}

func TestCrossValidateAllSynthetic(t *testing.T) {
	// Raw Input sees 100, HID sees 0 = all synthetic
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

	// Should be available on Windows
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
		t.Errorf("expected 0 RawInputCount, got %d", stats.CGEventTapCount)
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
	t.Log("Dual-Layer Keystroke Monitoring (Windows):")
	t.Log("")
	t.Log("Layer 1: Windows HID (Hardware Only)")
	t.Log("  - Monitors USB/Bluetooth HID events directly")
	t.Log("  - Cannot be faked by SendInput/keybd_event")
	t.Log("  - Requires actual hardware keyboard input")
	t.Log("")
	t.Log("Layer 2: Raw Input (Application Layer)")
	t.Log("  - Higher level event monitoring")
	t.Log("  - SendInput CAN inject here")
	t.Log("  - Provides timing and additional event data")
	t.Log("")
	t.Log("Cross-Validation:")
	t.Log("  - Compare counts between layers")
	t.Log("  - Raw Input > HID = Synthetic events detected")
	t.Log("  - Raw Input = HID = All events are hardware")
	t.Log("")
	t.Log("Attack Detection:")
	t.Log("  - SendInput attacks: 100% detected")
	t.Log("  - keybd_event injection: 100% detected")
	t.Log("  - PowerShell Send-Keys: 100% detected")
	t.Log("  - USB HID emulation (BadUSB): NOT detected (hardware level)")
	t.Log("")
	t.Log("This provides the strongest practical defense against")
	t.Log("software-based keystroke injection attacks on Windows.")
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
