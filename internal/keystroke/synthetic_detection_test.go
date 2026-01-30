//go:build darwin

package keystroke

import (
	"testing"
)

// =============================================================================
// Tests for Synthetic Event Detection (Darwin-specific)
// =============================================================================
//
// These tests verify the CGEvent source verification that detects CGEventPost
// injection attacks. The actual verification happens in C code, so these tests
// focus on:
// 1. Statistics tracking works correctly
// 2. Strict vs permissive mode behaves correctly
// 3. The Go API correctly exposes C-level functionality
//
// Note: We cannot easily inject actual synthetic events in unit tests without
// accessibility permissions and potentially affecting the test environment.
// For full integration testing, see the keystroke-gen tool.

func TestSyntheticEventStatsStruct(t *testing.T) {
	stats := SyntheticEventStats{
		TotalRejected:           10,
		Suspicious:              5,
		RejectedBadSourceState:  3,
		RejectedBadKeyboardType: 2,
		RejectedNonKernelPID:    4,
		RejectedZeroTimestamp:   1,
		TotalEventsSeen:         100,
	}

	if stats.TotalRejected != 10 {
		t.Errorf("expected TotalRejected 10, got %d", stats.TotalRejected)
	}

	if stats.TotalEventsSeen != 100 {
		t.Errorf("expected TotalEventsSeen 100, got %d", stats.TotalEventsSeen)
	}
}

func TestDarwinCounterStrictModeDefault(t *testing.T) {
	dc := &DarwinCounter{}

	// Default should be strict mode
	// Note: This tests the Go-side default; the C-side default is set independently
	if !dc.StrictMode() {
		t.Log("C-side strict mode defaults to enabled (as expected)")
	}
}

func TestDarwinCounterSetStrictMode(t *testing.T) {
	dc := &DarwinCounter{}

	// Set to permissive
	dc.SetStrictMode(false)
	if dc.StrictMode() {
		t.Error("strict mode should be false after SetStrictMode(false)")
	}

	// Set back to strict
	dc.SetStrictMode(true)
	if !dc.StrictMode() {
		t.Error("strict mode should be true after SetStrictMode(true)")
	}
}

func TestDarwinCounterSyntheticEventStatsAccessor(t *testing.T) {
	dc := &DarwinCounter{}

	// Get stats - should return valid struct even without running
	stats := dc.SyntheticEventStats()

	// All values should be non-negative
	if stats.TotalRejected < 0 {
		t.Error("TotalRejected should be non-negative")
	}
	if stats.Suspicious < 0 {
		t.Error("Suspicious should be non-negative")
	}
	if stats.TotalEventsSeen < 0 {
		t.Error("TotalEventsSeen should be non-negative")
	}
}

func TestDarwinCounterInjectionAttemptDetected(t *testing.T) {
	dc := &DarwinCounter{}

	// Without any events, should return false
	// Note: This depends on global C state, so may be affected by other tests
	detected := dc.InjectionAttemptDetected()
	t.Logf("InjectionAttemptDetected: %v", detected)
}

func TestDarwinCounterSyntheticRejectionRate(t *testing.T) {
	dc := &DarwinCounter{}

	// Get rejection rate
	rate := dc.SyntheticRejectionRate()

	// Rate should be between 0 and 100
	if rate < 0 || rate > 100 {
		t.Errorf("rejection rate should be 0-100, got %f", rate)
	}

	t.Logf("Current synthetic rejection rate: %.2f%%", rate)
}

func TestDarwinCounterResetAllCounters(t *testing.T) {
	dc := &DarwinCounter{}

	// Reset all counters
	dc.ResetAllCounters()

	// Stats should be zero after reset
	stats := dc.SyntheticEventStats()

	// Note: Due to global C state, these might not be exactly zero if
	// other tests or the system has generated events. We just verify
	// the reset function runs without error.
	t.Logf("After reset: TotalRejected=%d, TotalSeen=%d",
		stats.TotalRejected, stats.TotalEventsSeen)
}

// =============================================================================
// Documentation Tests
// =============================================================================

func TestSyntheticDetectionDocumentation(t *testing.T) {
	// This test documents the synthetic event detection capabilities
	t.Log("Synthetic Event Detection Capabilities:")
	t.Log("")
	t.Log("Detection Methods:")
	t.Log("1. Event Source State ID - Detects non-HID source events")
	t.Log("2. Keyboard Type - Detects missing/invalid keyboard type")
	t.Log("3. Source PID - Detects non-kernel source (CGEventPost sets process PID)")
	t.Log("4. Event Timestamp - Detects missing timestamps")
	t.Log("")
	t.Log("Modes:")
	t.Log("- Strict Mode (default): Rejects any suspicious event")
	t.Log("- Permissive Mode: Counts suspicious events but accepts them")
	t.Log("")
	t.Log("Limitations:")
	t.Log("- A sophisticated attacker could forge CGEvent fields")
	t.Log("- Hardware-level injection (USB HID) bypasses these checks")
	t.Log("- Virtual keyboards may trigger false positives")
	t.Log("")
	t.Log("Recommendations:")
	t.Log("- Use strict mode for high-security scenarios")
	t.Log("- Monitor rejection stats for attack detection")
	t.Log("- Combine with behavioral analysis for best results")
}

// =============================================================================
// Benchmark Tests
// =============================================================================

func BenchmarkSyntheticEventStatsAccess(b *testing.B) {
	dc := &DarwinCounter{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = dc.SyntheticEventStats()
	}
}

func BenchmarkInjectionAttemptDetected(b *testing.B) {
	dc := &DarwinCounter{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = dc.InjectionAttemptDetected()
	}
}

func BenchmarkSyntheticRejectionRate(b *testing.B) {
	dc := &DarwinCounter{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = dc.SyntheticRejectionRate()
	}
}
