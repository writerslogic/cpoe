package hardware

import (
	"bytes"
	"testing"
	"time"
)

func TestCPUJitterEntropy(t *testing.T) {
	jitter := NewCPUJitterEntropy()

	// Collect some entropy
	buf := make([]byte, 32)
	n, err := jitter.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read jitter entropy: %v", err)
	}
	if n != 32 {
		t.Fatalf("Expected 32 bytes, got %d", n)
	}

	// Verify not all zeros
	allZero := true
	for _, b := range buf {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("Jitter entropy returned all zeros")
	}

	// Verify health
	if !jitter.IsHealthy() {
		t.Error("Jitter source reported unhealthy after basic usage")
	}
}

func TestCPUJitterEntropyUniqueness(t *testing.T) {
	jitter := NewCPUJitterEntropy()

	// Collect multiple samples and verify they're different
	samples := make([][]byte, 10)
	for i := range samples {
		samples[i] = make([]byte, 16)
		jitter.Read(samples[i])
	}

	// Check that not all samples are the same
	duplicates := 0
	for i := 0; i < len(samples); i++ {
		for j := i + 1; j < len(samples); j++ {
			if bytes.Equal(samples[i], samples[j]) {
				duplicates++
			}
		}
	}

	if duplicates > 0 {
		t.Errorf("Found %d duplicate samples in 10 jitter entropy samples", duplicates)
	}
}

func TestBlendedEntropyPool(t *testing.T) {
	pool := NewBlendedEntropyPool(BlendedEntropyConfig{
		MinHealthySources: 1,
	})

	// Add a simple test source
	testSource := NewMonitoredEntropySource("test", func() ([]byte, error) {
		buf := make([]byte, 32)
		for i := range buf {
			buf[i] = byte(i ^ 0x55)
		}
		return buf, nil
	})
	pool.AddSource(testSource)

	// Get entropy
	entropy, err := pool.GetEntropy(32)
	if err != nil {
		t.Fatalf("Failed to get entropy: %v", err)
	}
	if len(entropy) != 32 {
		t.Fatalf("Expected 32 bytes, got %d", len(entropy))
	}

	// Verify health report
	report := pool.HealthReport()
	if report.TotalSources != 1 {
		t.Errorf("Expected 1 source, got %d", report.TotalSources)
	}
}

func TestBlendedEntropyPoolMinHealthy(t *testing.T) {
	pool := NewBlendedEntropyPool(BlendedEntropyConfig{
		MinHealthySources: 2,
	})

	// Add only one source - should fail
	testSource := NewMonitoredEntropySource("test", func() ([]byte, error) {
		return make([]byte, 32), nil
	})
	pool.AddSource(testSource)

	// Should fail because we require 2 healthy sources
	_, err := pool.GetEntropy(32)
	if err != ErrInsufficientEntropy {
		t.Errorf("Expected ErrInsufficientEntropy, got %v", err)
	}
}

func TestRepetitionCountTest(t *testing.T) {
	test := NewRepetitionCountTest(5)

	// Feed normal data
	for i := 0; i < 100; i++ {
		test.Feed(byte(i))
	}

	if test.Status() == HealthFailed {
		t.Error("RCT should not fail on varying data")
	}

	// Reset and feed repeating data
	test.Reset()
	for i := 0; i < 10; i++ {
		test.Feed(0x42)
	}

	if test.Status() != HealthFailed {
		t.Error("RCT should fail on 10 repeats with cutoff 5")
	}
}

func TestAdaptiveProportionTest(t *testing.T) {
	test := NewAdaptiveProportionTest(100, 50)

	// Feed balanced data
	for i := 0; i < 100; i++ {
		test.Feed(byte(i))
	}

	if test.Status() == HealthFailed {
		t.Error("APT should not fail on balanced data")
	}

	// Reset and feed biased data
	test.Reset()
	for i := 0; i < 100; i++ {
		test.Feed(0x00)
	}

	if test.Status() != HealthFailed {
		t.Error("APT should fail on heavily biased data")
	}
}

func TestChiSquareTest(t *testing.T) {
	test := NewChiSquareTest(256, 310.5)

	// Feed data from all byte values
	for i := 0; i < 256; i++ {
		test.Feed(byte(i))
	}

	// Should be healthy (uniform distribution)
	if test.Status() == HealthFailed {
		t.Error("Chi-square test should not fail on uniform data")
	}

	chiSq := test.LastChiSquare()
	t.Logf("Chi-square value for uniform data: %.2f", chiSq)
}

func TestMonitoredEntropySource(t *testing.T) {
	callCount := 0
	source := NewMonitoredEntropySource("test", func() ([]byte, error) {
		callCount++
		buf := make([]byte, 32)
		for i := range buf {
			buf[i] = byte(callCount + i)
		}
		return buf, nil
	})

	// Get entropy
	entropy, err := source.GetEntropy(32)
	if err != nil {
		t.Fatalf("Failed to get entropy: %v", err)
	}
	if len(entropy) != 32 {
		t.Fatalf("Expected 32 bytes, got %d", len(entropy))
	}

	// Check stats
	stats := source.Stats()
	if stats.Name != "test" {
		t.Errorf("Expected name 'test', got '%s'", stats.Name)
	}
}

func TestEntropyHealthTestInterface(t *testing.T) {
	// Verify all tests implement the interface
	tests := []EntropyHealthTest{
		NewRepetitionCountTest(21),
		NewAdaptiveProportionTest(512, 325),
		NewChiSquareTest(1024, 310.5),
		NewAutocorrelationTest(256, 16, 0.1),
	}

	for _, test := range tests {
		name := test.Name()
		if name == "" {
			t.Error("Test returned empty name")
		}

		// Feed some data
		for i := 0; i < 100; i++ {
			test.Feed(byte(i))
		}

		// Check status is valid
		status := test.Status()
		if status < HealthUnknown || status > HealthRecovering {
			t.Errorf("Test %s returned invalid status: %d", name, status)
		}

		// Reset should work
		test.Reset()
		if test.FailureCount() != 0 {
			t.Errorf("Test %s failure count not reset", name)
		}
	}
}

func TestBlendedEntropyPoolIsHealthy(t *testing.T) {
	pool := NewBlendedEntropyPool(BlendedEntropyConfig{
		MinHealthySources: 1,
	})

	// Empty pool with minHealthy=1 should fail to get entropy
	_, err := pool.GetEntropy(32)
	if err != ErrInsufficientEntropy {
		t.Errorf("Empty pool should return ErrInsufficientEntropy, got %v", err)
	}

	// Add a source that produces uniformly distributed data
	// Use a counter-based approach to ensure all byte values appear
	counter := 0
	pool.AddSource(NewMonitoredEntropySource("test", func() ([]byte, error) {
		buf := make([]byte, 32)
		for i := range buf {
			buf[i] = byte((counter + i) % 256)
		}
		counter += 32
		return buf, nil
	}))

	// Call GetEntropy - should succeed because the source produces
	// uniformly distributed data
	for i := 0; i < 5; i++ {
		_, err := pool.GetEntropy(32)
		if err != nil {
			t.Fatalf("GetEntropy failed on call %d: %v", i, err)
		}
	}

	// Check health report
	report := pool.HealthReport()
	t.Logf("Health report: total=%d, healthy=%d, overall=%s",
		report.TotalSources, report.HealthySources, report.OverallHealth)
}

func BenchmarkCPUJitterEntropy(b *testing.B) {
	jitter := NewCPUJitterEntropy()
	buf := make([]byte, 32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		jitter.Read(buf)
	}
}

func BenchmarkBlendedEntropyPool(b *testing.B) {
	pool := NewBlendedEntropyPool(BlendedEntropyConfig{
		MinHealthySources: 1,
	})

	pool.AddSource(NewMonitoredEntropySource("test", func() ([]byte, error) {
		return make([]byte, 32), nil
	}))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pool.GetEntropy(32)
	}
}

func TestIsolatedEntropyDaemon(t *testing.T) {
	socketPath := "/tmp/test-entropy-" + time.Now().Format("20060102150405") + ".sock"

	daemon, err := NewIsolatedEntropyDaemon(socketPath)
	if err != nil {
		t.Fatalf("Failed to create daemon: %v", err)
	}

	// Check initial state
	if daemon.running.Load() {
		t.Error("Daemon should not be running before Start()")
	}

	// Start the daemon
	if err := daemon.Start(); err != nil {
		t.Fatalf("Failed to start daemon: %v", err)
	}

	// Give it time to initialize
	time.Sleep(100 * time.Millisecond)

	if !daemon.running.Load() {
		t.Error("Daemon should be running after Start()")
	}

	// Stop the daemon
	daemon.Stop()

	time.Sleep(100 * time.Millisecond)

	if daemon.running.Load() {
		t.Error("Daemon should not be running after Stop()")
	}
}
