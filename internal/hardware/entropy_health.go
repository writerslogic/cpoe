// Package hardware provides hardware-rooted entropy with continuous health monitoring.
//
// This file implements:
// 1. NIST SP 800-90B health tests (Repetition Count, Adaptive Proportion)
// 2. Multi-source entropy blending (TPM + PUF + CPU jitter)
// 3. On-the-fly bias detection and source isolation
//
// If an attacker attempts to bias any single source, the health tests
// detect it and the blending ensures the other sources maintain security.
package hardware

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrEntropyHealthFailed    = errors.New("entropy source failed health test")
	ErrInsufficientEntropy    = errors.New("insufficient entropy sources available")
	ErrAllSourcesCompromised  = errors.New("all entropy sources failed health tests")
	ErrBiasDetected           = errors.New("bias detected in entropy source")
)

// HealthStatus represents the health state of an entropy source.
type HealthStatus int

const (
	HealthUnknown HealthStatus = iota
	HealthHealthy
	HealthDegraded  // Some tests failing, still usable with caution
	HealthFailed    // Critical failure, do not use
	HealthRecovering // Was failed, now passing (monitor closely)
)

func (h HealthStatus) String() string {
	switch h {
	case HealthHealthy:
		return "healthy"
	case HealthDegraded:
		return "degraded"
	case HealthFailed:
		return "failed"
	case HealthRecovering:
		return "recovering"
	default:
		return "unknown"
	}
}

// EntropyHealthTest defines the interface for entropy health tests.
type EntropyHealthTest interface {
	// Name returns the test name
	Name() string

	// Feed feeds a byte to the test
	Feed(b byte)

	// Status returns current test status
	Status() HealthStatus

	// Reset resets the test state
	Reset()

	// FailureCount returns number of failures since last reset
	FailureCount() uint64
}

// RepetitionCountTest implements NIST SP 800-90B Section 4.4.1.
// Detects stuck-at faults where the same value repeats too many times.
//
// If the same value appears C times in a row, where C exceeds the cutoff,
// the source is considered compromised.
type RepetitionCountTest struct {
	mu sync.Mutex

	// Configuration
	cutoff int // Maximum allowed consecutive repeats

	// State
	lastValue    byte
	repeatCount  int
	failures     uint64
	status       HealthStatus
}

// NewRepetitionCountTest creates a new repetition count test.
// cutoff is calculated as: 1 + ceil(-log2(alpha) / H)
// where alpha is false positive probability and H is min-entropy estimate.
// For alpha=2^-20 and H=1 (conservative), cutoff ≈ 21
func NewRepetitionCountTest(cutoff int) *RepetitionCountTest {
	if cutoff <= 0 {
		cutoff = 21 // Conservative default
	}
	return &RepetitionCountTest{
		cutoff: cutoff,
		status: HealthUnknown,
	}
}

func (t *RepetitionCountTest) Name() string {
	return "repetition_count"
}

func (t *RepetitionCountTest) Feed(b byte) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if b == t.lastValue {
		t.repeatCount++
		if t.repeatCount >= t.cutoff {
			t.failures++
			t.status = HealthFailed
		}
	} else {
		t.lastValue = b
		t.repeatCount = 1
		if t.status == HealthFailed {
			t.status = HealthRecovering
		} else if t.status != HealthRecovering {
			t.status = HealthHealthy
		}
	}
}

func (t *RepetitionCountTest) Status() HealthStatus {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.status
}

func (t *RepetitionCountTest) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.repeatCount = 0
	t.failures = 0
	t.status = HealthUnknown
}

func (t *RepetitionCountTest) FailureCount() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.failures
}

// AdaptiveProportionTest implements NIST SP 800-90B Section 4.4.2.
// Detects bias by monitoring the proportion of a single value in a window.
//
// If any value appears more than the cutoff times in a window of W samples,
// the source is considered biased.
type AdaptiveProportionTest struct {
	mu sync.Mutex

	// Configuration
	windowSize int // W - window size
	cutoff     int // C - maximum allowed occurrences

	// State
	window       []byte
	windowPos    int
	windowFull   bool
	counts       [256]int // Count of each byte value in window
	failures     uint64
	status       HealthStatus
}

// NewAdaptiveProportionTest creates a new adaptive proportion test.
// For H=1 (min-entropy) and alpha=2^-20:
// W = 512, C ≈ 325 (for 8-bit samples)
func NewAdaptiveProportionTest(windowSize, cutoff int) *AdaptiveProportionTest {
	if windowSize <= 0 {
		windowSize = 512
	}
	if cutoff <= 0 {
		cutoff = 325
	}
	return &AdaptiveProportionTest{
		windowSize: windowSize,
		cutoff:     cutoff,
		window:     make([]byte, windowSize),
		status:     HealthUnknown,
	}
}

func (t *AdaptiveProportionTest) Name() string {
	return "adaptive_proportion"
}

func (t *AdaptiveProportionTest) Feed(b byte) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Remove old value from counts if window is full
	if t.windowFull {
		oldValue := t.window[t.windowPos]
		t.counts[oldValue]--
	}

	// Add new value
	t.window[t.windowPos] = b
	t.counts[b]++
	t.windowPos = (t.windowPos + 1) % t.windowSize

	if t.windowPos == 0 {
		t.windowFull = true
	}

	// Check if any value exceeds cutoff
	if t.windowFull {
		maxCount := 0
		for _, c := range t.counts {
			if c > maxCount {
				maxCount = c
			}
		}

		if maxCount >= t.cutoff {
			t.failures++
			t.status = HealthFailed
		} else if t.status == HealthFailed {
			t.status = HealthRecovering
		} else {
			t.status = HealthHealthy
		}
	}
}

func (t *AdaptiveProportionTest) Status() HealthStatus {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.status
}

func (t *AdaptiveProportionTest) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.window = make([]byte, t.windowSize)
	t.windowPos = 0
	t.windowFull = false
	t.counts = [256]int{}
	t.failures = 0
	t.status = HealthUnknown
}

func (t *AdaptiveProportionTest) FailureCount() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.failures
}

// ChiSquareTest detects deviation from uniform distribution.
type ChiSquareTest struct {
	mu sync.Mutex

	// Configuration
	windowSize    int
	threshold     float64 // Chi-square critical value

	// State
	window        []byte
	windowPos     int
	windowFull    bool
	failures      uint64
	lastChiSquare float64
	status        HealthStatus
}

// NewChiSquareTest creates a chi-square uniformity test.
// For 255 degrees of freedom and alpha=0.001, threshold ≈ 310.5
func NewChiSquareTest(windowSize int, threshold float64) *ChiSquareTest {
	if windowSize <= 0 {
		windowSize = 1024
	}
	if threshold <= 0 {
		threshold = 310.5
	}
	return &ChiSquareTest{
		windowSize: windowSize,
		threshold:  threshold,
		window:     make([]byte, windowSize),
		status:     HealthUnknown,
	}
}

func (t *ChiSquareTest) Name() string {
	return "chi_square"
}

func (t *ChiSquareTest) Feed(b byte) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.window[t.windowPos] = b
	t.windowPos = (t.windowPos + 1) % t.windowSize

	if t.windowPos == 0 {
		t.windowFull = true
		t.evaluate()
	}
}

func (t *ChiSquareTest) evaluate() {
	// Count occurrences
	var counts [256]int
	for _, b := range t.window {
		counts[b]++
	}

	// Expected count for uniform distribution
	expected := float64(t.windowSize) / 256.0

	// Compute chi-square statistic
	var chiSquare float64
	for _, count := range counts {
		diff := float64(count) - expected
		chiSquare += (diff * diff) / expected
	}

	t.lastChiSquare = chiSquare

	if chiSquare > t.threshold {
		t.failures++
		t.status = HealthFailed
	} else if t.status == HealthFailed {
		t.status = HealthRecovering
	} else {
		t.status = HealthHealthy
	}
}

func (t *ChiSquareTest) Status() HealthStatus {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.status
}

func (t *ChiSquareTest) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.window = make([]byte, t.windowSize)
	t.windowPos = 0
	t.windowFull = false
	t.failures = 0
	t.status = HealthUnknown
}

func (t *ChiSquareTest) FailureCount() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.failures
}

func (t *ChiSquareTest) LastChiSquare() float64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lastChiSquare
}

// AutocorrelationTest detects patterns/correlations in the entropy stream.
type AutocorrelationTest struct {
	mu sync.Mutex

	// Configuration
	windowSize int
	maxLag     int
	threshold  float64 // Autocorrelation threshold

	// State
	window     []byte
	windowPos  int
	windowFull bool
	failures   uint64
	status     HealthStatus
}

// NewAutocorrelationTest creates an autocorrelation test.
func NewAutocorrelationTest(windowSize, maxLag int, threshold float64) *AutocorrelationTest {
	if windowSize <= 0 {
		windowSize = 256
	}
	if maxLag <= 0 {
		maxLag = 16
	}
	if threshold <= 0 {
		threshold = 0.1 // 10% correlation threshold
	}
	return &AutocorrelationTest{
		windowSize: windowSize,
		maxLag:     maxLag,
		threshold:  threshold,
		window:     make([]byte, windowSize),
		status:     HealthUnknown,
	}
}

func (t *AutocorrelationTest) Name() string {
	return "autocorrelation"
}

func (t *AutocorrelationTest) Feed(b byte) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.window[t.windowPos] = b
	t.windowPos = (t.windowPos + 1) % t.windowSize

	if t.windowPos == 0 {
		t.windowFull = true
		t.evaluate()
	}
}

func (t *AutocorrelationTest) evaluate() {
	// Compute mean
	var sum float64
	for _, b := range t.window {
		sum += float64(b)
	}
	mean := sum / float64(t.windowSize)

	// Compute variance
	var variance float64
	for _, b := range t.window {
		diff := float64(b) - mean
		variance += diff * diff
	}
	variance /= float64(t.windowSize)

	if variance == 0 {
		t.failures++
		t.status = HealthFailed
		return
	}

	// Check autocorrelation at each lag
	failed := false
	for lag := 1; lag <= t.maxLag && lag < t.windowSize; lag++ {
		var correlation float64
		for i := 0; i < t.windowSize-lag; i++ {
			diff1 := float64(t.window[i]) - mean
			diff2 := float64(t.window[i+lag]) - mean
			correlation += diff1 * diff2
		}
		correlation /= float64(t.windowSize-lag) * variance

		if math.Abs(correlation) > t.threshold {
			failed = true
			break
		}
	}

	if failed {
		t.failures++
		t.status = HealthFailed
	} else if t.status == HealthFailed {
		t.status = HealthRecovering
	} else {
		t.status = HealthHealthy
	}
}

func (t *AutocorrelationTest) Status() HealthStatus {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.status
}

func (t *AutocorrelationTest) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.window = make([]byte, t.windowSize)
	t.windowPos = 0
	t.windowFull = false
	t.failures = 0
	t.status = HealthUnknown
}

func (t *AutocorrelationTest) FailureCount() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.failures
}

// MonitoredEntropySource wraps an entropy source with health monitoring.
type MonitoredEntropySource struct {
	name   string
	source func() ([]byte, error)
	tests  []EntropyHealthTest

	// Statistics
	bytesProduced   uint64
	failureCount    uint64
	lastStatus      HealthStatus
	lastStatusTime  time.Time
	quarantineUntil time.Time

	mu sync.RWMutex
}

// NewMonitoredEntropySource creates a monitored entropy source.
func NewMonitoredEntropySource(name string, source func() ([]byte, error)) *MonitoredEntropySource {
	return &MonitoredEntropySource{
		name:   name,
		source: source,
		tests: []EntropyHealthTest{
			NewRepetitionCountTest(21),
			NewAdaptiveProportionTest(512, 325),
			NewChiSquareTest(1024, 310.5),
			NewAutocorrelationTest(256, 16, 0.1),
		},
		lastStatus: HealthUnknown,
	}
}

// GetEntropy gets entropy from the source with health checking.
func (m *MonitoredEntropySource) GetEntropy(size int) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if quarantined
	if time.Now().Before(m.quarantineUntil) {
		return nil, ErrEntropyHealthFailed
	}

	// Get raw entropy
	raw, err := m.source()
	if err != nil {
		return nil, err
	}

	// Feed to health tests
	for _, b := range raw {
		for _, test := range m.tests {
			test.Feed(b)
		}
	}

	// Check health status
	worstStatus := HealthHealthy
	for _, test := range m.tests {
		status := test.Status()
		if status > worstStatus {
			worstStatus = status
		}
	}

	m.lastStatus = worstStatus
	m.lastStatusTime = time.Now()

	if worstStatus == HealthFailed {
		m.failureCount++
		// Quarantine for exponential backoff
		quarantineDuration := time.Second * time.Duration(1<<min(m.failureCount, 10))
		m.quarantineUntil = time.Now().Add(quarantineDuration)
		return nil, ErrEntropyHealthFailed
	}

	atomic.AddUint64(&m.bytesProduced, uint64(len(raw)))

	// Return requested size
	if len(raw) >= size {
		return raw[:size], nil
	}
	return raw, nil
}

func (m *MonitoredEntropySource) Name() string {
	return m.name
}

func (m *MonitoredEntropySource) Status() HealthStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastStatus
}

func (m *MonitoredEntropySource) Stats() EntropySourceStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	testStats := make(map[string]uint64)
	for _, test := range m.tests {
		testStats[test.Name()] = test.FailureCount()
	}

	return EntropySourceStats{
		Name:            m.name,
		BytesProduced:   atomic.LoadUint64(&m.bytesProduced),
		FailureCount:    m.failureCount,
		Status:          m.lastStatus,
		TestFailures:    testStats,
		QuarantineUntil: m.quarantineUntil,
	}
}

// EntropySourceStats contains statistics about an entropy source.
type EntropySourceStats struct {
	Name            string
	BytesProduced   uint64
	FailureCount    uint64
	Status          HealthStatus
	TestFailures    map[string]uint64
	QuarantineUntil time.Time
}

// BlendedEntropyPool combines multiple entropy sources with health monitoring.
//
// Security properties:
// 1. If ANY source is healthy, the output is unpredictable to an attacker
//    who doesn't control ALL sources
// 2. Compromised sources are detected and isolated
// 3. Multiple combination methods prevent single-point attacks
type BlendedEntropyPool struct {
	mu sync.RWMutex

	sources         []*MonitoredEntropySource
	minHealthy      int  // Minimum healthy sources required
	requireTPM      bool
	requirePUF      bool

	// Entropy accumulator
	accumulator     [64]byte
	accumulatorPos  int

	// Statistics
	totalRequests   uint64
	failedRequests  uint64
}

// BlendedEntropyConfig configures the blended entropy pool.
type BlendedEntropyConfig struct {
	MinHealthySources int
	RequireTPM        bool
	RequirePUF        bool
}

// NewBlendedEntropyPool creates a new blended entropy pool.
func NewBlendedEntropyPool(config BlendedEntropyConfig) *BlendedEntropyPool {
	if config.MinHealthySources <= 0 {
		config.MinHealthySources = 2
	}
	return &BlendedEntropyPool{
		sources:    make([]*MonitoredEntropySource, 0),
		minHealthy: config.MinHealthySources,
		requireTPM: config.RequireTPM,
		requirePUF: config.RequirePUF,
	}
}

// AddSource adds an entropy source to the pool.
func (p *BlendedEntropyPool) AddSource(source *MonitoredEntropySource) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sources = append(p.sources, source)
}

// GetEntropy gets blended entropy from all healthy sources.
func (p *BlendedEntropyPool) GetEntropy(size int) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	atomic.AddUint64(&p.totalRequests, 1)

	// Collect entropy from all healthy sources
	var contributions [][]byte
	healthyCount := 0

	for _, source := range p.sources {
		entropy, err := source.GetEntropy(32)
		if err == nil {
			contributions = append(contributions, entropy)
			healthyCount++
		}
	}

	// Check minimum healthy sources
	if healthyCount < p.minHealthy {
		atomic.AddUint64(&p.failedRequests, 1)
		return nil, ErrInsufficientEntropy
	}

	// Blend using multiple methods for defense in depth

	// Method 1: XOR all contributions
	xorBlend := make([]byte, 32)
	for _, contrib := range contributions {
		for i := 0; i < 32 && i < len(contrib); i++ {
			xorBlend[i] ^= contrib[i]
		}
	}

	// Method 2: Hash all contributions together
	hasher := sha256.New()
	hasher.Write([]byte("witnessd-entropy-blend-v1"))
	for _, contrib := range contributions {
		hasher.Write(contrib)
	}
	hashBlend := hasher.Sum(nil)

	// Method 3: Accumulator feedback
	hasher.Reset()
	hasher.Write(p.accumulator[:])
	hasher.Write(xorBlend)
	hasher.Write(hashBlend)
	binary.Write(hasher, binary.BigEndian, time.Now().UnixNano())
	copy(p.accumulator[:], hasher.Sum(nil))

	// Final output: hash of all three methods
	finalHasher := sha256.New()
	finalHasher.Write(xorBlend)
	finalHasher.Write(hashBlend)
	finalHasher.Write(p.accumulator[:])

	result := finalHasher.Sum(nil)

	// Expand if needed
	if size > 32 {
		expanded := make([]byte, size)
		copy(expanded, result)
		for i := 32; i < size; i += 32 {
			hasher.Reset()
			hasher.Write(result)
			binary.Write(hasher, binary.BigEndian, uint64(i))
			result = hasher.Sum(nil)
			copy(expanded[i:], result)
		}
		return expanded[:size], nil
	}

	return result[:size], nil
}

// HealthReport returns health status of all sources.
func (p *BlendedEntropyPool) HealthReport() BlendedEntropyHealth {
	p.mu.RLock()
	defer p.mu.RUnlock()

	report := BlendedEntropyHealth{
		TotalSources:   len(p.sources),
		TotalRequests:  atomic.LoadUint64(&p.totalRequests),
		FailedRequests: atomic.LoadUint64(&p.failedRequests),
		SourceStats:    make([]EntropySourceStats, 0, len(p.sources)),
	}

	for _, source := range p.sources {
		stats := source.Stats()
		report.SourceStats = append(report.SourceStats, stats)
		if stats.Status == HealthHealthy || stats.Status == HealthRecovering {
			report.HealthySources++
		}
	}

	report.OverallHealth = HealthHealthy
	if report.HealthySources < p.minHealthy {
		report.OverallHealth = HealthFailed
	} else if report.HealthySources < len(p.sources) {
		report.OverallHealth = HealthDegraded
	}

	return report
}

// BlendedEntropyHealth is the health report for the blended pool.
type BlendedEntropyHealth struct {
	TotalSources   int
	HealthySources int
	OverallHealth  HealthStatus
	TotalRequests  uint64
	FailedRequests uint64
	SourceStats    []EntropySourceStats
}

// IsHealthy returns whether the blended pool is healthy enough to generate entropy.
func (p *BlendedEntropyPool) IsHealthy() bool {
	report := p.HealthReport()
	return report.OverallHealth != HealthFailed
}

func min(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}
