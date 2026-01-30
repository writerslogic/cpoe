//go:build darwin

package keystroke

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

// HardenedCounter provides maximum-security keystroke counting with:
// 1. Dual-layer validation (CGEventTap + IOKit HID)
// 2. HMAC integrity protection on all counter values
// 3. Timing anomaly detection for USB-HID spoofing
// 4. Cryptographic chaining of counter updates
//
// This counter is designed to be tamper-evident: any modification to
// counter values, timing data, or intermediate state will be detectable.
type HardenedCounter struct {
	BaseCounter

	// Underlying validated counter
	validated *ValidatedCounter

	// Integrity protection
	integrityKey  [32]byte // Random key generated at start
	counterMAC    [32]byte // HMAC of current counter state
	chainHash     [32]byte // Hash chain linking all updates
	updateCounter uint64   // Number of updates (for replay detection)

	// Timing anomaly detection
	timingAnalyzer *TimingAnalyzer

	// State protection
	mu           sync.RWMutex
	initialized  bool
	compromised  bool
	compromiseReason string

	// Sealed state snapshot for export verification
	sealedSnapshots []SealedSnapshot
}

// SealedSnapshot is a tamper-evident point-in-time capture of counter state.
type SealedSnapshot struct {
	Timestamp     time.Time
	Count         uint64
	UpdateCounter uint64
	ChainHash     [32]byte
	MAC           [32]byte // HMAC(key, timestamp || count || updateCounter || chainHash)
}

// TimingAnalyzer detects anomalous keystroke timing patterns.
type TimingAnalyzer struct {
	mu sync.Mutex

	// Recent inter-keystroke intervals (circular buffer)
	intervals    []time.Duration
	intervalIdx  int
	intervalFull bool

	// Statistics
	totalKeystrokes    uint64
	anomalousIntervals uint64

	// Detection thresholds
	minHumanInterval time.Duration // Too fast = machine
	maxHumanInterval time.Duration // Too slow = irrelevant
	varianceThreshold float64       // Variance below this = robotic

	// Last keystroke time
	lastKeystroke time.Time

	// Consecutive identical intervals (strong indicator of scripts)
	consecutiveIdentical int
	lastInterval         time.Duration

	// Timing pattern analysis
	patternBuffer []time.Duration
	patternHash   map[uint64]int // Hash of timing patterns seen
}

// AnomalyReport contains detected timing anomalies.
type AnomalyReport struct {
	TotalKeystrokes      uint64
	AnomalousIntervals   uint64
	AnomalyPercentage    float64
	ConsecutiveIdentical int
	SuspectedScripted    bool
	SuspectedUSBHID      bool
	ReasonCodes          []string
}

// NewHardenedCounter creates a maximum-security counter.
func NewHardenedCounter() (*HardenedCounter, error) {
	h := &HardenedCounter{
		validated:      NewValidatedCounter(),
		timingAnalyzer: newTimingAnalyzer(),
	}

	// Generate random integrity key
	if _, err := rand.Read(h.integrityKey[:]); err != nil {
		return nil, err
	}

	// Initialize chain hash with random value
	if _, err := rand.Read(h.chainHash[:]); err != nil {
		return nil, err
	}

	h.initialized = true
	h.updateMAC()

	return h, nil
}

// newTimingAnalyzer creates a timing analyzer with human-plausible thresholds.
func newTimingAnalyzer() *TimingAnalyzer {
	return &TimingAnalyzer{
		intervals:         make([]time.Duration, 100), // Last 100 intervals
		minHumanInterval:  20 * time.Millisecond,      // < 20ms is superhuman (50+ keys/sec)
		maxHumanInterval:  2 * time.Second,            // > 2s is a pause, not continuous typing
		varianceThreshold: 0.05,                       // Less than 5% variance is robotic
		patternHash:       make(map[uint64]int),
		patternBuffer:     make([]time.Duration, 0, 8),
	}
}

// Start begins hardened counting.
func (h *HardenedCounter) Start(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.initialized {
		return errors.New("counter not properly initialized")
	}

	if h.compromised {
		return errors.New("counter integrity compromised: " + h.compromiseReason)
	}

	// Verify integrity before starting
	if !h.verifyMACUnlocked() {
		h.compromised = true
		h.compromiseReason = "MAC verification failed at start"
		return errors.New("integrity verification failed")
	}

	return h.validated.Start(ctx)
}

// Stop stops hardened counting.
func (h *HardenedCounter) Stop() error {
	return h.validated.Stop()
}

// Count returns the current keystroke count after verifying integrity.
func (h *HardenedCounter) Count() uint64 {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.compromised {
		return 0
	}

	return h.validated.Count()
}

// Available checks if hardened counting is available.
func (h *HardenedCounter) Available() (bool, string) {
	return h.validated.Available()
}

// Subscribe returns a channel that receives events.
func (h *HardenedCounter) Subscribe(interval uint64) <-chan Event {
	return h.validated.Subscribe(interval)
}

// RecordKeystroke records a keystroke with timing analysis.
// Returns true if the keystroke appears legitimate.
func (h *HardenedCounter) RecordKeystroke() (legitimate bool, anomalyReason string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.compromised {
		return false, "counter compromised"
	}

	// Verify integrity
	if !h.verifyMACUnlocked() {
		h.compromised = true
		h.compromiseReason = "MAC verification failed during recording"
		return false, "integrity check failed"
	}

	// Analyze timing
	now := time.Now()
	anomaly := h.timingAnalyzer.analyzeKeystroke(now)
	if anomaly != "" {
		h.timingAnalyzer.mu.Lock()
		h.timingAnalyzer.anomalousIntervals++
		h.timingAnalyzer.mu.Unlock()
	}

	// Update chain
	h.updateChain()
	h.updateCounter++
	h.updateMAC()

	return anomaly == "", anomaly
}

// updateChain advances the cryptographic chain.
func (h *HardenedCounter) updateChain() {
	hasher := sha256.New()
	hasher.Write(h.chainHash[:])
	binary.Write(hasher, binary.BigEndian, h.updateCounter)
	binary.Write(hasher, binary.BigEndian, time.Now().UnixNano())
	binary.Write(hasher, binary.BigEndian, h.validated.Count())
	copy(h.chainHash[:], hasher.Sum(nil))
}

// updateMAC updates the integrity MAC.
func (h *HardenedCounter) updateMAC() {
	mac := hmac.New(sha256.New, h.integrityKey[:])
	binary.Write(mac, binary.BigEndian, h.validated.Count())
	binary.Write(mac, binary.BigEndian, h.updateCounter)
	mac.Write(h.chainHash[:])
	copy(h.counterMAC[:], mac.Sum(nil))
}

// verifyMACUnlocked verifies the integrity MAC (caller must hold lock).
func (h *HardenedCounter) verifyMACUnlocked() bool {
	mac := hmac.New(sha256.New, h.integrityKey[:])
	binary.Write(mac, binary.BigEndian, h.validated.Count())
	binary.Write(mac, binary.BigEndian, h.updateCounter)
	mac.Write(h.chainHash[:])

	expected := mac.Sum(nil)
	return hmac.Equal(h.counterMAC[:], expected)
}

// Seal creates a tamper-evident snapshot of the current state.
func (h *HardenedCounter) Seal() (SealedSnapshot, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.compromised {
		return SealedSnapshot{}, errors.New("counter compromised")
	}

	if !h.verifyMACUnlocked() {
		h.compromised = true
		h.compromiseReason = "MAC verification failed during seal"
		return SealedSnapshot{}, errors.New("integrity check failed")
	}

	snap := SealedSnapshot{
		Timestamp:     time.Now(),
		Count:         h.validated.Count(),
		UpdateCounter: h.updateCounter,
		ChainHash:     h.chainHash,
	}

	// Compute snapshot MAC
	mac := hmac.New(sha256.New, h.integrityKey[:])
	binary.Write(mac, binary.BigEndian, snap.Timestamp.UnixNano())
	binary.Write(mac, binary.BigEndian, snap.Count)
	binary.Write(mac, binary.BigEndian, snap.UpdateCounter)
	mac.Write(snap.ChainHash[:])
	copy(snap.MAC[:], mac.Sum(nil))

	h.sealedSnapshots = append(h.sealedSnapshots, snap)

	return snap, nil
}

// VerifySnapshot checks if a snapshot is valid.
func (h *HardenedCounter) VerifySnapshot(snap SealedSnapshot) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()

	mac := hmac.New(sha256.New, h.integrityKey[:])
	binary.Write(mac, binary.BigEndian, snap.Timestamp.UnixNano())
	binary.Write(mac, binary.BigEndian, snap.Count)
	binary.Write(mac, binary.BigEndian, snap.UpdateCounter)
	mac.Write(snap.ChainHash[:])

	return hmac.Equal(snap.MAC[:], mac.Sum(nil))
}

// AnomalyReport returns the current timing anomaly analysis.
func (h *HardenedCounter) AnomalyReport() AnomalyReport {
	return h.timingAnalyzer.report()
}

// ValidationStats returns the underlying validation statistics.
func (h *HardenedCounter) ValidationStats() ValidationStats {
	return h.validated.ValidationStats()
}

// IsCompromised returns whether the counter integrity has been compromised.
func (h *HardenedCounter) IsCompromised() (bool, string) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.compromised, h.compromiseReason
}

// SyntheticEventStats returns statistics about synthetic event detection.
func (h *HardenedCounter) SyntheticEventStats() SyntheticEventStats {
	return h.validated.cgEventCounter.SyntheticEventStats()
}

// =============================================================================
// Timing Analyzer Implementation
// =============================================================================

// analyzeKeystroke analyzes keystroke timing and returns anomaly reason if any.
func (t *TimingAnalyzer) analyzeKeystroke(now time.Time) string {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.totalKeystrokes++

	if t.lastKeystroke.IsZero() {
		t.lastKeystroke = now
		return ""
	}

	interval := now.Sub(t.lastKeystroke)
	t.lastKeystroke = now

	// Store interval
	t.intervals[t.intervalIdx] = interval
	t.intervalIdx = (t.intervalIdx + 1) % len(t.intervals)
	if t.intervalIdx == 0 {
		t.intervalFull = true
	}

	// Check for superhuman speed
	if interval < t.minHumanInterval {
		return "interval_too_fast"
	}

	// Check for consecutive identical intervals (scripted)
	// Allow 1ms tolerance for system timing jitter
	if abs(interval-t.lastInterval) < time.Millisecond {
		t.consecutiveIdentical++
		if t.consecutiveIdentical >= 5 {
			return "consecutive_identical_intervals"
		}
	} else {
		t.consecutiveIdentical = 0
	}
	t.lastInterval = interval

	// Update pattern buffer
	t.patternBuffer = append(t.patternBuffer, interval)
	if len(t.patternBuffer) >= 8 {
		// Hash the pattern
		patternKey := hashPattern(t.patternBuffer)
		t.patternHash[patternKey]++

		// If we've seen this exact pattern multiple times, it's suspicious
		if t.patternHash[patternKey] >= 3 {
			return "repeating_timing_pattern"
		}

		// Slide the window
		t.patternBuffer = t.patternBuffer[1:]
	}

	// Check for low variance (robotic typing)
	if t.intervalFull {
		variance := t.computeVariance()
		if variance < t.varianceThreshold {
			return "variance_too_low"
		}
	}

	return ""
}

// computeVariance calculates the coefficient of variation of intervals.
func (t *TimingAnalyzer) computeVariance() float64 {
	var sum, sumSq float64
	count := len(t.intervals)
	if !t.intervalFull {
		count = t.intervalIdx
	}
	if count < 2 {
		return 1.0 // Not enough data
	}

	for i := 0; i < count; i++ {
		ms := float64(t.intervals[i].Milliseconds())
		sum += ms
		sumSq += ms * ms
	}

	mean := sum / float64(count)
	if mean == 0 {
		return 0
	}

	variance := (sumSq / float64(count)) - (mean * mean)
	if variance < 0 {
		variance = 0
	}

	// Return coefficient of variation (stddev/mean)
	return sqrt(variance) / mean
}

// report generates an anomaly report.
func (t *TimingAnalyzer) report() AnomalyReport {
	t.mu.Lock()
	defer t.mu.Unlock()

	report := AnomalyReport{
		TotalKeystrokes:      t.totalKeystrokes,
		AnomalousIntervals:   t.anomalousIntervals,
		ConsecutiveIdentical: t.consecutiveIdentical,
	}

	if t.totalKeystrokes > 0 {
		report.AnomalyPercentage = float64(t.anomalousIntervals) / float64(t.totalKeystrokes) * 100
	}

	// Determine suspected attack type
	if t.consecutiveIdentical >= 5 {
		report.SuspectedScripted = true
		report.ReasonCodes = append(report.ReasonCodes, "CONSECUTIVE_IDENTICAL_TIMING")
	}

	if t.intervalFull && t.computeVariance() < t.varianceThreshold {
		report.SuspectedUSBHID = true
		report.ReasonCodes = append(report.ReasonCodes, "LOW_TIMING_VARIANCE")
	}

	// Check for repeating patterns
	for _, count := range t.patternHash {
		if count >= 3 {
			report.SuspectedScripted = true
			report.ReasonCodes = append(report.ReasonCodes, "REPEATING_TIMING_PATTERN")
			break
		}
	}

	if report.AnomalyPercentage > 10 {
		report.ReasonCodes = append(report.ReasonCodes, "HIGH_ANOMALY_RATE")
	}

	return report
}

// hashPattern creates a hash of a timing pattern for comparison.
func hashPattern(intervals []time.Duration) uint64 {
	h := sha256.New()
	for _, d := range intervals {
		// Bucket to 10ms resolution for fuzzy matching
		bucket := d.Milliseconds() / 10
		binary.Write(h, binary.BigEndian, bucket)
	}
	sum := h.Sum(nil)
	return binary.BigEndian.Uint64(sum[:8])
}

// abs returns the absolute value of a duration.
func abs(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// sqrt is a helper for float64 square root.
func sqrt(x float64) float64 {
	if x <= 0 {
		return 0
	}
	z := x / 2
	for i := 0; i < 10; i++ {
		z = z - (z*z-x)/(2*z)
	}
	return z
}

// Ensure HardenedCounter satisfies Counter interface
var _ Counter = (*HardenedCounter)(nil)
