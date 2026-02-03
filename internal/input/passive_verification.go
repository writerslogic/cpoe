//go:build darwin || linux || windows

package input

import (
	"math"
	"sync"
	"time"
)

// PassiveVerification provides continuous authentication WITHOUT interrupting
// the user's workflow. All verification happens invisibly in the background.
//
// Design principles:
// 1. NEVER interrupt the user with prompts or challenges
// 2. Use natural typing patterns as implicit challenges
// 3. Verify during natural pauses (sentence ends, thinking breaks)
// 4. Correlate multiple independent signals
// 5. Assume adversary can intercept any single channel
//
// The key insight: we don't need to ASK the user to do something special.
// Natural human behavior already contains enough entropy and uniqueness
// that we can verify authenticity passively.
type PassiveVerification struct {
	mu sync.RWMutex

	// Natural pattern detection
	commonPatterns    *PatternDetector
	pauseAnalyzer     *PauseAnalyzer
	rhythmMatcher     *RhythmMatcher

	// Cross-signal correlation
	correlator        *SignalCorrelator

	// Verification state
	verificationScore float64
	lastVerification  time.Time
	verificationLog   []VerificationEvent

	// Configuration
	config PassiveConfig
}

// PassiveConfig configures passive verification.
type PassiveConfig struct {
	// How often to recalculate verification score
	VerificationInterval time.Duration

	// Minimum confidence to consider verified
	MinConfidence float64

	// Enable specific passive checks
	EnablePatternMatching bool
	EnablePauseAnalysis   bool
	EnableCrossCorrelation bool
}

// DefaultPassiveConfig returns sensible defaults.
func DefaultPassiveConfig() PassiveConfig {
	return PassiveConfig{
		VerificationInterval:   30 * time.Second,
		MinConfidence:          0.6,
		EnablePatternMatching:  true,
		EnablePauseAnalysis:    true,
		EnableCrossCorrelation: true,
	}
}

// PatternDetector finds naturally-occurring patterns that serve as implicit challenges.
// For example, when a user types "the " or "ing " - common patterns that
// everyone types but with unique timing signatures.
type PatternDetector struct {
	mu sync.RWMutex

	// Known common patterns (these occur naturally in English text)
	// We use these as "implicit challenges" - timing of common patterns is personal
	targetPatterns []string

	// Observed pattern timings
	patternTimings map[string][]PatternTiming

	// User's signature for each pattern
	patternSignatures map[string]*PatternSignature
}

// PatternTiming records timing for a detected pattern.
type PatternTiming struct {
	Timestamp  time.Time
	Intervals  []time.Duration // Time between each character
	TotalTime  time.Duration
}

// PatternSignature is the user's unique timing for a pattern.
type PatternSignature struct {
	Pattern       string
	MeanIntervals []float64 // Mean time for each transition
	StdIntervals  []float64 // Standard deviation
	Samples       int
}

// CommonPatterns are frequently typed sequences that work as implicit challenges.
var CommonPatterns = []string{
	"the ", "and ", "ing ", "ion ", "tion",
	"that", "ent ", "for ", "are ", "was ",
	"you ", "with", "have", "this", "will",
}

// NewPatternDetector creates a pattern detector.
func NewPatternDetector() *PatternDetector {
	return &PatternDetector{
		targetPatterns:    CommonPatterns,
		patternTimings:    make(map[string][]PatternTiming),
		patternSignatures: make(map[string]*PatternSignature),
	}
}

// OnKeySequence checks if recent keys match a target pattern.
func (pd *PatternDetector) OnKeySequence(chars []rune, intervals []time.Duration) {
	pd.mu.Lock()
	defer pd.mu.Unlock()

	// Convert to string
	text := string(chars)

	// Check each target pattern
	for _, pattern := range pd.targetPatterns {
		if len(text) >= len(pattern) {
			// Check if text ends with pattern
			suffix := text[len(text)-len(pattern):]
			if suffix == pattern {
				// Extract intervals for this pattern
				patternLen := len(pattern)
				if len(intervals) >= patternLen-1 {
					patternIntervals := intervals[len(intervals)-(patternLen-1):]

					timing := PatternTiming{
						Timestamp: time.Now(),
						Intervals: patternIntervals,
					}
					for _, d := range patternIntervals {
						timing.TotalTime += d
					}

					pd.recordPattern(pattern, timing)
				}
			}
		}
	}
}

// recordPattern stores a pattern timing and updates signature.
func (pd *PatternDetector) recordPattern(pattern string, timing PatternTiming) {
	// Store timing
	pd.patternTimings[pattern] = append(pd.patternTimings[pattern], timing)

	// Limit history
	if len(pd.patternTimings[pattern]) > 100 {
		pd.patternTimings[pattern] = pd.patternTimings[pattern][50:]
	}

	// Update signature
	pd.updateSignature(pattern)
}

// updateSignature recomputes the signature for a pattern.
func (pd *PatternDetector) updateSignature(pattern string) {
	timings := pd.patternTimings[pattern]
	if len(timings) < 5 {
		return // Need minimum samples
	}

	patternLen := len(pattern)
	sig := &PatternSignature{
		Pattern:       pattern,
		MeanIntervals: make([]float64, patternLen-1),
		StdIntervals:  make([]float64, patternLen-1),
		Samples:       len(timings),
	}

	// Calculate mean and stddev for each transition
	for i := 0; i < patternLen-1; i++ {
		var values []float64
		for _, t := range timings {
			if i < len(t.Intervals) {
				values = append(values, float64(t.Intervals[i].Microseconds()))
			}
		}
		if len(values) > 0 {
			sig.MeanIntervals[i] = mean(values)
			sig.StdIntervals[i] = stddev(values)
		}
	}

	pd.patternSignatures[pattern] = sig
}

// MatchScore returns how well recent typing matches established signatures.
func (pd *PatternDetector) MatchScore() float64 {
	pd.mu.RLock()
	defer pd.mu.RUnlock()

	if len(pd.patternSignatures) == 0 {
		return 0.5 // Neutral if no data
	}

	var scores []float64

	for pattern, sig := range pd.patternSignatures {
		if sig.Samples < 10 {
			continue
		}

		// Get recent timings for this pattern
		timings := pd.patternTimings[pattern]
		if len(timings) < 3 {
			continue
		}

		// Compare last 3 timings to signature
		recentScore := pd.compareToSignature(sig, timings[len(timings)-3:])
		scores = append(scores, recentScore)
	}

	if len(scores) == 0 {
		return 0.5
	}

	return mean(scores)
}

// compareToSignature compares recent timings to established signature.
func (pd *PatternDetector) compareToSignature(sig *PatternSignature, recent []PatternTiming) float64 {
	var deviations []float64

	for _, timing := range recent {
		for i, interval := range timing.Intervals {
			if i >= len(sig.MeanIntervals) {
				break
			}

			// Calculate z-score (how many stddevs from mean)
			if sig.StdIntervals[i] > 0 {
				z := math.Abs(float64(interval.Microseconds())-sig.MeanIntervals[i]) / sig.StdIntervals[i]
				deviations = append(deviations, z)
			}
		}
	}

	if len(deviations) == 0 {
		return 0.5
	}

	// Mean z-score: 0-1 = good match, 1-2 = acceptable, >2 = poor match
	meanZ := mean(deviations)

	// Convert to 0-1 score (lower z = higher score)
	score := math.Exp(-meanZ / 2)
	return score
}

// PauseAnalyzer detects and analyzes natural pauses in typing.
// Pauses reveal cognitive patterns that are hard to fake.
type PauseAnalyzer struct {
	mu sync.RWMutex

	// Pause events
	pauses []PauseEvent

	// Pause profile
	profile PauseProfile
}

// PauseEvent records a detected pause.
type PauseEvent struct {
	Timestamp    time.Time
	Duration     time.Duration
	Type         PauseType
	KeysBefore   int // Keys typed before pause
	CharsAfter   int // First chars typed after pause
}

// PauseType categorizes pauses.
type PauseType int

const (
	PauseTypeWord     PauseType = iota // 200-500ms, between words
	PauseTypeThinking                   // 500-2000ms, cognitive load
	PauseTypeSentence                   // After punctuation
	PauseTypeParagraph                  // Longer, structural
)

// PauseProfile captures the user's pause patterns.
type PauseProfile struct {
	MeanWordPause      float64
	StdWordPause       float64
	MeanThinkPause     float64
	StdThinkPause      float64
	ThinkPauseRatio    float64 // % of pauses that are thinking pauses
	PausesPerMinute    float64
}

// NewPauseAnalyzer creates a pause analyzer.
func NewPauseAnalyzer() *PauseAnalyzer {
	return &PauseAnalyzer{
		pauses: make([]PauseEvent, 0, 500),
	}
}

// OnPause records a detected pause.
func (pa *PauseAnalyzer) OnPause(duration time.Duration, keysBefore int) {
	pa.mu.Lock()
	defer pa.mu.Unlock()

	pauseType := pa.classifyPause(duration)

	event := PauseEvent{
		Timestamp:  time.Now(),
		Duration:   duration,
		Type:       pauseType,
		KeysBefore: keysBefore,
	}

	pa.pauses = append(pa.pauses, event)

	// Limit history
	if len(pa.pauses) > 500 {
		pa.pauses = pa.pauses[250:]
	}

	pa.updateProfile()
}

// classifyPause determines the type of pause.
func (pa *PauseAnalyzer) classifyPause(duration time.Duration) PauseType {
	ms := duration.Milliseconds()

	switch {
	case ms < 500:
		return PauseTypeWord
	case ms < 2000:
		return PauseTypeThinking
	case ms < 5000:
		return PauseTypeSentence
	default:
		return PauseTypeParagraph
	}
}

// updateProfile recalculates the pause profile.
func (pa *PauseAnalyzer) updateProfile() {
	var wordPauses, thinkPauses []float64

	for _, p := range pa.pauses {
		ms := float64(p.Duration.Milliseconds())
		switch p.Type {
		case PauseTypeWord:
			wordPauses = append(wordPauses, ms)
		case PauseTypeThinking:
			thinkPauses = append(thinkPauses, ms)
		}
	}

	if len(wordPauses) > 0 {
		pa.profile.MeanWordPause = mean(wordPauses)
		pa.profile.StdWordPause = stddev(wordPauses)
	}

	if len(thinkPauses) > 0 {
		pa.profile.MeanThinkPause = mean(thinkPauses)
		pa.profile.StdThinkPause = stddev(thinkPauses)
	}

	total := len(wordPauses) + len(thinkPauses)
	if total > 0 {
		pa.profile.ThinkPauseRatio = float64(len(thinkPauses)) / float64(total)
	}
}

// ConsistencyScore returns how consistent recent pauses are with profile.
func (pa *PauseAnalyzer) ConsistencyScore() float64 {
	pa.mu.RLock()
	defer pa.mu.RUnlock()

	if len(pa.pauses) < 20 {
		return 0.5 // Not enough data
	}

	// Compare recent pauses to profile
	recent := pa.pauses[len(pa.pauses)-10:]

	var scores []float64

	for _, p := range recent {
		var expectedMean, expectedStd float64

		switch p.Type {
		case PauseTypeWord:
			expectedMean = pa.profile.MeanWordPause
			expectedStd = pa.profile.StdWordPause
		case PauseTypeThinking:
			expectedMean = pa.profile.MeanThinkPause
			expectedStd = pa.profile.StdThinkPause
		default:
			continue
		}

		if expectedStd > 0 {
			z := math.Abs(float64(p.Duration.Milliseconds())-expectedMean) / expectedStd
			score := math.Exp(-z / 2)
			scores = append(scores, score)
		}
	}

	if len(scores) == 0 {
		return 0.5
	}

	return mean(scores)
}

// SignalCorrelator correlates multiple independent signals to detect spoofing.
// The key insight: an adversary would need to spoof ALL signals consistently,
// which is extremely difficult when signals come from independent sources.
type SignalCorrelator struct {
	mu sync.RWMutex

	// Input signal timeline
	inputSignals []TimestampedSignal

	// Document change timeline
	docSignals []TimestampedSignal

	// Environmental signal timeline
	envSignals []TimestampedSignal

	// Correlation scores
	inputDocCorrelation float64
	inputEnvCorrelation float64
}

// TimestampedSignal is a signal with timestamp.
type TimestampedSignal struct {
	Timestamp time.Time
	Type      string
	Value     float64
	Hash      [32]byte // For content verification
}

// NewSignalCorrelator creates a signal correlator.
func NewSignalCorrelator() *SignalCorrelator {
	return &SignalCorrelator{
		inputSignals: make([]TimestampedSignal, 0, 1000),
		docSignals:   make([]TimestampedSignal, 0, 1000),
		envSignals:   make([]TimestampedSignal, 0, 1000),
	}
}

// RecordInput records an input signal.
func (sc *SignalCorrelator) RecordInput(signalType string, value float64) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	sc.inputSignals = append(sc.inputSignals, TimestampedSignal{
		Timestamp: time.Now(),
		Type:      signalType,
		Value:     value,
	})

	sc.trimAndCorrelate()
}

// RecordDocChange records a document change signal.
func (sc *SignalCorrelator) RecordDocChange(charsDelta int, contentHash [32]byte) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	sc.docSignals = append(sc.docSignals, TimestampedSignal{
		Timestamp: time.Now(),
		Type:      "doc_change",
		Value:     float64(charsDelta),
		Hash:      contentHash,
	})

	sc.trimAndCorrelate()
}

// RecordEnvironment records an environmental signal.
func (sc *SignalCorrelator) RecordEnvironment(signalType string, value float64) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	sc.envSignals = append(sc.envSignals, TimestampedSignal{
		Timestamp: time.Now(),
		Type:      signalType,
		Value:     value,
	})

	sc.trimAndCorrelate()
}

// trimAndCorrelate limits history and updates correlation scores.
func (sc *SignalCorrelator) trimAndCorrelate() {
	// Trim to last 1000
	if len(sc.inputSignals) > 1000 {
		sc.inputSignals = sc.inputSignals[500:]
	}
	if len(sc.docSignals) > 1000 {
		sc.docSignals = sc.docSignals[500:]
	}
	if len(sc.envSignals) > 1000 {
		sc.envSignals = sc.envSignals[500:]
	}

	// Update correlations
	sc.inputDocCorrelation = sc.computeCorrelation(sc.inputSignals, sc.docSignals)
	sc.inputEnvCorrelation = sc.computeCorrelation(sc.inputSignals, sc.envSignals)
}

// computeCorrelation calculates correlation between two signal streams.
func (sc *SignalCorrelator) computeCorrelation(a, b []TimestampedSignal) float64 {
	if len(a) < 10 || len(b) < 10 {
		return 0.5 // Not enough data
	}

	// Count how many 'a' events have a corresponding 'b' event within 1 second
	matches := 0
	for _, sigA := range a {
		for _, sigB := range b {
			diff := sigA.Timestamp.Sub(sigB.Timestamp)
			if diff < 0 {
				diff = -diff
			}
			if diff < time.Second {
				matches++
				break
			}
		}
	}

	return float64(matches) / float64(len(a))
}

// CorrelationScore returns the overall correlation score.
func (sc *SignalCorrelator) CorrelationScore() float64 {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	// Input-document correlation is most important
	// (typing should cause document changes)
	return sc.inputDocCorrelation
}

// VerificationEvent records a passive verification check.
type VerificationEvent struct {
	Timestamp         time.Time
	PatternScore      float64
	PauseScore        float64
	CorrelationScore  float64
	OverallScore      float64
	Passed            bool
}

// NewPassiveVerification creates a passive verification system.
func NewPassiveVerification(config PassiveConfig) *PassiveVerification {
	return &PassiveVerification{
		commonPatterns:   NewPatternDetector(),
		pauseAnalyzer:    NewPauseAnalyzer(),
		rhythmMatcher:    NewRhythmMatcher(),
		correlator:       NewSignalCorrelator(),
		verificationLog:  make([]VerificationEvent, 0, 100),
		config:           config,
	}
}

// OnKeystroke processes a keystroke for passive verification.
func (pv *PassiveVerification) OnKeystroke(char rune, interval time.Duration, chars []rune, intervals []time.Duration) {
	pv.mu.Lock()
	defer pv.mu.Unlock()

	// Pattern detection
	if pv.config.EnablePatternMatching {
		pv.commonPatterns.OnKeySequence(chars, intervals)
	}

	// Pause detection (if interval is long enough)
	if pv.config.EnablePauseAnalysis && interval > 200*time.Millisecond {
		pv.pauseAnalyzer.OnPause(interval, len(chars))
	}

	// Rhythm matching
	pv.rhythmMatcher.OnKeystroke(char, interval)

	// Record input signal for correlation
	if pv.config.EnableCrossCorrelation {
		pv.correlator.RecordInput("keystroke", float64(interval.Milliseconds()))
	}

	// Periodic verification check
	if time.Since(pv.lastVerification) > pv.config.VerificationInterval {
		pv.performVerification()
	}
}

// OnDocumentChange records a document change for correlation.
func (pv *PassiveVerification) OnDocumentChange(charsDelta int, contentHash [32]byte) {
	pv.mu.Lock()
	defer pv.mu.Unlock()

	if pv.config.EnableCrossCorrelation {
		pv.correlator.RecordDocChange(charsDelta, contentHash)
	}
}

// performVerification runs a passive verification check.
func (pv *PassiveVerification) performVerification() {
	event := VerificationEvent{
		Timestamp: time.Now(),
	}

	var scores []float64

	// Pattern matching score
	if pv.config.EnablePatternMatching {
		event.PatternScore = pv.commonPatterns.MatchScore()
		scores = append(scores, event.PatternScore)
	}

	// Pause analysis score
	if pv.config.EnablePauseAnalysis {
		event.PauseScore = pv.pauseAnalyzer.ConsistencyScore()
		scores = append(scores, event.PauseScore)
	}

	// Cross-correlation score
	if pv.config.EnableCrossCorrelation {
		event.CorrelationScore = pv.correlator.CorrelationScore()
		scores = append(scores, event.CorrelationScore)
	}

	// Overall score
	if len(scores) > 0 {
		event.OverallScore = mean(scores)
	} else {
		event.OverallScore = 0.5
	}

	event.Passed = event.OverallScore >= pv.config.MinConfidence

	pv.verificationScore = event.OverallScore
	pv.lastVerification = time.Now()
	pv.verificationLog = append(pv.verificationLog, event)

	// Limit log size
	if len(pv.verificationLog) > 100 {
		pv.verificationLog = pv.verificationLog[50:]
	}
}

// Score returns the current verification score.
func (pv *PassiveVerification) Score() float64 {
	pv.mu.RLock()
	defer pv.mu.RUnlock()
	return pv.verificationScore
}

// IsVerified returns true if currently verified.
func (pv *PassiveVerification) IsVerified() bool {
	pv.mu.RLock()
	defer pv.mu.RUnlock()
	return pv.verificationScore >= pv.config.MinConfidence
}

// RhythmMatcher tracks typing rhythm for consistency.
type RhythmMatcher struct {
	mu sync.RWMutex

	// Recent intervals
	intervals []time.Duration

	// Rhythm profile
	meanInterval float64
	stdInterval  float64
}

// NewRhythmMatcher creates a rhythm matcher.
func NewRhythmMatcher() *RhythmMatcher {
	return &RhythmMatcher{
		intervals: make([]time.Duration, 0, 1000),
	}
}

// OnKeystroke records a keystroke interval.
func (rm *RhythmMatcher) OnKeystroke(char rune, interval time.Duration) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	// Only record reasonable intervals
	if interval > 10*time.Millisecond && interval < 2*time.Second {
		rm.intervals = append(rm.intervals, interval)

		// Limit size
		if len(rm.intervals) > 1000 {
			rm.intervals = rm.intervals[500:]
		}

		// Update profile
		rm.updateProfile()
	}
}

// updateProfile recalculates rhythm profile.
func (rm *RhythmMatcher) updateProfile() {
	if len(rm.intervals) < 20 {
		return
	}

	var values []float64
	for _, d := range rm.intervals {
		values = append(values, float64(d.Milliseconds()))
	}

	rm.meanInterval = mean(values)
	rm.stdInterval = stddev(values)
}

// ConsistencyScore returns how consistent the rhythm is.
func (rm *RhythmMatcher) ConsistencyScore() float64 {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	if rm.meanInterval == 0 {
		return 0.5
	}

	// Coefficient of variation
	cv := rm.stdInterval / rm.meanInterval

	// Human CV is typically 0.3-0.6
	// Too low (<0.1) = robotic
	// Too high (>1.0) = erratic

	if cv < 0.1 {
		return 0.3 // Suspiciously consistent
	}
	if cv > 1.0 {
		return 0.4 // Very erratic
	}

	// Sweet spot around 0.3-0.5
	return 0.6 + 0.4*math.Exp(-math.Pow(cv-0.4, 2)/0.1)
}
