//go:build darwin || linux || windows

package input

import (
	"crypto/sha256"
	"encoding/binary"
	"math"
	"sync"
	"time"
)

// KeyboardBiometrics provides advanced keystroke dynamics analysis.
// This extracts biometric identity from typing patterns - a well-studied
// field that can achieve >95% accuracy in user identification.
//
// Signals captured:
// - Spatial: Key positions, flight distances, hand patterns
// - Temporal: Dwell time, flight time, digraph/trigraph timing
// - Pressure proxy: Hold duration correlates with intended emphasis
// - Biometric: Personal rhythm signature, error patterns
// - Liveness: Micro-variations, fatigue detection, cognitive load
type KeyboardBiometrics struct {
	mu sync.RWMutex

	// Raw keystroke data
	keyEvents   []KeyEvent
	maxEvents   int

	// Digraph timing (time between consecutive key pairs)
	digraphs    map[string]*DigraphStats

	// Trigraph timing (three-key sequences)
	trigraphs   map[string]*TrigraphStats

	// Dwell times (how long each key is held)
	dwellTimes  map[uint16][]time.Duration

	// Flight times (time from key-up to next key-down)
	flightTimes []time.Duration

	// Spatial analysis
	handPattern []HandSide // Track left/right hand usage
	rowPattern  []KeyRow   // Track row usage (number, top, home, bottom)

	// Error tracking
	errorSequences []ErrorSequence

	// Session statistics
	sessionStart time.Time
	totalKeys    uint64

	// Computed profile
	profile KeyboardProfile
}

// KeyEvent represents a keyboard event with full metadata.
type KeyEvent struct {
	Timestamp  time.Time     `json:"timestamp"`
	KeyCode    uint16        `json:"key_code"`
	IsKeyDown  bool          `json:"is_key_down"`
	Character  rune          `json:"character,omitempty"`
	Position   KeyPosition   `json:"position"`
	HandSide   HandSide      `json:"hand_side"`
	Row        KeyRow        `json:"row"`
	Finger     FingerID      `json:"finger"`
}

// KeyPosition represents the physical position of a key.
type KeyPosition struct {
	X float64 `json:"x"` // 0.0 (left) to 1.0 (right)
	Y float64 `json:"y"` // 0.0 (top) to 1.0 (bottom)
}

// HandSide indicates which hand typically presses a key.
type HandSide int

const (
	HandUnknown HandSide = iota
	HandLeft
	HandRight
)

// KeyRow indicates the keyboard row.
type KeyRow int

const (
	RowUnknown KeyRow = iota
	RowNumber      // 1234567890
	RowTop         // QWERTYUIOP
	RowHome        // ASDFGHJKL
	RowBottom      // ZXCVBNM
	RowSpace       // Spacebar, modifiers
)

// FingerID identifies which finger typically presses a key.
type FingerID int

const (
	FingerUnknown FingerID = iota
	FingerLeftPinky
	FingerLeftRing
	FingerLeftMiddle
	FingerLeftIndex
	FingerLeftThumb
	FingerRightThumb
	FingerRightIndex
	FingerRightMiddle
	FingerRightRing
	FingerRightPinky
)

// DigraphStats tracks timing for a two-key sequence.
type DigraphStats struct {
	Count    int
	Times    []time.Duration
	Mean     float64
	StdDev   float64
}

// TrigraphStats tracks timing for a three-key sequence.
type TrigraphStats struct {
	Count    int
	Times    []time.Duration
	Mean     float64
	StdDev   float64
}

// ErrorSequence records a typing error (backspace after keys).
type ErrorSequence struct {
	Timestamp    time.Time
	KeysBefore   []uint16 // Keys typed before backspace
	BackspaceCount int
}

// KeyboardProfile is the computed biometric profile.
type KeyboardProfile struct {
	// Timing characteristics
	MeanDwellTime      float64 `json:"mean_dwell_time_ms"`
	StdDevDwellTime    float64 `json:"stddev_dwell_time_ms"`
	MeanFlightTime     float64 `json:"mean_flight_time_ms"`
	StdDevFlightTime   float64 `json:"stddev_flight_time_ms"`

	// Rhythm signature (key timing pattern)
	RhythmSignature    [16]float64 `json:"rhythm_signature"` // 16-bin histogram

	// Spatial patterns
	LeftHandRatio      float64 `json:"left_hand_ratio"`    // % left hand keys
	HomeRowRatio       float64 `json:"home_row_ratio"`     // % home row usage
	MeanFlightDistance float64 `json:"mean_flight_distance"` // Average physical distance

	// Digraph signature (top 20 digraph timings normalized)
	DigraphSignature   [20]float64 `json:"digraph_signature"`

	// "Pressure" proxy from dwell time
	EmphasisScore      float64 `json:"emphasis_score"` // Variation in dwell = intentional emphasis

	// Error patterns
	ErrorRate          float64 `json:"error_rate"`      // Errors per 100 keys
	CommonErrorKeys    []uint16 `json:"common_error_keys"` // Keys often followed by backspace

	// Liveness indicators
	MicroVariation     float64 `json:"micro_variation"`  // Tiny timing variations (anti-replay)
	FatigueSlope       float64 `json:"fatigue_slope"`    // Speed change over session
	CognitiveLoadSpikes int    `json:"cognitive_load_spikes"` // Unusual pauses

	// Overall metrics
	TotalKeystrokes    uint64  `json:"total_keystrokes"`
	SessionDuration    time.Duration `json:"session_duration"`
	KeysPerMinute      float64 `json:"keys_per_minute"`

	// Biometric confidence
	IdentityConfidence float64 `json:"identity_confidence"` // 0-1, how unique is this profile
	LivenessConfidence float64 `json:"liveness_confidence"` // 0-1, how likely this is live

	// Integrity
	ProfileHash        [32]byte `json:"profile_hash"`
}

// NewKeyboardBiometrics creates a keyboard biometrics analyzer.
func NewKeyboardBiometrics() *KeyboardBiometrics {
	return &KeyboardBiometrics{
		keyEvents:    make([]KeyEvent, 0, 5000),
		maxEvents:    5000,
		digraphs:     make(map[string]*DigraphStats),
		trigraphs:    make(map[string]*TrigraphStats),
		dwellTimes:   make(map[uint16][]time.Duration),
		flightTimes:  make([]time.Duration, 0, 2000),
		handPattern:  make([]HandSide, 0, 2000),
		rowPattern:   make([]KeyRow, 0, 2000),
		sessionStart: time.Now(),
	}
}

// RecordKeyDown records a key press event.
func (kb *KeyboardBiometrics) RecordKeyDown(keyCode uint16, timestamp time.Time) {
	kb.mu.Lock()
	defer kb.mu.Unlock()

	event := KeyEvent{
		Timestamp: timestamp,
		KeyCode:   keyCode,
		IsKeyDown: true,
		Position:  getKeyPosition(keyCode),
		HandSide:  getHandSide(keyCode),
		Row:       getKeyRow(keyCode),
		Finger:    getFinger(keyCode),
	}

	kb.recordEvent(event)
	kb.totalKeys++

	// Track hand and row patterns
	kb.handPattern = append(kb.handPattern, event.HandSide)
	kb.rowPattern = append(kb.rowPattern, event.Row)

	// Calculate flight time from previous key-up
	for i := len(kb.keyEvents) - 2; i >= 0; i-- {
		if !kb.keyEvents[i].IsKeyDown {
			flightTime := timestamp.Sub(kb.keyEvents[i].Timestamp)
			if flightTime > 0 && flightTime < 2*time.Second {
				kb.flightTimes = append(kb.flightTimes, flightTime)
			}
			break
		}
	}

	// Update digraph timing
	kb.updateDigraphs(keyCode, timestamp)

	// Check for error patterns (backspace)
	if keyCode == 51 || keyCode == 0x2A || keyCode == 14 { // Various backspace codes
		kb.recordError(timestamp)
	}

	kb.trimArrays()
}

// RecordKeyUp records a key release event.
func (kb *KeyboardBiometrics) RecordKeyUp(keyCode uint16, timestamp time.Time) {
	kb.mu.Lock()
	defer kb.mu.Unlock()

	event := KeyEvent{
		Timestamp: timestamp,
		KeyCode:   keyCode,
		IsKeyDown: false,
		Position:  getKeyPosition(keyCode),
	}

	kb.recordEvent(event)

	// Calculate dwell time
	for i := len(kb.keyEvents) - 2; i >= 0; i-- {
		if kb.keyEvents[i].KeyCode == keyCode && kb.keyEvents[i].IsKeyDown {
			dwellTime := timestamp.Sub(kb.keyEvents[i].Timestamp)
			if dwellTime > 0 && dwellTime < 2*time.Second {
				kb.dwellTimes[keyCode] = append(kb.dwellTimes[keyCode], dwellTime)
				// Limit per-key history
				if len(kb.dwellTimes[keyCode]) > 100 {
					kb.dwellTimes[keyCode] = kb.dwellTimes[keyCode][50:]
				}
			}
			break
		}
	}
}

// recordEvent adds an event to the buffer.
func (kb *KeyboardBiometrics) recordEvent(event KeyEvent) {
	if len(kb.keyEvents) >= kb.maxEvents {
		kb.keyEvents = kb.keyEvents[kb.maxEvents/2:]
	}
	kb.keyEvents = append(kb.keyEvents, event)
}

// updateDigraphs updates digraph timing statistics.
func (kb *KeyboardBiometrics) updateDigraphs(keyCode uint16, timestamp time.Time) {
	// Find previous key-down
	var prevKey uint16
	var prevTime time.Time
	for i := len(kb.keyEvents) - 2; i >= 0; i-- {
		if kb.keyEvents[i].IsKeyDown {
			prevKey = kb.keyEvents[i].KeyCode
			prevTime = kb.keyEvents[i].Timestamp
			break
		}
	}

	if prevTime.IsZero() {
		return
	}

	// Create digraph key
	digraphKey := string([]byte{byte(prevKey >> 8), byte(prevKey), byte(keyCode >> 8), byte(keyCode)})
	interval := timestamp.Sub(prevTime)

	if interval > 0 && interval < 2*time.Second {
		if kb.digraphs[digraphKey] == nil {
			kb.digraphs[digraphKey] = &DigraphStats{
				Times: make([]time.Duration, 0, 50),
			}
		}
		stats := kb.digraphs[digraphKey]
		stats.Times = append(stats.Times, interval)
		stats.Count++

		// Limit history
		if len(stats.Times) > 50 {
			stats.Times = stats.Times[25:]
		}

		// Update mean
		stats.Mean = meanDuration(stats.Times)
		stats.StdDev = stddevDuration(stats.Times)
	}
}

// recordError records an error sequence (backspace pressed).
func (kb *KeyboardBiometrics) recordError(timestamp time.Time) {
	// Look back for recent key presses
	var keysBefore []uint16
	for i := len(kb.keyEvents) - 2; i >= 0 && len(keysBefore) < 5; i-- {
		if kb.keyEvents[i].IsKeyDown {
			keysBefore = append(keysBefore, kb.keyEvents[i].KeyCode)
		}
	}

	kb.errorSequences = append(kb.errorSequences, ErrorSequence{
		Timestamp:      timestamp,
		KeysBefore:     keysBefore,
		BackspaceCount: 1,
	})

	// Limit error history
	if len(kb.errorSequences) > 200 {
		kb.errorSequences = kb.errorSequences[100:]
	}
}

// trimArrays limits array sizes.
func (kb *KeyboardBiometrics) trimArrays() {
	if len(kb.flightTimes) > 2000 {
		kb.flightTimes = kb.flightTimes[1000:]
	}
	if len(kb.handPattern) > 2000 {
		kb.handPattern = kb.handPattern[1000:]
	}
	if len(kb.rowPattern) > 2000 {
		kb.rowPattern = kb.rowPattern[1000:]
	}
}

// Profile computes the current biometric profile.
func (kb *KeyboardBiometrics) Profile() KeyboardProfile {
	kb.mu.RLock()
	defer kb.mu.RUnlock()

	profile := KeyboardProfile{
		TotalKeystrokes: kb.totalKeys,
		SessionDuration: time.Since(kb.sessionStart),
	}

	// Calculate KPM
	if profile.SessionDuration.Minutes() > 0 {
		profile.KeysPerMinute = float64(kb.totalKeys) / profile.SessionDuration.Minutes()
	}

	// Dwell time statistics
	var allDwells []time.Duration
	for _, dwells := range kb.dwellTimes {
		allDwells = append(allDwells, dwells...)
	}
	if len(allDwells) > 0 {
		profile.MeanDwellTime = meanDuration(allDwells)
		profile.StdDevDwellTime = stddevDuration(allDwells)
	}

	// Flight time statistics
	if len(kb.flightTimes) > 0 {
		profile.MeanFlightTime = meanDuration(kb.flightTimes)
		profile.StdDevFlightTime = stddevDuration(kb.flightTimes)
	}

	// Rhythm signature (histogram of flight times)
	profile.RhythmSignature = kb.computeRhythmSignature()

	// Spatial patterns
	profile.LeftHandRatio = kb.computeLeftHandRatio()
	profile.HomeRowRatio = kb.computeHomeRowRatio()
	profile.MeanFlightDistance = kb.computeMeanFlightDistance()

	// Digraph signature
	profile.DigraphSignature = kb.computeDigraphSignature()

	// Emphasis score (dwell time variation = intentional emphasis)
	profile.EmphasisScore = kb.computeEmphasisScore()

	// Error patterns
	profile.ErrorRate = kb.computeErrorRate()
	profile.CommonErrorKeys = kb.findCommonErrorKeys()

	// Liveness indicators
	profile.MicroVariation = kb.computeMicroVariation()
	profile.FatigueSlope = kb.computeFatigueSlope()
	profile.CognitiveLoadSpikes = kb.countCognitiveLoadSpikes()

	// Confidence scores
	profile.IdentityConfidence = kb.computeIdentityConfidence(profile)
	profile.LivenessConfidence = kb.computeLivenessConfidence(profile)

	// Hash
	profile.ProfileHash = kb.hashProfile(profile)

	return profile
}

// computeRhythmSignature creates a 16-bin histogram of flight times.
func (kb *KeyboardBiometrics) computeRhythmSignature() [16]float64 {
	var sig [16]float64
	if len(kb.flightTimes) == 0 {
		return sig
	}

	// Bins: 0-50ms, 50-100ms, 100-150ms, ... 700-750ms, 750+ms
	for _, ft := range kb.flightTimes {
		bin := int(ft.Milliseconds() / 50)
		if bin >= 16 {
			bin = 15
		}
		if bin < 0 {
			bin = 0
		}
		sig[bin]++
	}

	// Normalize
	total := float64(len(kb.flightTimes))
	for i := range sig {
		sig[i] /= total
	}

	return sig
}

// computeLeftHandRatio calculates percentage of left-hand keys.
func (kb *KeyboardBiometrics) computeLeftHandRatio() float64 {
	if len(kb.handPattern) == 0 {
		return 0.5
	}

	leftCount := 0
	for _, hand := range kb.handPattern {
		if hand == HandLeft {
			leftCount++
		}
	}

	return float64(leftCount) / float64(len(kb.handPattern))
}

// computeHomeRowRatio calculates percentage of home row keys.
func (kb *KeyboardBiometrics) computeHomeRowRatio() float64 {
	if len(kb.rowPattern) == 0 {
		return 0.25
	}

	homeCount := 0
	for _, row := range kb.rowPattern {
		if row == RowHome {
			homeCount++
		}
	}

	return float64(homeCount) / float64(len(kb.rowPattern))
}

// computeMeanFlightDistance calculates average physical distance between consecutive keys.
func (kb *KeyboardBiometrics) computeMeanFlightDistance() float64 {
	var distances []float64

	for i := 1; i < len(kb.keyEvents); i++ {
		if kb.keyEvents[i].IsKeyDown && kb.keyEvents[i-1].IsKeyDown {
			pos1 := kb.keyEvents[i-1].Position
			pos2 := kb.keyEvents[i].Position
			dist := math.Sqrt(math.Pow(pos2.X-pos1.X, 2) + math.Pow(pos2.Y-pos1.Y, 2))
			distances = append(distances, dist)
		}
	}

	if len(distances) == 0 {
		return 0
	}

	return mean(distances)
}

// computeDigraphSignature creates a normalized signature from top digraphs.
func (kb *KeyboardBiometrics) computeDigraphSignature() [20]float64 {
	var sig [20]float64

	// Get top 20 digraphs by count
	type digraphEntry struct {
		key  string
		mean float64
	}

	var entries []digraphEntry
	for key, stats := range kb.digraphs {
		if stats.Count >= 3 { // Need at least 3 samples
			entries = append(entries, digraphEntry{key, stats.Mean})
		}
	}

	// Sort by frequency (we use the key as proxy since common digraphs will have more samples)
	// Just take first 20 for simplicity
	for i := 0; i < len(entries) && i < 20; i++ {
		sig[i] = entries[i].mean
	}

	// Normalize to 0-1 range
	maxVal := 0.0
	for _, v := range sig {
		if v > maxVal {
			maxVal = v
		}
	}
	if maxVal > 0 {
		for i := range sig {
			sig[i] /= maxVal
		}
	}

	return sig
}

// computeEmphasisScore measures intentional variation in key hold times.
func (kb *KeyboardBiometrics) computeEmphasisScore() float64 {
	// Higher variation in dwell times suggests intentional emphasis
	var allDwells []time.Duration
	for _, dwells := range kb.dwellTimes {
		allDwells = append(allDwells, dwells...)
	}

	if len(allDwells) < 10 {
		return 0
	}

	meanD := meanDuration(allDwells)
	stdD := stddevDuration(allDwells)

	if meanD == 0 {
		return 0
	}

	// Coefficient of variation
	cv := stdD / meanD

	// Normalize to 0-1 (CV of 0.3-0.5 is typical for humans)
	return math.Min(cv/0.5, 1.0)
}

// computeErrorRate calculates errors per 100 keystrokes.
func (kb *KeyboardBiometrics) computeErrorRate() float64 {
	if kb.totalKeys == 0 {
		return 0
	}
	return float64(len(kb.errorSequences)) / float64(kb.totalKeys) * 100
}

// findCommonErrorKeys finds keys that commonly precede backspaces.
func (kb *KeyboardBiometrics) findCommonErrorKeys() []uint16 {
	counts := make(map[uint16]int)

	for _, err := range kb.errorSequences {
		if len(err.KeysBefore) > 0 {
			counts[err.KeysBefore[0]]++
		}
	}

	// Find top 5
	var keys []uint16
	for key, count := range counts {
		if count >= 3 {
			keys = append(keys, key)
		}
	}

	return keys
}

// computeMicroVariation measures tiny timing variations (anti-replay).
func (kb *KeyboardBiometrics) computeMicroVariation() float64 {
	if len(kb.flightTimes) < 10 {
		return 0
	}

	// Calculate differences between consecutive flight times
	var diffs []float64
	for i := 1; i < len(kb.flightTimes); i++ {
		diff := math.Abs(float64(kb.flightTimes[i]-kb.flightTimes[i-1])) / float64(time.Millisecond)
		diffs = append(diffs, diff)
	}

	// Humans have micro-variations; replays are too consistent
	meanDiff := mean(diffs)

	// Normalize: 5-20ms variation is typical for humans
	if meanDiff < 1 {
		return 0 // Suspiciously consistent (replay?)
	}
	if meanDiff > 50 {
		return 1 // Very variable (human)
	}

	return meanDiff / 20
}

// computeFatigueSlope measures speed change over session (humans slow down).
func (kb *KeyboardBiometrics) computeFatigueSlope() float64 {
	if len(kb.flightTimes) < 100 {
		return 0
	}

	// Compare first quarter to last quarter
	quarter := len(kb.flightTimes) / 4
	firstQuarter := kb.flightTimes[:quarter]
	lastQuarter := kb.flightTimes[len(kb.flightTimes)-quarter:]

	firstMean := meanDuration(firstQuarter)
	lastMean := meanDuration(lastQuarter)

	if firstMean == 0 {
		return 0
	}

	// Positive slope = slowing down (human), negative = speeding up
	return (lastMean - firstMean) / firstMean
}

// countCognitiveLoadSpikes counts unusually long pauses (thinking).
func (kb *KeyboardBiometrics) countCognitiveLoadSpikes() int {
	if len(kb.flightTimes) < 20 {
		return 0
	}

	meanFlight := meanDuration(kb.flightTimes)
	threshold := meanFlight * 3 // 3x mean = cognitive load

	count := 0
	for _, ft := range kb.flightTimes {
		if float64(ft) > threshold {
			count++
		}
	}

	return count
}

// computeIdentityConfidence estimates how unique/identifying this profile is.
func (kb *KeyboardBiometrics) computeIdentityConfidence(profile KeyboardProfile) float64 {
	score := 0.0

	// More data = higher confidence
	if kb.totalKeys > 100 {
		score += 0.2
	}
	if kb.totalKeys > 500 {
		score += 0.1
	}
	if kb.totalKeys > 1000 {
		score += 0.1
	}

	// Consistent rhythm = identifiable
	if profile.StdDevFlightTime > 0 && profile.MeanFlightTime > 0 {
		cv := profile.StdDevFlightTime / profile.MeanFlightTime
		if cv > 0.2 && cv < 0.6 { // Human-like variation
			score += 0.2
		}
	}

	// Distinctive digraph patterns
	nonZeroDigraphs := 0
	for _, v := range profile.DigraphSignature {
		if v > 0 {
			nonZeroDigraphs++
		}
	}
	score += float64(nonZeroDigraphs) / 40 // Max 0.5 from digraphs

	return math.Min(score, 1.0)
}

// computeLivenessConfidence estimates likelihood this is live human input.
func (kb *KeyboardBiometrics) computeLivenessConfidence(profile KeyboardProfile) float64 {
	score := 0.5 // Base

	// Micro-variations indicate human
	if profile.MicroVariation > 0.3 {
		score += 0.15
	}

	// Fatigue indicates human (robots don't get tired)
	if profile.FatigueSlope > 0.05 { // Slowing down
		score += 0.1
	}

	// Cognitive load spikes indicate thinking
	if profile.CognitiveLoadSpikes > 5 {
		score += 0.1
	}

	// Error rate in human range (1-5%)
	if profile.ErrorRate > 0.5 && profile.ErrorRate < 10 {
		score += 0.1
	}

	// Emphasis variation (intentional holding)
	if profile.EmphasisScore > 0.3 {
		score += 0.05
	}

	return math.Min(score, 1.0)
}

// hashProfile creates integrity hash.
func (kb *KeyboardBiometrics) hashProfile(profile KeyboardProfile) [32]byte {
	h := sha256.New()
	h.Write([]byte("witnessd-keyboard-profile-v1"))

	binary.Write(h, binary.BigEndian, profile.MeanDwellTime)
	binary.Write(h, binary.BigEndian, profile.MeanFlightTime)
	binary.Write(h, binary.BigEndian, profile.TotalKeystrokes)

	for _, v := range profile.RhythmSignature {
		binary.Write(h, binary.BigEndian, v)
	}

	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// IsHumanPlausible checks if profile appears human.
func (profile KeyboardProfile) IsHumanPlausible() bool {
	if profile.TotalKeystrokes < 50 {
		return true // Not enough data
	}

	// Human typing speed: 20-120 WPM = ~100-600 KPM
	if profile.KeysPerMinute > 0 {
		if profile.KeysPerMinute < 10 || profile.KeysPerMinute > 800 {
			return false
		}
	}

	// Micro-variation check
	if profile.MicroVariation < 0.1 {
		return false // Too consistent = replay/robot
	}

	// Liveness confidence
	if profile.LivenessConfidence < 0.3 {
		return false
	}

	return true
}

// Key mapping functions (simplified QWERTY layout)

func getKeyPosition(keyCode uint16) KeyPosition {
	// Simplified mapping - actual implementation would be more comprehensive
	positions := map[uint16]KeyPosition{
		// Number row
		18: {0.0, 0.0}, 19: {0.1, 0.0}, 20: {0.2, 0.0}, 21: {0.3, 0.0},
		// QWERTY row
		12: {0.05, 0.25}, 13: {0.15, 0.25}, 14: {0.25, 0.25}, 15: {0.35, 0.25},
		// ASDF row
		0: {0.08, 0.5}, 1: {0.18, 0.5}, 2: {0.28, 0.5}, 3: {0.38, 0.5},
		// ZXCV row
		6: {0.12, 0.75}, 7: {0.22, 0.75}, 8: {0.32, 0.75}, 9: {0.42, 0.75},
	}

	if pos, ok := positions[keyCode]; ok {
		return pos
	}
	return KeyPosition{0.5, 0.5} // Default center
}

func getHandSide(keyCode uint16) HandSide {
	// Left hand keys (QWERTY layout)
	leftKeys := map[uint16]bool{
		12: true, 13: true, 14: true, 15: true, 17: true, // Q W E R T
		0: true, 1: true, 2: true, 3: true, 5: true,       // A S D F G
		6: true, 7: true, 8: true, 9: true, 11: true,      // Z X C V B
	}

	if leftKeys[keyCode] {
		return HandLeft
	}
	return HandRight
}

func getKeyRow(keyCode uint16) KeyRow {
	numberRow := map[uint16]bool{18: true, 19: true, 20: true, 21: true, 23: true, 22: true, 26: true, 28: true, 25: true, 29: true}
	topRow := map[uint16]bool{12: true, 13: true, 14: true, 15: true, 17: true, 16: true, 32: true, 34: true, 31: true, 35: true}
	homeRow := map[uint16]bool{0: true, 1: true, 2: true, 3: true, 5: true, 4: true, 38: true, 40: true, 37: true, 41: true}
	bottomRow := map[uint16]bool{6: true, 7: true, 8: true, 9: true, 11: true, 45: true, 46: true, 43: true, 47: true, 44: true}

	switch {
	case numberRow[keyCode]:
		return RowNumber
	case topRow[keyCode]:
		return RowTop
	case homeRow[keyCode]:
		return RowHome
	case bottomRow[keyCode]:
		return RowBottom
	default:
		return RowSpace
	}
}

func getFinger(keyCode uint16) FingerID {
	// Simplified - actual implementation would map all keys
	fingerMap := map[uint16]FingerID{
		12: FingerLeftPinky, 0: FingerLeftPinky, 6: FingerLeftPinky,    // Q A Z
		13: FingerLeftRing, 1: FingerLeftRing, 7: FingerLeftRing,       // W S X
		14: FingerLeftMiddle, 2: FingerLeftMiddle, 8: FingerLeftMiddle, // E D C
		15: FingerLeftIndex, 3: FingerLeftIndex, 9: FingerLeftIndex,    // R F V
	}

	if finger, ok := fingerMap[keyCode]; ok {
		return finger
	}
	return FingerUnknown
}
