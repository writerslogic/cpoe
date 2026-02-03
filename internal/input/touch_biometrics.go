//go:build darwin || linux || windows

// Package input provides secure capture and analysis of non-keyboard input methods.
//
// This package handles touchscreen and dictation input with security guarantees
// comparable to (or exceeding) keyboard-based tracking.
package input

import (
	"crypto/sha256"
	"encoding/binary"
	"math"
	"sync"
	"time"
)

// TouchEvent represents a single touch interaction.
type TouchEvent struct {
	Timestamp  time.Time `json:"timestamp"`
	Phase      TouchPhase `json:"phase"`
	X          float64   `json:"x"`           // Normalized 0.0-1.0
	Y          float64   `json:"y"`           // Normalized 0.0-1.0
	Pressure   float64   `json:"pressure"`    // 0.0-1.0 (if available)
	Radius     float64   `json:"radius"`      // Touch radius in points
	VelocityX  float64   `json:"velocity_x"`  // Points per second
	VelocityY  float64   `json:"velocity_y"`
	TouchID    int       `json:"touch_id"`    // For multi-touch tracking
}

// TouchPhase represents the state of a touch.
type TouchPhase int

const (
	TouchPhaseBegan TouchPhase = iota
	TouchPhaseMoved
	TouchPhaseStationary
	TouchPhaseEnded
	TouchPhaseCancelled
)

// TouchBiometrics captures behavioral patterns from touchscreen input.
// These patterns are highly individual and difficult to forge.
type TouchBiometrics struct {
	mu sync.RWMutex

	// Raw events (limited buffer)
	events    []TouchEvent
	maxEvents int

	// Timing patterns
	tapIntervals     []time.Duration // Time between taps
	holdDurations    []time.Duration // How long touches are held
	swipeVelocities  []float64       // Speed of swipe gestures

	// Spatial patterns
	touchPositions   [][2]float64    // Where user typically touches
	pressureProfile  []float64       // Pressure distribution
	touchRadii       []float64       // Finger size consistency

	// Derived biometrics
	profile TouchProfile
}

// TouchProfile is the computed biometric profile from touch patterns.
type TouchProfile struct {
	// Timing characteristics
	MeanTapInterval    float64 `json:"mean_tap_interval_ms"`
	StdDevTapInterval  float64 `json:"stddev_tap_interval_ms"`
	MeanHoldDuration   float64 `json:"mean_hold_duration_ms"`
	StdDevHoldDuration float64 `json:"stddev_hold_duration_ms"`

	// Pressure characteristics (highly individual)
	MeanPressure       float64 `json:"mean_pressure"`
	StdDevPressure     float64 `json:"stddev_pressure"`
	PressureRange      float64 `json:"pressure_range"`

	// Velocity characteristics
	MeanSwipeVelocity  float64 `json:"mean_swipe_velocity"`
	StdDevSwipeVelocity float64 `json:"stddev_swipe_velocity"`

	// Spatial characteristics
	TouchHeatmap       [10][10]float64 `json:"touch_heatmap"` // 10x10 grid density
	MeanTouchRadius    float64         `json:"mean_touch_radius"`
	StdDevTouchRadius  float64         `json:"stddev_touch_radius"`

	// Consistency metrics
	TotalTouches       uint64  `json:"total_touches"`
	UniqueFingers      int     `json:"unique_fingers"` // Multi-touch patterns
	ConsistencyScore   float64 `json:"consistency_score"` // 0-1, higher = more consistent

	// Hash of the profile for integrity
	ProfileHash        [32]byte `json:"profile_hash"`
}

// NewTouchBiometrics creates a touch biometrics analyzer.
func NewTouchBiometrics() *TouchBiometrics {
	return &TouchBiometrics{
		events:          make([]TouchEvent, 0, 1000),
		maxEvents:       1000,
		tapIntervals:    make([]time.Duration, 0, 500),
		holdDurations:   make([]time.Duration, 0, 500),
		swipeVelocities: make([]float64, 0, 500),
		touchPositions:  make([][2]float64, 0, 500),
		pressureProfile: make([]float64, 0, 500),
		touchRadii:      make([]float64, 0, 500),
	}
}

// RecordTouch records a touch event and updates biometrics.
func (tb *TouchBiometrics) RecordTouch(event TouchEvent) {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	// Store event
	if len(tb.events) >= tb.maxEvents {
		tb.events = tb.events[tb.maxEvents/2:]
	}
	tb.events = append(tb.events, event)

	// Update patterns based on phase
	switch event.Phase {
	case TouchPhaseBegan:
		tb.recordTapStart(event)
	case TouchPhaseEnded:
		tb.recordTapEnd(event)
	case TouchPhaseMoved:
		tb.recordSwipe(event)
	}

	// Always record position and pressure
	tb.touchPositions = append(tb.touchPositions, [2]float64{event.X, event.Y})
	if event.Pressure > 0 {
		tb.pressureProfile = append(tb.pressureProfile, event.Pressure)
	}
	if event.Radius > 0 {
		tb.touchRadii = append(tb.touchRadii, event.Radius)
	}

	// Limit array sizes
	tb.trimArrays()
}

// recordTapStart handles touch begin events.
func (tb *TouchBiometrics) recordTapStart(event TouchEvent) {
	// Calculate interval from last tap
	for i := len(tb.events) - 2; i >= 0; i-- {
		if tb.events[i].Phase == TouchPhaseBegan {
			interval := event.Timestamp.Sub(tb.events[i].Timestamp)
			if interval < 5*time.Second { // Ignore very long gaps
				tb.tapIntervals = append(tb.tapIntervals, interval)
			}
			break
		}
	}
}

// recordTapEnd handles touch end events.
func (tb *TouchBiometrics) recordTapEnd(event TouchEvent) {
	// Find matching begin event
	for i := len(tb.events) - 2; i >= 0; i-- {
		if tb.events[i].Phase == TouchPhaseBegan && tb.events[i].TouchID == event.TouchID {
			duration := event.Timestamp.Sub(tb.events[i].Timestamp)
			tb.holdDurations = append(tb.holdDurations, duration)
			break
		}
	}
}

// recordSwipe handles touch move events.
func (tb *TouchBiometrics) recordSwipe(event TouchEvent) {
	velocity := math.Sqrt(event.VelocityX*event.VelocityX + event.VelocityY*event.VelocityY)
	if velocity > 0 {
		tb.swipeVelocities = append(tb.swipeVelocities, velocity)
	}
}

// trimArrays limits array sizes to prevent unbounded growth.
func (tb *TouchBiometrics) trimArrays() {
	const maxSize = 500
	if len(tb.tapIntervals) > maxSize {
		tb.tapIntervals = tb.tapIntervals[len(tb.tapIntervals)-maxSize:]
	}
	if len(tb.holdDurations) > maxSize {
		tb.holdDurations = tb.holdDurations[len(tb.holdDurations)-maxSize:]
	}
	if len(tb.swipeVelocities) > maxSize {
		tb.swipeVelocities = tb.swipeVelocities[len(tb.swipeVelocities)-maxSize:]
	}
	if len(tb.touchPositions) > maxSize {
		tb.touchPositions = tb.touchPositions[len(tb.touchPositions)-maxSize:]
	}
	if len(tb.pressureProfile) > maxSize {
		tb.pressureProfile = tb.pressureProfile[len(tb.pressureProfile)-maxSize:]
	}
	if len(tb.touchRadii) > maxSize {
		tb.touchRadii = tb.touchRadii[len(tb.touchRadii)-maxSize:]
	}
}

// Profile computes the current biometric profile.
func (tb *TouchBiometrics) Profile() TouchProfile {
	tb.mu.RLock()
	defer tb.mu.RUnlock()

	profile := TouchProfile{
		TotalTouches: uint64(len(tb.events)),
	}

	// Compute timing statistics
	if len(tb.tapIntervals) > 0 {
		profile.MeanTapInterval = meanDuration(tb.tapIntervals)
		profile.StdDevTapInterval = stddevDuration(tb.tapIntervals)
	}
	if len(tb.holdDurations) > 0 {
		profile.MeanHoldDuration = meanDuration(tb.holdDurations)
		profile.StdDevHoldDuration = stddevDuration(tb.holdDurations)
	}

	// Compute pressure statistics
	if len(tb.pressureProfile) > 0 {
		profile.MeanPressure = mean(tb.pressureProfile)
		profile.StdDevPressure = stddev(tb.pressureProfile)
		profile.PressureRange = maxVal(tb.pressureProfile) - minVal(tb.pressureProfile)
	}

	// Compute velocity statistics
	if len(tb.swipeVelocities) > 0 {
		profile.MeanSwipeVelocity = mean(tb.swipeVelocities)
		profile.StdDevSwipeVelocity = stddev(tb.swipeVelocities)
	}

	// Compute touch radius statistics
	if len(tb.touchRadii) > 0 {
		profile.MeanTouchRadius = mean(tb.touchRadii)
		profile.StdDevTouchRadius = stddev(tb.touchRadii)
	}

	// Build touch heatmap
	profile.TouchHeatmap = tb.buildHeatmap()

	// Count unique fingers
	profile.UniqueFingers = tb.countUniqueFingers()

	// Compute consistency score
	profile.ConsistencyScore = tb.computeConsistency(profile)

	// Compute profile hash
	profile.ProfileHash = tb.hashProfile(profile)

	return profile
}

// buildHeatmap creates a 10x10 density map of touch locations.
func (tb *TouchBiometrics) buildHeatmap() [10][10]float64 {
	var heatmap [10][10]float64
	if len(tb.touchPositions) == 0 {
		return heatmap
	}

	for _, pos := range tb.touchPositions {
		x := int(pos[0] * 10)
		y := int(pos[1] * 10)
		if x >= 10 {
			x = 9
		}
		if y >= 10 {
			y = 9
		}
		if x < 0 {
			x = 0
		}
		if y < 0 {
			y = 0
		}
		heatmap[y][x]++
	}

	// Normalize
	total := float64(len(tb.touchPositions))
	for y := 0; y < 10; y++ {
		for x := 0; x < 10; x++ {
			heatmap[y][x] /= total
		}
	}

	return heatmap
}

// countUniqueFingers counts distinct touch IDs seen.
func (tb *TouchBiometrics) countUniqueFingers() int {
	seen := make(map[int]bool)
	for _, e := range tb.events {
		seen[e.TouchID] = true
	}
	return len(seen)
}

// computeConsistency calculates how consistent the touch patterns are.
// Higher consistency suggests a single user with stable behavior.
func (tb *TouchBiometrics) computeConsistency(profile TouchProfile) float64 {
	var scores []float64

	// Timing consistency (lower stddev relative to mean = more consistent)
	if profile.MeanTapInterval > 0 {
		timingCV := profile.StdDevTapInterval / profile.MeanTapInterval
		scores = append(scores, 1.0/(1.0+timingCV))
	}

	// Pressure consistency
	if profile.MeanPressure > 0 {
		pressureCV := profile.StdDevPressure / profile.MeanPressure
		scores = append(scores, 1.0/(1.0+pressureCV))
	}

	// Touch radius consistency (finger size should be stable)
	if profile.MeanTouchRadius > 0 {
		radiusCV := profile.StdDevTouchRadius / profile.MeanTouchRadius
		scores = append(scores, 1.0/(1.0+radiusCV))
	}

	if len(scores) == 0 {
		return 0.5
	}

	return mean(scores)
}

// hashProfile creates a hash of the profile for integrity verification.
func (tb *TouchBiometrics) hashProfile(profile TouchProfile) [32]byte {
	h := sha256.New()
	h.Write([]byte("witnessd-touch-profile-v1"))

	binary.Write(h, binary.BigEndian, profile.MeanTapInterval)
	binary.Write(h, binary.BigEndian, profile.MeanPressure)
	binary.Write(h, binary.BigEndian, profile.MeanSwipeVelocity)
	binary.Write(h, binary.BigEndian, profile.TotalTouches)

	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// IsHumanPlausible checks if the touch profile appears to be from a human.
func (profile TouchProfile) IsHumanPlausible() bool {
	// Check for minimum data
	if profile.TotalTouches < 10 {
		return true // Not enough data to judge
	}

	// Humans have natural variation - too consistent is suspicious
	if profile.ConsistencyScore > 0.99 {
		return false // Robotic precision
	}

	// Humans have some variation - too random is also suspicious
	if profile.ConsistencyScore < 0.1 {
		return false // Chaotic, possibly random input
	}

	// Check tap interval plausibility (50ms - 2000ms typical for humans)
	if profile.MeanTapInterval > 0 {
		if profile.MeanTapInterval < 30 || profile.MeanTapInterval > 5000 {
			return false
		}
	}

	// Check pressure variation (humans vary, robots don't)
	if profile.MeanPressure > 0 && profile.StdDevPressure < 0.001 {
		return false // Perfectly consistent pressure is suspicious
	}

	return true
}

// Helper functions

func mean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

func stddev(values []float64) float64 {
	if len(values) < 2 {
		return 0
	}
	m := mean(values)
	sum := 0.0
	for _, v := range values {
		diff := v - m
		sum += diff * diff
	}
	return math.Sqrt(sum / float64(len(values)-1))
}

func meanDuration(values []time.Duration) float64 {
	if len(values) == 0 {
		return 0
	}
	sum := time.Duration(0)
	for _, v := range values {
		sum += v
	}
	return float64(sum.Milliseconds()) / float64(len(values))
}

func stddevDuration(values []time.Duration) float64 {
	if len(values) < 2 {
		return 0
	}
	m := meanDuration(values)
	sum := 0.0
	for _, v := range values {
		diff := float64(v.Milliseconds()) - m
		sum += diff * diff
	}
	return math.Sqrt(sum / float64(len(values)-1))
}

func minVal(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	min := values[0]
	for _, v := range values[1:] {
		if v < min {
			min = v
		}
	}
	return min
}

func maxVal(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	max := values[0]
	for _, v := range values[1:] {
		if v > max {
			max = v
		}
	}
	return max
}
