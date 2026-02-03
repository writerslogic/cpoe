//go:build darwin || linux || windows

package input

import (
	"crypto/sha256"
	"encoding/binary"
	"math"
	"sync"
	"time"
)

// MinimalEnvironmental captures privacy-preserving environmental signals.
//
// Design principles:
// 1. NO identifiable information (no faces, no audio content, no video)
// 2. MINIMAL data (single values, not streams)
// 3. CANNOT be reconstructed into meaningful content
// 4. USEFUL for correlation and liveness detection
//
// What we capture:
// - Ambient light level changes (not images)
// - Audio energy presence (not content)
// - Motion energy (not video)
// - Timing correlations
//
// What we explicitly DO NOT capture:
// - Video frames or images
// - Audio recordings or speech
// - Facial features or biometrics
// - Screen content
// - Personally identifiable information
type MinimalEnvironmental struct {
	mu sync.RWMutex

	// Light level tracking (single scalar value)
	lightLevels    []LightSample
	lightBaseline  float64
	lightVariance  float64

	// Audio presence tracking (energy only, not content)
	audioEnergy    []AudioEnergySample
	audioBaseline  float64

	// Motion presence tracking (binary: movement or not)
	motionEvents   []MotionEvent
	motionRate     float64 // Events per minute

	// Correlation with input
	inputCorrelation float64

	// Configuration
	enabled bool
}

// LightSample is a single ambient light reading.
// This is just a number (0-1), not an image.
type LightSample struct {
	Timestamp time.Time
	Level     float64 // 0.0 (dark) to 1.0 (bright)
	Delta     float64 // Change from previous
}

// AudioEnergySample is a single audio energy reading.
// This captures "is there sound?" not "what is the sound?"
type AudioEnergySample struct {
	Timestamp time.Time
	Energy    float64 // 0.0 (silent) to 1.0 (loud)
	IsActive  bool    // Above threshold
}

// MotionEvent records that motion was detected.
// This is binary (motion/no motion), not what moved.
type MotionEvent struct {
	Timestamp time.Time
	Magnitude float64 // Relative amount of motion
}

// NewMinimalEnvironmental creates a minimal environmental sensor.
func NewMinimalEnvironmental(enabled bool) *MinimalEnvironmental {
	return &MinimalEnvironmental{
		lightLevels:  make([]LightSample, 0, 500),
		audioEnergy:  make([]AudioEnergySample, 0, 500),
		motionEvents: make([]MotionEvent, 0, 500),
		enabled:      enabled,
	}
}

// RecordLightLevel records an ambient light measurement.
// Input should be a normalized 0-1 value from ambient light sensor.
func (me *MinimalEnvironmental) RecordLightLevel(level float64) {
	if !me.enabled {
		return
	}

	me.mu.Lock()
	defer me.mu.Unlock()

	delta := 0.0
	if len(me.lightLevels) > 0 {
		delta = level - me.lightLevels[len(me.lightLevels)-1].Level
	}

	sample := LightSample{
		Timestamp: time.Now(),
		Level:     level,
		Delta:     delta,
	}

	me.lightLevels = append(me.lightLevels, sample)

	// Limit history
	if len(me.lightLevels) > 500 {
		me.lightLevels = me.lightLevels[250:]
	}

	me.updateLightStats()
}

// updateLightStats recalculates light statistics.
func (me *MinimalEnvironmental) updateLightStats() {
	if len(me.lightLevels) < 10 {
		return
	}

	var levels []float64
	for _, s := range me.lightLevels {
		levels = append(levels, s.Level)
	}

	me.lightBaseline = mean(levels)
	me.lightVariance = stddev(levels)
}

// RecordAudioEnergy records an audio energy measurement.
// This is just the volume level, NOT audio content.
func (me *MinimalEnvironmental) RecordAudioEnergy(energy float64) {
	if !me.enabled {
		return
	}

	me.mu.Lock()
	defer me.mu.Unlock()

	sample := AudioEnergySample{
		Timestamp: time.Now(),
		Energy:    energy,
		IsActive:  energy > 0.1, // Above silence threshold
	}

	me.audioEnergy = append(me.audioEnergy, sample)

	// Limit history
	if len(me.audioEnergy) > 500 {
		me.audioEnergy = me.audioEnergy[250:]
	}

	me.updateAudioStats()
}

// updateAudioStats recalculates audio statistics.
func (me *MinimalEnvironmental) updateAudioStats() {
	if len(me.audioEnergy) < 10 {
		return
	}

	var energies []float64
	for _, s := range me.audioEnergy {
		energies = append(energies, s.Energy)
	}

	me.audioBaseline = mean(energies)
}

// RecordMotion records that motion was detected.
// This is binary presence, NOT what moved or where.
func (me *MinimalEnvironmental) RecordMotion(magnitude float64) {
	if !me.enabled {
		return
	}

	me.mu.Lock()
	defer me.mu.Unlock()

	event := MotionEvent{
		Timestamp: time.Now(),
		Magnitude: magnitude,
	}

	me.motionEvents = append(me.motionEvents, event)

	// Limit history
	if len(me.motionEvents) > 500 {
		me.motionEvents = me.motionEvents[250:]
	}

	// Calculate motion rate
	if len(me.motionEvents) >= 2 {
		duration := me.motionEvents[len(me.motionEvents)-1].Timestamp.Sub(me.motionEvents[0].Timestamp)
		if duration.Minutes() > 0 {
			me.motionRate = float64(len(me.motionEvents)) / duration.Minutes()
		}
	}
}

// CorrelateWithInput checks if environmental signals correlate with input timing.
// For example: typing should correlate with motion (hands moving).
func (me *MinimalEnvironmental) CorrelateWithInput(inputTimestamps []time.Time) float64 {
	me.mu.Lock()
	defer me.mu.Unlock()

	if len(inputTimestamps) < 10 || len(me.motionEvents) < 10 {
		return 0.5 // Not enough data
	}

	// Count how many input events have motion within 500ms
	matches := 0
	for _, inputTime := range inputTimestamps {
		for _, motionEvent := range me.motionEvents {
			diff := inputTime.Sub(motionEvent.Timestamp)
			if diff < 0 {
				diff = -diff
			}
			if diff < 500*time.Millisecond {
				matches++
				break
			}
		}
	}

	me.inputCorrelation = float64(matches) / float64(len(inputTimestamps))
	return me.inputCorrelation
}

// LivenessScore returns a liveness score based on environmental signals.
func (me *MinimalEnvironmental) LivenessScore() float64 {
	me.mu.RLock()
	defer me.mu.RUnlock()

	if !me.enabled {
		return 0.5 // Neutral if disabled
	}

	var scores []float64

	// Light variation indicates real environment (not static image)
	if me.lightVariance > 0.001 {
		scores = append(scores, 0.7) // Some natural variation
	} else if len(me.lightLevels) > 50 {
		scores = append(scores, 0.3) // Suspiciously static
	}

	// Audio activity indicates human presence
	activeCount := 0
	for _, s := range me.audioEnergy {
		if s.IsActive {
			activeCount++
		}
	}
	if len(me.audioEnergy) > 0 {
		activityRatio := float64(activeCount) / float64(len(me.audioEnergy))
		// Some audio activity expected (0.1-0.5 is typical)
		if activityRatio > 0.05 && activityRatio < 0.8 {
			scores = append(scores, 0.7)
		} else {
			scores = append(scores, 0.4)
		}
	}

	// Motion correlates with typing (hands moving)
	if me.inputCorrelation > 0.5 {
		scores = append(scores, 0.8)
	} else if me.inputCorrelation > 0.2 {
		scores = append(scores, 0.6)
	} else if len(me.motionEvents) > 10 {
		scores = append(scores, 0.4) // Motion but not correlated with input
	}

	if len(scores) == 0 {
		return 0.5
	}

	return mean(scores)
}

// EnvironmentalHash creates a hash of recent environmental state.
// This can be used to prove environmental conditions at a point in time.
func (me *MinimalEnvironmental) EnvironmentalHash() [32]byte {
	me.mu.RLock()
	defer me.mu.RUnlock()

	h := sha256.New()
	h.Write([]byte("witnessd-environmental-v1"))

	// Include light stats
	binary.Write(h, binary.BigEndian, me.lightBaseline)
	binary.Write(h, binary.BigEndian, me.lightVariance)

	// Include audio baseline
	binary.Write(h, binary.BigEndian, me.audioBaseline)

	// Include motion rate
	binary.Write(h, binary.BigEndian, me.motionRate)

	// Include timestamp
	binary.Write(h, binary.BigEndian, time.Now().UnixNano())

	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// PrivacyReport confirms what data is/isn't being collected.
type PrivacyReport struct {
	// What IS collected (minimal)
	CollectsLightLevel    bool   `json:"collects_light_level"`
	CollectsAudioEnergy   bool   `json:"collects_audio_energy"`
	CollectsMotionPresence bool  `json:"collects_motion_presence"`

	// What is NOT collected (explicit guarantees)
	CollectsVideo         bool   `json:"collects_video"`          // Always false
	CollectsAudioContent  bool   `json:"collects_audio_content"`  // Always false
	CollectsFacialFeatures bool  `json:"collects_facial_features"` // Always false
	CollectsScreenContent bool   `json:"collects_screen_content"` // Always false

	// Data retention
	MaxSamplesStored     int    `json:"max_samples_stored"`
	DataRetentionMinutes int    `json:"data_retention_minutes"`

	// Summary
	PrivacyLevel         string `json:"privacy_level"` // "minimal", "none"
}

// PrivacyReport returns a privacy report.
func (me *MinimalEnvironmental) PrivacyReport() PrivacyReport {
	return PrivacyReport{
		CollectsLightLevel:     me.enabled,
		CollectsAudioEnergy:    me.enabled,
		CollectsMotionPresence: me.enabled,

		// Explicit guarantees
		CollectsVideo:          false,
		CollectsAudioContent:   false,
		CollectsFacialFeatures: false,
		CollectsScreenContent:  false,

		MaxSamplesStored:     500,
		DataRetentionMinutes: 30, // Approximate based on sample rate

		PrivacyLevel: func() string {
			if me.enabled {
				return "minimal"
			}
			return "none"
		}(),
	}
}

// CenterPixelTracker is an alternative approach: track just the center pixel.
// This captures screen activity without capturing content.
type CenterPixelTracker struct {
	mu sync.RWMutex

	samples    []CenterPixelSample
	enabled    bool
}

// CenterPixelSample is a single center pixel color.
type CenterPixelSample struct {
	Timestamp time.Time
	// We only store HSL to avoid identifying content
	Hue        float64 // 0-360
	Saturation float64 // 0-1
	Lightness  float64 // 0-1
}

// NewCenterPixelTracker creates a center pixel tracker.
func NewCenterPixelTracker(enabled bool) *CenterPixelTracker {
	return &CenterPixelTracker{
		samples: make([]CenterPixelSample, 0, 500),
		enabled: enabled,
	}
}

// RecordCenterPixel records the center pixel color.
// Input is HSL (hue 0-360, saturation 0-1, lightness 0-1).
func (cpt *CenterPixelTracker) RecordCenterPixel(h, s, l float64) {
	if !cpt.enabled {
		return
	}

	cpt.mu.Lock()
	defer cpt.mu.Unlock()

	sample := CenterPixelSample{
		Timestamp:  time.Now(),
		Hue:        h,
		Saturation: s,
		Lightness:  l,
	}

	cpt.samples = append(cpt.samples, sample)

	// Limit history
	if len(cpt.samples) > 500 {
		cpt.samples = cpt.samples[250:]
	}
}

// ActivityScore returns a score based on how much the center pixel changes.
// Active writing = screen changes = higher score.
func (cpt *CenterPixelTracker) ActivityScore() float64 {
	cpt.mu.RLock()
	defer cpt.mu.RUnlock()

	if len(cpt.samples) < 10 {
		return 0.5
	}

	// Calculate variance in lightness (most indicative of text changes)
	var lightnesses []float64
	for _, s := range cpt.samples {
		lightnesses = append(lightnesses, s.Lightness)
	}

	variance := stddev(lightnesses)

	// Some variance expected during typing (0.01-0.1)
	if variance > 0.01 && variance < 0.5 {
		return 0.7 // Normal activity
	} else if variance < 0.001 {
		return 0.3 // Screen not changing (suspicious if typing)
	}

	return 0.5
}

// CorrelateWithTyping checks if screen changes correlate with typing.
func (cpt *CenterPixelTracker) CorrelateWithTyping(keystrokeTimestamps []time.Time) float64 {
	cpt.mu.RLock()
	defer cpt.mu.RUnlock()

	if len(keystrokeTimestamps) < 10 || len(cpt.samples) < 10 {
		return 0.5
	}

	// Find samples where lightness changed significantly
	var changeTimestamps []time.Time
	for i := 1; i < len(cpt.samples); i++ {
		delta := math.Abs(cpt.samples[i].Lightness - cpt.samples[i-1].Lightness)
		if delta > 0.01 {
			changeTimestamps = append(changeTimestamps, cpt.samples[i].Timestamp)
		}
	}

	if len(changeTimestamps) < 5 {
		return 0.5
	}

	// Count keystroke events with corresponding screen changes within 500ms
	matches := 0
	for _, keystroke := range keystrokeTimestamps {
		for _, change := range changeTimestamps {
			diff := keystroke.Sub(change)
			if diff < 0 {
				diff = -diff
			}
			if diff < 500*time.Millisecond {
				matches++
				break
			}
		}
	}

	return float64(matches) / float64(len(keystrokeTimestamps))
}
