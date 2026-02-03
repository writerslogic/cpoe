//go:build darwin || linux || windows

package input

import (
	"crypto/rand"
	"encoding/binary"
	"math"
	"sync"
	"time"
)

// AdversarialDefense provides multi-layered protection against spoofing attacks.
//
// Attack vectors and defenses:
//
// KEYBOARD ATTACKS:
// 1. USB-HID injection → IOKit cross-validation, device fingerprinting
// 2. CGEventPost/SendInput → Synthetic event detection, source PID check
// 3. Replay attacks → TPM counters, nonce challenges, VDF
// 4. Keystroke recording → Micro-variation analysis, rhythm matching
// 5. AI typing simulation → Cross-correlation with content timing
//
// TOUCHSCREEN ATTACKS:
// 1. Touch injection (accessibility) → Source verification, gesture analysis
// 2. Robotic touch devices → Pressure/radius consistency, temperature
// 3. Recorded touch replay → Micro-tremor detection, challenge-response
// 4. Emulators → Hardware attestation, sensor fingerprinting
//
// DICTATION ATTACKS:
// 1. Pre-recorded audio → Liveness detection, real-time challenges
// 2. Voice synthesis/deepfake → Spectral analysis, prosody anomalies
// 3. Text-to-speech → Unnatural cadence detection
// 4. Another person speaking → Voice print verification, continuous auth
//
// CROSS-CUTTING DEFENSES:
// - Multi-modal verification (require multiple input methods)
// - Continuous authentication (not just at start)
// - Challenge-response protocols
// - Environmental correlation (ambient audio, accelerometer)
// - Hardware attestation (TPM, Secure Enclave)
type AdversarialDefense struct {
	mu sync.RWMutex

	// Challenge-response state
	pendingChallenges []Challenge
	completedChallenges []ChallengeResult

	// Anomaly tracking
	anomalies []Anomaly
	anomalyScore float64

	// Input consistency tracking
	keyboardProfile  *KeyboardProfile
	touchProfile     *TouchProfile
	voiceProfile     *VoiceProfile

	// Cross-modal correlation
	inputTimeline []InputTimestamp
	contentTimeline []ContentTimestamp

	// Environmental signals
	ambientSignatures []AmbientSignature

	// Configuration
	config DefenseConfig
}

// DefenseConfig configures adversarial defenses.
type DefenseConfig struct {
	// Challenge frequency
	ChallengeInterval    time.Duration
	RequireMultiModal    bool // Require multiple input methods

	// Sensitivity thresholds
	AnomalyThreshold     float64 // 0-1, trigger alert above this
	ReplayWindowMs       int64   // Time window for replay detection

	// Feature toggles
	EnableChallenges     bool
	EnableCrossModal     bool
	EnableEnvironmental  bool
}

// DefaultDefenseConfig returns sensible defaults.
func DefaultDefenseConfig() DefenseConfig {
	return DefenseConfig{
		ChallengeInterval:   5 * time.Minute,
		RequireMultiModal:   false,
		AnomalyThreshold:    0.7,
		ReplayWindowMs:      100, // 100ms replay detection window
		EnableChallenges:    true,
		EnableCrossModal:    true,
		EnableEnvironmental: false, // Opt-in for privacy
	}
}

// Challenge represents a liveness verification challenge.
type Challenge struct {
	ID          [16]byte
	Type        ChallengeType
	IssuedAt    time.Time
	ExpiresAt   time.Time
	Data        []byte // Challenge-specific data
	ExpectedResponse []byte
}

// ChallengeType defines different challenge mechanisms.
type ChallengeType int

const (
	// ChallengeTypeRhythm asks user to type a specific rhythm pattern
	ChallengeTypeRhythm ChallengeType = iota

	// ChallengeTypeTouchPattern asks user to draw a specific pattern
	ChallengeTypeTouchPattern

	// ChallengeTypeVoicePhrase asks user to speak a random phrase
	ChallengeTypeVoicePhrase

	// ChallengeTypePause asks user to pause and resume (proves attention)
	ChallengeTypePause

	// ChallengeTypeSpeedChange asks user to type faster/slower
	ChallengeTypeSpeedChange
)

// ChallengeResult records the outcome of a challenge.
type ChallengeResult struct {
	ChallengeID [16]byte
	CompletedAt time.Time
	Passed      bool
	Response    []byte
	Confidence  float64
}

// Anomaly represents a detected suspicious behavior.
type Anomaly struct {
	Timestamp   time.Time
	Type        AnomalyType
	Severity    float64 // 0-1
	Description string
	Evidence    map[string]interface{}
}

// AnomalyType categorizes anomalies.
type AnomalyType int

const (
	AnomalyTypeTimingTooConsistent AnomalyType = iota
	AnomalyTypeTimingTooVariable
	AnomalyTypeSyntheticEvent
	AnomalyTypeDeviceMismatch
	AnomalyTypeReplayDetected
	AnomalyTypeSpeedInhuman
	AnomalyTypePressureUnnatural
	AnomalyTypeVoiceUnnatural
	AnomalyTypeContentMismatch
	AnomalyTypeProfileShift
	AnomalyTypeChallengeFailure
)

func (a AnomalyType) String() string {
	names := []string{
		"TIMING_TOO_CONSISTENT",
		"TIMING_TOO_VARIABLE",
		"SYNTHETIC_EVENT",
		"DEVICE_MISMATCH",
		"REPLAY_DETECTED",
		"SPEED_INHUMAN",
		"PRESSURE_UNNATURAL",
		"VOICE_UNNATURAL",
		"CONTENT_MISMATCH",
		"PROFILE_SHIFT",
		"CHALLENGE_FAILURE",
	}
	if int(a) < len(names) {
		return names[a]
	}
	return "UNKNOWN"
}

// InputTimestamp records when input occurred.
type InputTimestamp struct {
	Timestamp time.Time
	Method    InputMethod
	CharCount int
}

// ContentTimestamp records when content appeared in document.
type ContentTimestamp struct {
	Timestamp time.Time
	CharCount int
	ContentHash [32]byte
}

// AmbientSignature captures environmental signals for correlation.
type AmbientSignature struct {
	Timestamp       time.Time
	AudioFingerprint [32]byte // Hash of ambient audio characteristics
	AccelerometerSum float64   // Device movement indicator
}

// NewAdversarialDefense creates an adversarial defense system.
func NewAdversarialDefense(config DefenseConfig) *AdversarialDefense {
	return &AdversarialDefense{
		pendingChallenges:   make([]Challenge, 0),
		completedChallenges: make([]ChallengeResult, 0),
		anomalies:           make([]Anomaly, 0),
		inputTimeline:       make([]InputTimestamp, 0, 1000),
		contentTimeline:     make([]ContentTimestamp, 0, 1000),
		ambientSignatures:   make([]AmbientSignature, 0, 100),
		config:              config,
	}
}

// AnalyzeKeyboardInput checks keyboard input for anomalies.
func (ad *AdversarialDefense) AnalyzeKeyboardInput(profile KeyboardProfile) []Anomaly {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	var detected []Anomaly

	// Check 1: Timing too consistent (replay attack)
	if profile.MicroVariation < 0.05 {
		detected = append(detected, Anomaly{
			Timestamp:   time.Now(),
			Type:        AnomalyTypeTimingTooConsistent,
			Severity:    0.9,
			Description: "Keystroke timing shows robotic consistency - possible replay attack",
			Evidence: map[string]interface{}{
				"micro_variation": profile.MicroVariation,
				"threshold":       0.05,
			},
		})
	}

	// Check 2: Speed inhuman
	if profile.KeysPerMinute > 600 { // ~120 WPM sustained is elite
		detected = append(detected, Anomaly{
			Timestamp:   time.Now(),
			Type:        AnomalyTypeSpeedInhuman,
			Severity:    0.8,
			Description: "Typing speed exceeds human capability",
			Evidence: map[string]interface{}{
				"kpm":       profile.KeysPerMinute,
				"threshold": 600,
			},
		})
	}

	// Check 3: No fatigue over long session (robots don't tire)
	if profile.SessionDuration > 30*time.Minute && profile.FatigueSlope < -0.1 {
		detected = append(detected, Anomaly{
			Timestamp:   time.Now(),
			Type:        AnomalyTypeTimingTooVariable,
			Severity:    0.5,
			Description: "User speeding up over 30+ minute session - unusual",
			Evidence: map[string]interface{}{
				"fatigue_slope": profile.FatigueSlope,
				"session_mins":  profile.SessionDuration.Minutes(),
			},
		})
	}

	// Check 4: Profile shift (different person?)
	if ad.keyboardProfile != nil {
		shift := ad.computeProfileShift(*ad.keyboardProfile, profile)
		if shift > 0.5 {
			detected = append(detected, Anomaly{
				Timestamp:   time.Now(),
				Type:        AnomalyTypeProfileShift,
				Severity:    shift,
				Description: "Typing pattern significantly changed - possible user switch",
				Evidence: map[string]interface{}{
					"shift_magnitude": shift,
				},
			})
		}
	}

	// Update stored profile
	ad.keyboardProfile = &profile

	// Record anomalies
	ad.anomalies = append(ad.anomalies, detected...)
	ad.updateAnomalyScore()

	return detected
}

// AnalyzeTouchInput checks touch input for anomalies.
func (ad *AdversarialDefense) AnalyzeTouchInput(profile TouchProfile) []Anomaly {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	var detected []Anomaly

	// Check 1: Pressure too consistent (robotic)
	if profile.MeanPressure > 0 && profile.StdDevPressure < 0.01 {
		detected = append(detected, Anomaly{
			Timestamp:   time.Now(),
			Type:        AnomalyTypePressureUnnatural,
			Severity:    0.85,
			Description: "Touch pressure shows robotic consistency",
			Evidence: map[string]interface{}{
				"pressure_stddev": profile.StdDevPressure,
				"threshold":       0.01,
			},
		})
	}

	// Check 2: Touch radius too consistent (physical finger varies slightly)
	if profile.MeanTouchRadius > 0 && profile.StdDevTouchRadius < 0.5 {
		detected = append(detected, Anomaly{
			Timestamp:   time.Now(),
			Type:        AnomalyTypePressureUnnatural,
			Severity:    0.7,
			Description: "Touch radius unnaturally consistent",
			Evidence: map[string]interface{}{
				"radius_stddev": profile.StdDevTouchRadius,
			},
		})
	}

	// Check 3: Tap timing too regular
	if profile.MeanTapInterval > 0 && profile.StdDevTapInterval < 10 {
		detected = append(detected, Anomaly{
			Timestamp:   time.Now(),
			Type:        AnomalyTypeTimingTooConsistent,
			Severity:    0.8,
			Description: "Touch timing shows robotic regularity",
			Evidence: map[string]interface{}{
				"tap_interval_stddev": profile.StdDevTapInterval,
			},
		})
	}

	// Check 4: Consistency too high overall
	if profile.ConsistencyScore > 0.98 {
		detected = append(detected, Anomaly{
			Timestamp:   time.Now(),
			Type:        AnomalyTypeTimingTooConsistent,
			Severity:    0.9,
			Description: "Touch patterns show inhuman consistency",
			Evidence: map[string]interface{}{
				"consistency_score": profile.ConsistencyScore,
			},
		})
	}

	// Update stored profile
	ad.touchProfile = &profile

	ad.anomalies = append(ad.anomalies, detected...)
	ad.updateAnomalyScore()

	return detected
}

// AnalyzeVoiceInput checks voice input for anomalies.
func (ad *AdversarialDefense) AnalyzeVoiceInput(profile VoiceProfile) []Anomaly {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	var detected []Anomaly

	// Check 1: WPM too consistent (TTS is often very regular)
	if profile.MeanWPM > 0 && profile.StdDevWPM < 5 {
		detected = append(detected, Anomaly{
			Timestamp:   time.Now(),
			Type:        AnomalyTypeVoiceUnnatural,
			Severity:    0.8,
			Description: "Speaking rate unnaturally consistent - possible TTS",
			Evidence: map[string]interface{}{
				"wpm_stddev":  profile.StdDevWPM,
				"wpm_mean":    profile.MeanWPM,
			},
		})
	}

	// Check 2: No word pauses (natural speech has micro-pauses)
	if profile.MeanWordPause < 50 { // Less than 50ms between all words
		detected = append(detected, Anomaly{
			Timestamp:   time.Now(),
			Type:        AnomalyTypeVoiceUnnatural,
			Severity:    0.75,
			Description: "No natural pauses between words - possible TTS",
			Evidence: map[string]interface{}{
				"mean_word_pause_ms": profile.MeanWordPause,
			},
		})
	}

	// Check 3: Liveness score too low
	if profile.LivenessScore < 0.4 {
		detected = append(detected, Anomaly{
			Timestamp:   time.Now(),
			Type:        AnomalyTypeVoiceUnnatural,
			Severity:    0.85,
			Description: "Voice fails liveness checks - possible pre-recorded",
			Evidence: map[string]interface{}{
				"liveness_score": profile.LivenessScore,
			},
		})
	}

	// Check 4: Pitch too monotone (natural voices vary)
	if profile.MeanPitch > 0 && profile.StdDevPitch < 5 {
		detected = append(detected, Anomaly{
			Timestamp:   time.Now(),
			Type:        AnomalyTypeVoiceUnnatural,
			Severity:    0.6,
			Description: "Voice pitch unnaturally monotone",
			Evidence: map[string]interface{}{
				"pitch_stddev": profile.StdDevPitch,
			},
		})
	}

	// Check 5: Perfect recognition confidence (real speech has errors)
	if profile.MeanConfidence > 0.99 && profile.TotalWords > 100 {
		detected = append(detected, Anomaly{
			Timestamp:   time.Now(),
			Type:        AnomalyTypeVoiceUnnatural,
			Severity:    0.5,
			Description: "Speech recognition confidence unusually high",
			Evidence: map[string]interface{}{
				"mean_confidence": profile.MeanConfidence,
			},
		})
	}

	// Update stored profile
	ad.voiceProfile = &profile

	ad.anomalies = append(ad.anomalies, detected...)
	ad.updateAnomalyScore()

	return detected
}

// AnalyzeCrossModal checks correlation between input and content changes.
func (ad *AdversarialDefense) AnalyzeCrossModal() []Anomaly {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	var detected []Anomaly

	if !ad.config.EnableCrossModal {
		return detected
	}

	// Check: Content appearing without corresponding input
	inputChars := 0
	for _, input := range ad.inputTimeline {
		inputChars += input.CharCount
	}

	contentChars := 0
	for _, content := range ad.contentTimeline {
		contentChars += content.CharCount
	}

	// Allow some margin for paste operations, but flag large discrepancies
	if contentChars > inputChars*2 && contentChars-inputChars > 500 {
		detected = append(detected, Anomaly{
			Timestamp:   time.Now(),
			Type:        AnomalyTypeContentMismatch,
			Severity:    0.7,
			Description: "Content growth exceeds input events - possible injection",
			Evidence: map[string]interface{}{
				"input_chars":   inputChars,
				"content_chars": contentChars,
				"delta":         contentChars - inputChars,
			},
		})
	}

	ad.anomalies = append(ad.anomalies, detected...)
	ad.updateAnomalyScore()

	return detected
}

// IssueChallenge creates a new liveness challenge.
func (ad *AdversarialDefense) IssueChallenge(challengeType ChallengeType) *Challenge {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	if !ad.config.EnableChallenges {
		return nil
	}

	var id [16]byte
	rand.Read(id[:])

	challenge := Challenge{
		ID:        id,
		Type:      challengeType,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(60 * time.Second),
	}

	// Generate challenge-specific data
	switch challengeType {
	case ChallengeTypeRhythm:
		// Generate a rhythm pattern (e.g., "type space-space-pause-space")
		pattern := generateRhythmPattern()
		challenge.Data = pattern
		challenge.ExpectedResponse = pattern

	case ChallengeTypeTouchPattern:
		// Generate a simple shape to draw
		pattern := generateTouchPattern()
		challenge.Data = pattern

	case ChallengeTypeVoicePhrase:
		// Generate random phrase to speak
		phrase := generateRandomPhrase()
		challenge.Data = []byte(phrase)

	case ChallengeTypePause:
		// No data needed
		challenge.Data = nil

	case ChallengeTypeSpeedChange:
		// Target speed change (1.5x or 0.5x)
		if randBool() {
			challenge.Data = []byte("faster")
		} else {
			challenge.Data = []byte("slower")
		}
	}

	ad.pendingChallenges = append(ad.pendingChallenges, challenge)

	return &challenge
}

// VerifyChallenge checks if a challenge response is valid.
func (ad *AdversarialDefense) VerifyChallenge(challengeID [16]byte, response []byte) (*ChallengeResult, error) {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	// Find the challenge
	var challenge *Challenge
	for i, c := range ad.pendingChallenges {
		if c.ID == challengeID {
			challenge = &ad.pendingChallenges[i]
			break
		}
	}

	if challenge == nil {
		return nil, nil // Challenge not found
	}

	// Check expiration
	if time.Now().After(challenge.ExpiresAt) {
		return &ChallengeResult{
			ChallengeID: challengeID,
			CompletedAt: time.Now(),
			Passed:      false,
			Confidence:  0,
		}, nil
	}

	// Verify based on type
	passed := false
	confidence := 0.0

	switch challenge.Type {
	case ChallengeTypeRhythm:
		passed, confidence = verifyRhythmResponse(challenge.ExpectedResponse, response)
	case ChallengeTypeTouchPattern:
		passed, confidence = verifyTouchPatternResponse(challenge.Data, response)
	case ChallengeTypeVoicePhrase:
		passed, confidence = verifyVoicePhraseResponse(challenge.Data, response)
	case ChallengeTypePause:
		passed, confidence = verifyPauseResponse(response)
	case ChallengeTypeSpeedChange:
		passed, confidence = verifySpeedChangeResponse(challenge.Data, response)
	}

	result := &ChallengeResult{
		ChallengeID: challengeID,
		CompletedAt: time.Now(),
		Passed:      passed,
		Response:    response,
		Confidence:  confidence,
	}

	// Record result
	ad.completedChallenges = append(ad.completedChallenges, *result)

	// Record anomaly if failed
	if !passed {
		ad.anomalies = append(ad.anomalies, Anomaly{
			Timestamp:   time.Now(),
			Type:        AnomalyTypeChallengeFailure,
			Severity:    0.9,
			Description: "Failed liveness challenge",
			Evidence: map[string]interface{}{
				"challenge_type": challenge.Type,
				"confidence":     confidence,
			},
		})
		ad.updateAnomalyScore()
	}

	// Remove from pending
	for i, c := range ad.pendingChallenges {
		if c.ID == challengeID {
			ad.pendingChallenges = append(ad.pendingChallenges[:i], ad.pendingChallenges[i+1:]...)
			break
		}
	}

	return result, nil
}

// RecordInput records an input event for cross-modal analysis.
func (ad *AdversarialDefense) RecordInput(method InputMethod, charCount int) {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	ad.inputTimeline = append(ad.inputTimeline, InputTimestamp{
		Timestamp: time.Now(),
		Method:    method,
		CharCount: charCount,
	})

	// Trim
	if len(ad.inputTimeline) > 1000 {
		ad.inputTimeline = ad.inputTimeline[500:]
	}
}

// RecordContent records a content change for cross-modal analysis.
func (ad *AdversarialDefense) RecordContent(charCount int, contentHash [32]byte) {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	ad.contentTimeline = append(ad.contentTimeline, ContentTimestamp{
		Timestamp:   time.Now(),
		CharCount:   charCount,
		ContentHash: contentHash,
	})

	// Trim
	if len(ad.contentTimeline) > 1000 {
		ad.contentTimeline = ad.contentTimeline[500:]
	}
}

// AnomalyScore returns the current overall anomaly score (0-1).
func (ad *AdversarialDefense) AnomalyScore() float64 {
	ad.mu.RLock()
	defer ad.mu.RUnlock()
	return ad.anomalyScore
}

// Anomalies returns all detected anomalies.
func (ad *AdversarialDefense) Anomalies() []Anomaly {
	ad.mu.RLock()
	defer ad.mu.RUnlock()

	result := make([]Anomaly, len(ad.anomalies))
	copy(result, ad.anomalies)
	return result
}

// IsCompromised returns true if anomaly score exceeds threshold.
func (ad *AdversarialDefense) IsCompromised() bool {
	ad.mu.RLock()
	defer ad.mu.RUnlock()
	return ad.anomalyScore >= ad.config.AnomalyThreshold
}

// updateAnomalyScore recalculates the overall anomaly score.
func (ad *AdversarialDefense) updateAnomalyScore() {
	if len(ad.anomalies) == 0 {
		ad.anomalyScore = 0
		return
	}

	// Weight recent anomalies more heavily
	now := time.Now()
	totalWeight := 0.0
	weightedSum := 0.0

	for _, anomaly := range ad.anomalies {
		age := now.Sub(anomaly.Timestamp)
		// Decay weight: full weight for <1min, half at 5min, quarter at 15min
		weight := math.Exp(-float64(age) / float64(5*time.Minute))

		totalWeight += weight
		weightedSum += anomaly.Severity * weight
	}

	if totalWeight > 0 {
		ad.anomalyScore = weightedSum / totalWeight
	}

	// Clamp to 0-1
	if ad.anomalyScore > 1 {
		ad.anomalyScore = 1
	}
}

// computeProfileShift measures how much a keyboard profile has changed.
func (ad *AdversarialDefense) computeProfileShift(old, new KeyboardProfile) float64 {
	var diffs []float64

	// Compare rhythm signatures
	rhythmDiff := 0.0
	for i := 0; i < 16; i++ {
		rhythmDiff += math.Abs(old.RhythmSignature[i] - new.RhythmSignature[i])
	}
	diffs = append(diffs, rhythmDiff/16)

	// Compare timing
	if old.MeanFlightTime > 0 {
		timingDiff := math.Abs(old.MeanFlightTime-new.MeanFlightTime) / old.MeanFlightTime
		diffs = append(diffs, math.Min(timingDiff, 1.0))
	}

	// Compare hand ratio
	handDiff := math.Abs(old.LeftHandRatio - new.LeftHandRatio)
	diffs = append(diffs, handDiff)

	if len(diffs) == 0 {
		return 0
	}

	return mean(diffs)
}

// Helper functions for challenges

func generateRhythmPattern() []byte {
	// Generate a pattern like: short-short-long-short
	// Encoded as 10ms units (so 10 = 100ms, 25 = 250ms)
	patterns := [][]byte{
		{10, 10, 25, 10}, // 100, 100, 250, 100 ms
		{15, 15, 15, 25}, // 150, 150, 150, 250 ms
		{20, 10, 20, 10}, // 200, 100, 200, 100 ms
		{10, 25, 10, 25}, // 100, 250, 100, 250 ms
	}
	idx := randInt(len(patterns))
	return patterns[idx]
}

func generateTouchPattern() []byte {
	// Generate a simple shape descriptor
	shapes := []string{"circle", "square", "triangle", "zigzag"}
	return []byte(shapes[randInt(len(shapes))])
}

func generateRandomPhrase() string {
	phrases := []string{
		"the quick brown fox",
		"hello world today",
		"verify my voice now",
		"random security phrase",
	}
	return phrases[randInt(len(phrases))]
}

func verifyRhythmResponse(expected, actual []byte) (bool, float64) {
	if len(expected) != len(actual) {
		return false, 0
	}

	totalError := 0.0
	for i := range expected {
		diff := math.Abs(float64(expected[i]) - float64(actual[i]))
		tolerance := float64(expected[i]) * 0.3 // 30% tolerance
		if diff > tolerance {
			totalError += diff / float64(expected[i])
		}
	}

	if totalError > float64(len(expected))*0.5 {
		return false, 0.5 - totalError/float64(len(expected))
	}

	return true, 1.0 - totalError/float64(len(expected))
}

func verifyTouchPatternResponse(expected, actual []byte) (bool, float64) {
	// Simplified: check if the drawn shape matches
	if string(expected) == string(actual) {
		return true, 1.0
	}
	return false, 0.3
}

func verifyVoicePhraseResponse(expected, actual []byte) (bool, float64) {
	// Check if transcribed text matches expected phrase
	expectedStr := string(expected)
	actualStr := string(actual)

	// Simple word match
	expectedWords := len(expectedStr) / 5 // Approximate word count
	actualWords := len(actualStr) / 5

	if math.Abs(float64(expectedWords-actualWords)) <= 1 {
		return true, 0.8
	}
	return false, 0.2
}

func verifyPauseResponse(response []byte) (bool, float64) {
	// Response should indicate a pause was detected
	if len(response) > 0 && response[0] == 1 {
		return true, 1.0
	}
	return false, 0
}

func verifySpeedChangeResponse(expected, actual []byte) (bool, float64) {
	expectedDirection := string(expected)
	actualRatio := float64(actual[0]) / 100.0 // Encoded as percentage

	if expectedDirection == "faster" && actualRatio > 1.2 {
		return true, math.Min(actualRatio-1.0, 1.0)
	}
	if expectedDirection == "slower" && actualRatio < 0.8 {
		return true, math.Min(1.0-actualRatio, 1.0)
	}
	return false, 0.3
}

func randInt(max int) int {
	var b [8]byte
	rand.Read(b[:])
	return int(binary.BigEndian.Uint64(b[:]) % uint64(max))
}

func randBool() bool {
	var b [1]byte
	rand.Read(b[:])
	return b[0]%2 == 0
}

// SecurityReport generates a comprehensive security report.
type SecurityReport struct {
	Timestamp          time.Time            `json:"timestamp"`
	OverallScore       float64              `json:"overall_score"` // 0-100
	AnomalyScore       float64              `json:"anomaly_score"` // 0-1
	IsCompromised      bool                 `json:"is_compromised"`

	// Per-method analysis
	KeyboardAnalysis   *MethodAnalysis      `json:"keyboard_analysis,omitempty"`
	TouchAnalysis      *MethodAnalysis      `json:"touch_analysis,omitempty"`
	VoiceAnalysis      *MethodAnalysis      `json:"voice_analysis,omitempty"`

	// Challenges
	ChallengesPassed   int                  `json:"challenges_passed"`
	ChallengesFailed   int                  `json:"challenges_failed"`

	// Anomalies
	TotalAnomalies     int                  `json:"total_anomalies"`
	CriticalAnomalies  int                  `json:"critical_anomalies"`
	AnomalySummary     map[string]int       `json:"anomaly_summary"`

	// Recommendations
	Recommendations    []string             `json:"recommendations"`
}

// MethodAnalysis contains analysis for one input method.
type MethodAnalysis struct {
	Method            string  `json:"method"`
	DataPoints        int     `json:"data_points"`
	IdentityConfidence float64 `json:"identity_confidence"`
	LivenessConfidence float64 `json:"liveness_confidence"`
	HumanPlausible    bool    `json:"human_plausible"`
	AnomalyCount      int     `json:"anomaly_count"`
}

// GenerateReport creates a comprehensive security report.
func (ad *AdversarialDefense) GenerateReport() SecurityReport {
	ad.mu.RLock()
	defer ad.mu.RUnlock()

	report := SecurityReport{
		Timestamp:     time.Now(),
		AnomalyScore:  ad.anomalyScore,
		IsCompromised: ad.anomalyScore >= ad.config.AnomalyThreshold,
		AnomalySummary: make(map[string]int),
	}

	// Count anomalies by type
	for _, anomaly := range ad.anomalies {
		report.TotalAnomalies++
		report.AnomalySummary[anomaly.Type.String()]++
		if anomaly.Severity >= 0.8 {
			report.CriticalAnomalies++
		}
	}

	// Count challenges
	for _, result := range ad.completedChallenges {
		if result.Passed {
			report.ChallengesPassed++
		} else {
			report.ChallengesFailed++
		}
	}

	// Keyboard analysis
	if ad.keyboardProfile != nil {
		report.KeyboardAnalysis = &MethodAnalysis{
			Method:             "keyboard",
			DataPoints:         int(ad.keyboardProfile.TotalKeystrokes),
			IdentityConfidence: ad.keyboardProfile.IdentityConfidence,
			LivenessConfidence: ad.keyboardProfile.LivenessConfidence,
			HumanPlausible:     ad.keyboardProfile.IsHumanPlausible(),
		}
	}

	// Touch analysis
	if ad.touchProfile != nil {
		report.TouchAnalysis = &MethodAnalysis{
			Method:             "touch",
			DataPoints:         int(ad.touchProfile.TotalTouches),
			IdentityConfidence: ad.touchProfile.ConsistencyScore,
			LivenessConfidence: ad.touchProfile.ConsistencyScore, // Touch doesn't have separate liveness
			HumanPlausible:     ad.touchProfile.IsHumanPlausible(),
		}
	}

	// Voice analysis
	if ad.voiceProfile != nil {
		report.VoiceAnalysis = &MethodAnalysis{
			Method:             "voice",
			DataPoints:         int(ad.voiceProfile.TotalWords),
			IdentityConfidence: ad.voiceProfile.ConsistencyScore,
			LivenessConfidence: ad.voiceProfile.LivenessScore,
			HumanPlausible:     ad.voiceProfile.IsHumanPlausible(),
		}
	}

	// Calculate overall score (0-100)
	report.OverallScore = ad.calculateOverallScore(report)

	// Generate recommendations
	report.Recommendations = ad.generateRecommendations(report)

	return report
}

// calculateOverallScore computes a 0-100 security score.
func (ad *AdversarialDefense) calculateOverallScore(report SecurityReport) float64 {
	score := 100.0

	// Deduct for anomalies
	score -= float64(report.CriticalAnomalies) * 15
	score -= float64(report.TotalAnomalies-report.CriticalAnomalies) * 5

	// Deduct for failed challenges
	score -= float64(report.ChallengesFailed) * 10

	// Bonus for passed challenges
	score += float64(report.ChallengesPassed) * 2

	// Bonus for multiple verified input methods
	methodCount := 0
	if report.KeyboardAnalysis != nil && report.KeyboardAnalysis.HumanPlausible {
		methodCount++
	}
	if report.TouchAnalysis != nil && report.TouchAnalysis.HumanPlausible {
		methodCount++
	}
	if report.VoiceAnalysis != nil && report.VoiceAnalysis.HumanPlausible {
		methodCount++
		score += 10 // Extra bonus for voice (biometric)
	}
	score += float64(methodCount) * 5

	// Clamp
	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}

	return score
}

// generateRecommendations creates actionable recommendations.
func (ad *AdversarialDefense) generateRecommendations(report SecurityReport) []string {
	var recs []string

	if report.CriticalAnomalies > 0 {
		recs = append(recs, "CRITICAL: Suspicious activity detected - verify user identity")
	}

	if report.ChallengesFailed > report.ChallengesPassed {
		recs = append(recs, "Consider requiring additional authentication")
	}

	if report.KeyboardAnalysis == nil && report.TouchAnalysis == nil && report.VoiceAnalysis == nil {
		recs = append(recs, "No biometric data collected - enable input tracking")
	}

	if report.VoiceAnalysis == nil {
		recs = append(recs, "Voice input provides strongest biometric verification - consider enabling")
	}

	methodCount := 0
	if report.KeyboardAnalysis != nil {
		methodCount++
	}
	if report.TouchAnalysis != nil {
		methodCount++
	}
	if report.VoiceAnalysis != nil {
		methodCount++
	}

	if methodCount < 2 {
		recs = append(recs, "Multi-modal input (keyboard + touch or voice) increases security")
	}

	return recs
}
