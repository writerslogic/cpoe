//go:build darwin || linux || windows

package input

import (
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"time"
)

// VoiceBiometrics captures behavioral patterns from dictation input.
// Voice input is inherently biometric - each person's speech patterns are unique.
//
// Key insight: Dictation can be MORE secure than typing because:
// 1. Voice is a biometric identifier (hard to fake)
// 2. Speech patterns (cadence, pauses, prosody) are personal
// 3. Background audio provides environmental verification
// 4. Real-time processing proves liveness (no pre-recording)
type VoiceBiometrics struct {
	mu sync.RWMutex

	// Speech segments
	segments    []SpeechSegment
	maxSegments int

	// Timing patterns
	wordIntervals   []time.Duration // Pauses between words
	sentenceGaps    []time.Duration // Longer pauses (sentence boundaries)
	speakingBursts  []time.Duration // Duration of continuous speech

	// Speech characteristics
	wordsPerMinute  []float64 // Speaking rate over time
	confidenceScores []float64 // ASR confidence scores

	// Prosody features (if available from speech API)
	pitchSamples    []float64 // Voice pitch variations
	energySamples   []float64 // Volume/energy levels

	// Text output tracking
	totalWords      uint64
	totalCharacters uint64
	corrections     uint64 // Speech recognition corrections

	// Profile
	profile VoiceProfile
}

// SpeechSegment represents a unit of dictated speech.
type SpeechSegment struct {
	Timestamp     time.Time `json:"timestamp"`
	Duration      time.Duration `json:"duration"`
	Text          string    `json:"text"`           // Transcribed text (not stored in evidence)
	WordCount     int       `json:"word_count"`
	CharCount     int       `json:"char_count"`
	Confidence    float64   `json:"confidence"`     // 0-1 ASR confidence
	IsFinal       bool      `json:"is_final"`       // Final vs interim result
	TextHash      [32]byte  `json:"text_hash"`      // Hash of text for verification
}

// VoiceProfile is the computed biometric profile from speech patterns.
type VoiceProfile struct {
	// Speaking rate characteristics
	MeanWPM           float64 `json:"mean_wpm"`            // Words per minute
	StdDevWPM         float64 `json:"stddev_wpm"`
	MinWPM            float64 `json:"min_wpm"`
	MaxWPM            float64 `json:"max_wpm"`

	// Pause characteristics (highly individual)
	MeanWordPause     float64 `json:"mean_word_pause_ms"`  // Pause between words
	StdDevWordPause   float64 `json:"stddev_word_pause_ms"`
	MeanSentencePause float64 `json:"mean_sentence_pause_ms"`
	StdDevSentencePause float64 `json:"stddev_sentence_pause_ms"`

	// Burst characteristics (how long they speak continuously)
	MeanBurstDuration float64 `json:"mean_burst_duration_ms"`
	StdDevBurstDuration float64 `json:"stddev_burst_duration_ms"`

	// Prosody characteristics (voice quality)
	MeanPitch         float64 `json:"mean_pitch_hz,omitempty"`
	StdDevPitch       float64 `json:"stddev_pitch_hz,omitempty"`
	MeanEnergy        float64 `json:"mean_energy,omitempty"`
	StdDevEnergy      float64 `json:"stddev_energy,omitempty"`

	// Recognition characteristics
	MeanConfidence    float64 `json:"mean_confidence"`
	CorrectionRate    float64 `json:"correction_rate"` // Corrections per 100 words

	// Totals
	TotalSegments     uint64  `json:"total_segments"`
	TotalWords        uint64  `json:"total_words"`
	TotalDuration     time.Duration `json:"total_duration"`

	// Consistency and plausibility
	ConsistencyScore  float64 `json:"consistency_score"`
	LivenessScore     float64 `json:"liveness_score"` // Confidence it's live speech

	// Integrity
	ProfileHash       [32]byte `json:"profile_hash"`
}

// NewVoiceBiometrics creates a voice biometrics analyzer.
func NewVoiceBiometrics() *VoiceBiometrics {
	return &VoiceBiometrics{
		segments:        make([]SpeechSegment, 0, 500),
		maxSegments:     500,
		wordIntervals:   make([]time.Duration, 0, 1000),
		sentenceGaps:    make([]time.Duration, 0, 200),
		speakingBursts:  make([]time.Duration, 0, 200),
		wordsPerMinute:  make([]float64, 0, 200),
		confidenceScores: make([]float64, 0, 500),
		pitchSamples:    make([]float64, 0, 1000),
		energySamples:   make([]float64, 0, 1000),
	}
}

// RecordSegment records a speech segment from dictation.
func (vb *VoiceBiometrics) RecordSegment(segment SpeechSegment) {
	vb.mu.Lock()
	defer vb.mu.Unlock()

	// Hash the text (we don't store the actual text in evidence)
	segment.TextHash = sha256.Sum256([]byte(segment.Text))

	// Store segment
	if len(vb.segments) >= vb.maxSegments {
		vb.segments = vb.segments[vb.maxSegments/2:]
	}
	vb.segments = append(vb.segments, segment)

	// Update totals
	vb.totalWords += uint64(segment.WordCount)
	vb.totalCharacters += uint64(segment.CharCount)

	// Record confidence
	if segment.Confidence > 0 {
		vb.confidenceScores = append(vb.confidenceScores, segment.Confidence)
	}

	// Calculate WPM for this segment
	if segment.Duration > 0 && segment.WordCount > 0 {
		wpm := float64(segment.WordCount) / segment.Duration.Minutes()
		vb.wordsPerMinute = append(vb.wordsPerMinute, wpm)
	}

	// Calculate interval from previous segment
	if len(vb.segments) > 1 {
		prev := vb.segments[len(vb.segments)-2]
		gap := segment.Timestamp.Sub(prev.Timestamp.Add(prev.Duration))

		if gap > 0 && gap < 30*time.Second {
			// Classify as word pause or sentence pause
			if gap < 500*time.Millisecond {
				vb.wordIntervals = append(vb.wordIntervals, gap)
			} else {
				vb.sentenceGaps = append(vb.sentenceGaps, gap)
			}
		}

		// Track speaking bursts (consecutive speech without long pauses)
		if gap > 2*time.Second && segment.Duration > 0 {
			vb.speakingBursts = append(vb.speakingBursts, segment.Duration)
		}
	}

	// Trim arrays
	vb.trimArrays()
}

// RecordCorrection records when the user corrects a recognition error.
func (vb *VoiceBiometrics) RecordCorrection() {
	vb.mu.Lock()
	defer vb.mu.Unlock()
	vb.corrections++
}

// RecordProsody records prosodic features if available.
func (vb *VoiceBiometrics) RecordProsody(pitch, energy float64) {
	vb.mu.Lock()
	defer vb.mu.Unlock()

	if pitch > 0 {
		vb.pitchSamples = append(vb.pitchSamples, pitch)
		if len(vb.pitchSamples) > 1000 {
			vb.pitchSamples = vb.pitchSamples[500:]
		}
	}

	if energy > 0 {
		vb.energySamples = append(vb.energySamples, energy)
		if len(vb.energySamples) > 1000 {
			vb.energySamples = vb.energySamples[500:]
		}
	}
}

// trimArrays limits array sizes.
func (vb *VoiceBiometrics) trimArrays() {
	if len(vb.wordIntervals) > 1000 {
		vb.wordIntervals = vb.wordIntervals[500:]
	}
	if len(vb.sentenceGaps) > 200 {
		vb.sentenceGaps = vb.sentenceGaps[100:]
	}
	if len(vb.speakingBursts) > 200 {
		vb.speakingBursts = vb.speakingBursts[100:]
	}
	if len(vb.wordsPerMinute) > 200 {
		vb.wordsPerMinute = vb.wordsPerMinute[100:]
	}
	if len(vb.confidenceScores) > 500 {
		vb.confidenceScores = vb.confidenceScores[250:]
	}
}

// Profile computes the current voice biometric profile.
func (vb *VoiceBiometrics) Profile() VoiceProfile {
	vb.mu.RLock()
	defer vb.mu.RUnlock()

	profile := VoiceProfile{
		TotalSegments: uint64(len(vb.segments)),
		TotalWords:    vb.totalWords,
	}

	// Calculate total duration
	for _, seg := range vb.segments {
		profile.TotalDuration += seg.Duration
	}

	// WPM statistics
	if len(vb.wordsPerMinute) > 0 {
		profile.MeanWPM = mean(vb.wordsPerMinute)
		profile.StdDevWPM = stddev(vb.wordsPerMinute)
		profile.MinWPM = minVal(vb.wordsPerMinute)
		profile.MaxWPM = maxVal(vb.wordsPerMinute)
	}

	// Pause statistics
	if len(vb.wordIntervals) > 0 {
		profile.MeanWordPause = meanDuration(vb.wordIntervals)
		profile.StdDevWordPause = stddevDuration(vb.wordIntervals)
	}
	if len(vb.sentenceGaps) > 0 {
		profile.MeanSentencePause = meanDuration(vb.sentenceGaps)
		profile.StdDevSentencePause = stddevDuration(vb.sentenceGaps)
	}

	// Burst statistics
	if len(vb.speakingBursts) > 0 {
		profile.MeanBurstDuration = meanDuration(vb.speakingBursts)
		profile.StdDevBurstDuration = stddevDuration(vb.speakingBursts)
	}

	// Prosody statistics
	if len(vb.pitchSamples) > 0 {
		profile.MeanPitch = mean(vb.pitchSamples)
		profile.StdDevPitch = stddev(vb.pitchSamples)
	}
	if len(vb.energySamples) > 0 {
		profile.MeanEnergy = mean(vb.energySamples)
		profile.StdDevEnergy = stddev(vb.energySamples)
	}

	// Recognition statistics
	if len(vb.confidenceScores) > 0 {
		profile.MeanConfidence = mean(vb.confidenceScores)
	}
	if vb.totalWords > 0 {
		profile.CorrectionRate = float64(vb.corrections) / float64(vb.totalWords) * 100
	}

	// Compute scores
	profile.ConsistencyScore = vb.computeConsistency(profile)
	profile.LivenessScore = vb.computeLiveness(profile)

	// Hash the profile
	profile.ProfileHash = vb.hashProfile(profile)

	return profile
}

// computeConsistency calculates how consistent the speech patterns are.
func (vb *VoiceBiometrics) computeConsistency(profile VoiceProfile) float64 {
	var scores []float64

	// WPM consistency
	if profile.MeanWPM > 0 {
		wpmCV := profile.StdDevWPM / profile.MeanWPM
		scores = append(scores, 1.0/(1.0+wpmCV))
	}

	// Pause consistency
	if profile.MeanWordPause > 0 {
		pauseCV := profile.StdDevWordPause / profile.MeanWordPause
		scores = append(scores, 1.0/(1.0+pauseCV))
	}

	// Pitch consistency (if available)
	if profile.MeanPitch > 0 {
		pitchCV := profile.StdDevPitch / profile.MeanPitch
		scores = append(scores, 1.0/(1.0+pitchCV))
	}

	if len(scores) == 0 {
		return 0.5
	}

	return mean(scores)
}

// computeLiveness estimates confidence that this is live speech (not pre-recorded).
func (vb *VoiceBiometrics) computeLiveness(profile VoiceProfile) float64 {
	score := 0.5 // Neutral starting point

	// Natural variation in WPM suggests live speech
	if profile.MeanWPM > 0 {
		wpmRange := profile.MaxWPM - profile.MinWPM
		expectedRange := profile.MeanWPM * 0.3 // ~30% variation expected
		if wpmRange >= expectedRange*0.5 && wpmRange <= expectedRange*2 {
			score += 0.15
		}
	}

	// Pause patterns indicate real-time thinking
	if profile.MeanWordPause > 100 && profile.MeanWordPause < 500 {
		score += 0.1
	}
	if profile.StdDevWordPause > 50 { // Some variation in pauses
		score += 0.1
	}

	// Pitch variation (monotone = suspicious)
	if profile.StdDevPitch > 10 { // Hz variation
		score += 0.1
	}

	// Not too perfect confidence (real speech has recognition errors)
	if profile.MeanConfidence > 0.7 && profile.MeanConfidence < 0.98 {
		score += 0.05
	}

	// Limit to 0-1
	if score > 1.0 {
		score = 1.0
	}
	if score < 0 {
		score = 0
	}

	return score
}

// hashProfile creates an integrity hash of the profile.
func (vb *VoiceBiometrics) hashProfile(profile VoiceProfile) [32]byte {
	h := sha256.New()
	h.Write([]byte("witnessd-voice-profile-v1"))

	binary.Write(h, binary.BigEndian, profile.MeanWPM)
	binary.Write(h, binary.BigEndian, profile.MeanWordPause)
	binary.Write(h, binary.BigEndian, profile.MeanPitch)
	binary.Write(h, binary.BigEndian, profile.TotalWords)
	binary.Write(h, binary.BigEndian, int64(profile.TotalDuration))

	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// IsHumanPlausible checks if the voice profile appears to be from a human.
func (profile VoiceProfile) IsHumanPlausible() bool {
	// Check for minimum data
	if profile.TotalWords < 20 {
		return true // Not enough data
	}

	// Human WPM typically 100-180 for conversational speech
	if profile.MeanWPM > 0 {
		if profile.MeanWPM < 60 || profile.MeanWPM > 250 {
			return false // Too slow or too fast
		}
	}

	// Some variation expected
	if profile.ConsistencyScore > 0.99 {
		return false // Robotic consistency
	}

	// Liveness check
	if profile.LivenessScore < 0.3 {
		return false // Likely pre-recorded
	}

	// Natural pause patterns
	if profile.MeanWordPause > 0 {
		// Pauses too short = machine, too long = not natural dictation
		if profile.MeanWordPause < 20 || profile.MeanWordPause > 1000 {
			return false
		}
	}

	return true
}

// SpeechToTextEvent represents an event from speech recognition.
type SpeechToTextEvent struct {
	Timestamp    time.Time
	Text         string
	IsFinal      bool
	Confidence   float64
	Alternatives []string
	AudioDuration time.Duration
}

// DictationSession wraps voice biometrics with session management.
type DictationSession struct {
	mu sync.RWMutex

	id          string
	startTime   time.Time
	endTime     time.Time
	biometrics  *VoiceBiometrics

	// Document integration
	documentPath string
	charsBefore  int64 // Document size before dictation
	charsAdded   int64 // Characters added via dictation

	running     bool
}

// NewDictationSession creates a dictation tracking session.
func NewDictationSession(id, documentPath string) *DictationSession {
	return &DictationSession{
		id:           id,
		startTime:    time.Now(),
		documentPath: documentPath,
		biometrics:   NewVoiceBiometrics(),
	}
}

// RecordSpeech records a speech-to-text result.
func (ds *DictationSession) RecordSpeech(event SpeechToTextEvent) {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	wordCount := countWords(event.Text)
	charCount := len(event.Text)

	segment := SpeechSegment{
		Timestamp:  event.Timestamp,
		Duration:   event.AudioDuration,
		Text:       event.Text,
		WordCount:  wordCount,
		CharCount:  charCount,
		Confidence: event.Confidence,
		IsFinal:    event.IsFinal,
	}

	ds.biometrics.RecordSegment(segment)

	if event.IsFinal {
		ds.charsAdded += int64(charCount)
	}
}

// Profile returns the current voice biometric profile.
func (ds *DictationSession) Profile() VoiceProfile {
	return ds.biometrics.Profile()
}

// countWords counts words in a string.
func countWords(s string) int {
	if len(s) == 0 {
		return 0
	}
	count := 0
	inWord := false
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			inWord = false
		} else if !inWord {
			inWord = true
			count++
		}
	}
	return count
}
