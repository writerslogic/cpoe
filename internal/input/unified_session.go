//go:build darwin || linux || windows

package input

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"sync"
	"time"
)

// UnifiedInputSession tracks all input methods with security verification.
// This provides a single interface for keyboard, touch, and voice input,
// with cross-method validation and combined biometric analysis.
type UnifiedInputSession struct {
	mu sync.RWMutex

	// Session identity
	ID           string    `json:"id"`
	StartTime    time.Time `json:"start_time"`
	EndTime      time.Time `json:"end_time,omitempty"`
	DocumentPath string    `json:"document_path"`

	// Input method trackers
	keyboard *KeyboardTracker
	touch    *TouchBiometrics
	voice    *VoiceBiometrics

	// Cross-method correlation
	inputEvents []UnifiedInputEvent

	// Document state
	lastDocSize int64
	lastDocHash [32]byte

	// Aggregate statistics
	stats UnifiedStats

	// Running state
	running bool
}

// UnifiedInputEvent represents any input event with unified metadata.
type UnifiedInputEvent struct {
	Timestamp   time.Time       `json:"timestamp"`
	Method      InputMethod     `json:"method"`
	CharCount   int             `json:"char_count"`
	WordCount   int             `json:"word_count,omitempty"`
	Duration    time.Duration   `json:"duration,omitempty"`
	Confidence  float64         `json:"confidence,omitempty"` // For voice/touch
	DocHashAfter [32]byte       `json:"doc_hash_after"`
	Verified    bool            `json:"verified"` // Content verified in document
}

// InputMethod identifies how input was generated.
type InputMethod int

const (
	MethodKeyboard InputMethod = iota
	MethodTouch
	MethodVoice
	MethodPaste
	MethodUnknown
)

func (m InputMethod) String() string {
	switch m {
	case MethodKeyboard:
		return "keyboard"
	case MethodTouch:
		return "touch"
	case MethodVoice:
		return "voice"
	case MethodPaste:
		return "paste"
	default:
		return "unknown"
	}
}

// UnifiedStats tracks statistics across all input methods.
type UnifiedStats struct {
	// Per-method counts
	KeyboardChars   uint64 `json:"keyboard_chars"`
	TouchChars      uint64 `json:"touch_chars"`
	VoiceChars      uint64 `json:"voice_chars"`
	PasteChars      uint64 `json:"paste_chars"`

	// Per-method time
	KeyboardTime    time.Duration `json:"keyboard_time"`
	TouchTime       time.Duration `json:"touch_time"`
	VoiceTime       time.Duration `json:"voice_time"`

	// Derived metrics
	TotalChars      uint64  `json:"total_chars"`
	KeyboardPercent float64 `json:"keyboard_percent"`
	TouchPercent    float64 `json:"touch_percent"`
	VoicePercent    float64 `json:"voice_percent"`
	PastePercent    float64 `json:"paste_percent"`

	// Cross-method correlation
	MethodSwitches  int     `json:"method_switches"` // Times user changed input method
	ConsistentUser  float64 `json:"consistent_user"` // Confidence it's same person across methods
}

// KeyboardTracker is a simplified keyboard tracker for the unified session.
type KeyboardTracker struct {
	totalChars uint64
	totalTime  time.Duration
	lastEvent  time.Time
}

// NewUnifiedInputSession creates a unified input tracking session.
func NewUnifiedInputSession(id, documentPath string) *UnifiedInputSession {
	return &UnifiedInputSession{
		ID:           id,
		StartTime:    time.Now(),
		DocumentPath: documentPath,
		keyboard:     &KeyboardTracker{},
		touch:        NewTouchBiometrics(),
		voice:        NewVoiceBiometrics(),
		inputEvents:  make([]UnifiedInputEvent, 0, 1000),
	}
}

// RecordKeyboard records keyboard input.
func (us *UnifiedInputSession) RecordKeyboard(charCount int, docHash [32]byte) {
	us.mu.Lock()
	defer us.mu.Unlock()

	now := time.Now()

	// Update keyboard tracker
	us.keyboard.totalChars += uint64(charCount)
	if !us.keyboard.lastEvent.IsZero() {
		us.keyboard.totalTime += now.Sub(us.keyboard.lastEvent)
	}
	us.keyboard.lastEvent = now

	// Record unified event
	event := UnifiedInputEvent{
		Timestamp:    now,
		Method:       MethodKeyboard,
		CharCount:    charCount,
		DocHashAfter: docHash,
		Verified:     true,
	}
	us.recordEvent(event)

	// Update stats
	us.stats.KeyboardChars += uint64(charCount)
}

// RecordTouch records touchscreen input.
func (us *UnifiedInputSession) RecordTouch(event TouchEvent, charCount int, docHash [32]byte) {
	us.mu.Lock()
	defer us.mu.Unlock()

	// Record in touch biometrics
	us.touch.RecordTouch(event)

	// Record unified event
	unified := UnifiedInputEvent{
		Timestamp:    event.Timestamp,
		Method:       MethodTouch,
		CharCount:    charCount,
		DocHashAfter: docHash,
		Confidence:   us.touch.Profile().ConsistencyScore,
		Verified:     true,
	}
	us.recordEvent(unified)

	// Update stats
	us.stats.TouchChars += uint64(charCount)
}

// RecordVoice records dictation input.
func (us *UnifiedInputSession) RecordVoice(segment SpeechSegment, docHash [32]byte) {
	us.mu.Lock()
	defer us.mu.Unlock()

	// Record in voice biometrics
	us.voice.RecordSegment(segment)

	// Record unified event
	event := UnifiedInputEvent{
		Timestamp:    segment.Timestamp,
		Method:       MethodVoice,
		CharCount:    segment.CharCount,
		WordCount:    segment.WordCount,
		Duration:     segment.Duration,
		Confidence:   segment.Confidence,
		DocHashAfter: docHash,
		Verified:     segment.IsFinal,
	}
	us.recordEvent(event)

	// Update stats
	us.stats.VoiceChars += uint64(segment.CharCount)
	us.stats.VoiceTime += segment.Duration
}

// RecordPaste records paste input.
func (us *UnifiedInputSession) RecordPaste(charCount int, docHash [32]byte) {
	us.mu.Lock()
	defer us.mu.Unlock()

	event := UnifiedInputEvent{
		Timestamp:    time.Now(),
		Method:       MethodPaste,
		CharCount:    charCount,
		DocHashAfter: docHash,
		Verified:     true,
	}
	us.recordEvent(event)

	// Update stats
	us.stats.PasteChars += uint64(charCount)
}

// recordEvent adds an event and checks for method switches.
func (us *UnifiedInputSession) recordEvent(event UnifiedInputEvent) {
	// Check for method switch
	if len(us.inputEvents) > 0 {
		lastMethod := us.inputEvents[len(us.inputEvents)-1].Method
		if lastMethod != event.Method {
			us.stats.MethodSwitches++
		}
	}

	// Store event (with size limit)
	if len(us.inputEvents) >= 1000 {
		us.inputEvents = us.inputEvents[500:]
	}
	us.inputEvents = append(us.inputEvents, event)

	// Update totals
	us.stats.TotalChars = us.stats.KeyboardChars + us.stats.TouchChars +
		us.stats.VoiceChars + us.stats.PasteChars

	// Update percentages
	if us.stats.TotalChars > 0 {
		total := float64(us.stats.TotalChars)
		us.stats.KeyboardPercent = float64(us.stats.KeyboardChars) / total * 100
		us.stats.TouchPercent = float64(us.stats.TouchChars) / total * 100
		us.stats.VoicePercent = float64(us.stats.VoiceChars) / total * 100
		us.stats.PastePercent = float64(us.stats.PasteChars) / total * 100
	}

	// Update document state
	us.lastDocHash = event.DocHashAfter
}

// Stats returns the current unified statistics.
func (us *UnifiedInputSession) Stats() UnifiedStats {
	us.mu.RLock()
	defer us.mu.RUnlock()

	// Compute cross-method consistency
	us.stats.ConsistentUser = us.computeCrossMethodConsistency()

	return us.stats
}

// computeCrossMethodConsistency checks if biometrics suggest same user across methods.
func (us *UnifiedInputSession) computeCrossMethodConsistency() float64 {
	var scores []float64

	// Touch consistency
	touchProfile := us.touch.Profile()
	if touchProfile.TotalTouches > 10 {
		scores = append(scores, touchProfile.ConsistencyScore)
	}

	// Voice consistency
	voiceProfile := us.voice.Profile()
	if voiceProfile.TotalWords > 20 {
		scores = append(scores, voiceProfile.ConsistencyScore)
		scores = append(scores, voiceProfile.LivenessScore)
	}

	if len(scores) == 0 {
		return 0.5 // Neutral if not enough data
	}

	return mean(scores)
}

// Export creates a complete evidence export.
func (us *UnifiedInputSession) Export() *UnifiedEvidence {
	us.mu.RLock()
	defer us.mu.RUnlock()

	evidence := &UnifiedEvidence{
		SessionID:     us.ID,
		DocumentPath:  us.DocumentPath,
		StartTime:     us.StartTime,
		EndTime:       us.EndTime,
		Stats:         us.stats,
		TouchProfile:  us.touch.Profile(),
		VoiceProfile:  us.voice.Profile(),
		InputSummary:  us.summarizeInputs(),
		FinalDocHash:  us.lastDocHash,
	}

	evidence.computeSignature()

	return evidence
}

// summarizeInputs creates a summary of input events.
func (us *UnifiedInputSession) summarizeInputs() []InputMethodSummary {
	summary := make(map[InputMethod]*InputMethodSummary)

	for _, event := range us.inputEvents {
		if summary[event.Method] == nil {
			summary[event.Method] = &InputMethodSummary{
				Method: event.Method.String(),
			}
		}
		s := summary[event.Method]
		s.EventCount++
		s.TotalChars += uint64(event.CharCount)
		s.TotalWords += uint64(event.WordCount)
		if event.Verified {
			s.VerifiedEvents++
		}
	}

	var result []InputMethodSummary
	for _, s := range summary {
		result = append(result, *s)
	}
	return result
}

// UnifiedEvidence is the complete evidence export.
type UnifiedEvidence struct {
	SessionID    string               `json:"session_id"`
	DocumentPath string               `json:"document_path"`
	StartTime    time.Time            `json:"start_time"`
	EndTime      time.Time            `json:"end_time"`
	Stats        UnifiedStats         `json:"stats"`
	TouchProfile TouchProfile         `json:"touch_profile,omitempty"`
	VoiceProfile VoiceProfile         `json:"voice_profile,omitempty"`
	InputSummary []InputMethodSummary `json:"input_summary"`
	FinalDocHash [32]byte             `json:"final_doc_hash"`
	Signature    [32]byte             `json:"signature"`
}

// InputMethodSummary summarizes input from one method.
type InputMethodSummary struct {
	Method         string `json:"method"`
	EventCount     int    `json:"event_count"`
	TotalChars     uint64 `json:"total_chars"`
	TotalWords     uint64 `json:"total_words,omitempty"`
	VerifiedEvents int    `json:"verified_events"`
}

// computeSignature creates an integrity signature for the evidence.
func (e *UnifiedEvidence) computeSignature() {
	h := sha256.New()
	h.Write([]byte("witnessd-unified-evidence-v1"))
	h.Write([]byte(e.SessionID))
	h.Write([]byte(e.DocumentPath))
	binary.Write(h, binary.BigEndian, e.StartTime.UnixNano())
	binary.Write(h, binary.BigEndian, e.EndTime.UnixNano())
	binary.Write(h, binary.BigEndian, e.Stats.TotalChars)
	h.Write(e.FinalDocHash[:])
	h.Write(e.TouchProfile.ProfileHash[:])
	h.Write(e.VoiceProfile.ProfileHash[:])

	copy(e.Signature[:], h.Sum(nil))
}

// IsHumanLikely returns true if the combined evidence suggests human authorship.
func (e *UnifiedEvidence) IsHumanLikely() bool {
	// Check touch profile if significant touch input
	if e.Stats.TouchChars > 100 {
		if !e.TouchProfile.IsHumanPlausible() {
			return false
		}
	}

	// Check voice profile if significant voice input
	if e.Stats.VoiceChars > 100 {
		if !e.VoiceProfile.IsHumanPlausible() {
			return false
		}
	}

	// Cross-method consistency should be reasonable
	if e.Stats.ConsistentUser < 0.2 {
		return false // Very inconsistent behavior across methods
	}

	// Some typing/input should have happened
	if e.Stats.TotalChars < 10 {
		return true // Not enough data to judge
	}

	// Very high paste percentage is suspicious
	if e.Stats.PastePercent > 90 {
		return false // Almost entirely pasted
	}

	return true
}

// SecurityScore returns a 0-100 score of how secure/trustworthy the evidence is.
func (e *UnifiedEvidence) SecurityScore() int {
	score := 50 // Base score

	// Touch biometrics add security
	if e.Stats.TouchChars > 50 && e.TouchProfile.IsHumanPlausible() {
		score += 15
		if e.TouchProfile.ConsistencyScore > 0.7 {
			score += 5
		}
	}

	// Voice biometrics add significant security (voice is hard to fake)
	if e.Stats.VoiceChars > 50 && e.VoiceProfile.IsHumanPlausible() {
		score += 20
		if e.VoiceProfile.LivenessScore > 0.7 {
			score += 10
		}
	}

	// Keyboard input (if we have that integration)
	if e.Stats.KeyboardChars > 50 {
		score += 10
	}

	// Cross-method consistency
	if e.Stats.ConsistentUser > 0.6 {
		score += 5
	}

	// Penalize high paste percentage
	if e.Stats.PastePercent > 50 {
		score -= 10
	}
	if e.Stats.PastePercent > 80 {
		score -= 20
	}

	// Clamp to 0-100
	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}

	return score
}

// JSON serializes the evidence.
func (e *UnifiedEvidence) JSON() ([]byte, error) {
	return json.MarshalIndent(e, "", "  ")
}
