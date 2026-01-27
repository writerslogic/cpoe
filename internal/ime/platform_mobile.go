package ime

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Mobile platform support via gomobile.
//
// Android: The Go code is compiled to an AAR library using gomobile bind.
// The Kotlin/Java InputMethodService wraps the Go Engine.
//
// iOS: The Go code is compiled to an xcframework using gomobile bind.
// The Swift UIInputViewController wraps the Go Engine.
//
// Build commands:
//   gomobile bind -target=android -o witnessd.aar ./internal/ime
//   gomobile bind -target=ios -o Witnessd.xcframework ./internal/ime

// MobileEngine wraps Engine for gomobile export.
// gomobile has limitations on what types can be exported, so we provide
// a simplified interface here.
type MobileEngine struct {
	engine *Engine
}

// NewMobileEngine creates a new engine for mobile platforms.
// This is the main entry point for Android/iOS.
func NewMobileEngine() *MobileEngine {
	return &MobileEngine{
		engine: NewEngine(),
	}
}

// StartSession begins a witnessing session.
// appID: Bundle ID (iOS) or package name (Android)
// docID: Document identifier (URL, file path, or field ID)
// context: Optional user-provided context
func (m *MobileEngine) StartSession(appID, docID, context string) error {
	return m.engine.StartSession(SessionOptions{
		AppID:   appID,
		DocID:   docID,
		Context: context,
	})
}

// OnKeyDown processes a key press.
// char: The character typed (Unicode code point)
// Returns the jitter delay in microseconds.
func (m *MobileEngine) OnKeyDown(char int32) (int64, error) {
	delay, err := m.engine.OnKeyDown(NewKey(rune(char)))
	if err != nil {
		return 0, err
	}
	return delay.Microseconds(), nil
}

// OnKeyDownWithZone processes a key press with explicit zone.
// zone: Keyboard zone (0-7), or -1 if unknown
// char: The character typed
// Returns the jitter delay in microseconds.
func (m *MobileEngine) OnKeyDownWithZone(zone int, char int32) (int64, error) {
	delay, err := m.engine.OnKeyDown(NewKeyWithZone(rune(char), zone))
	if err != nil {
		return 0, err
	}
	return delay.Microseconds(), nil
}

// OnKeyDownWithPosition processes a key press with touch position.
// x, y: Normalized touch position (0.0-1.0) on keyboard
// char: The character typed
// Returns the jitter delay in microseconds.
func (m *MobileEngine) OnKeyDownWithPosition(x, y float32, char int32) (int64, error) {
	zone := ZoneFromPosition(x, y)
	delay, err := m.engine.OnKeyDown(NewKeyWithZone(rune(char), zone))
	if err != nil {
		return 0, err
	}
	return delay.Microseconds(), nil
}

// OnTextCommit records committed text.
func (m *MobileEngine) OnTextCommit(text string) error {
	return m.engine.OnTextCommit(text)
}

// OnTextDelete records deleted text (rune count).
func (m *MobileEngine) OnTextDelete(count int) error {
	return m.engine.OnTextDelete(count)
}

// GetSampleCount returns the number of samples collected.
func (m *MobileEngine) GetSampleCount() int {
	return m.engine.GetSampleCount()
}

// HasActiveSession returns true if a session is active.
func (m *MobileEngine) HasActiveSession() bool {
	return m.engine.HasActiveSession()
}

// EndSession ends the session and returns JSON-encoded evidence summary.
func (m *MobileEngine) EndSession() (string, error) {
	evidence, err := m.engine.EndSession()
	if err != nil {
		return "", err
	}
	return encodeEvidenceJSON(evidence)
}

// EndSessionFull ends the session and returns complete JSON-encoded evidence.
func (m *MobileEngine) EndSessionFull() (string, error) {
	evidence, err := m.engine.EndSession()
	if err != nil {
		return "", err
	}
	return evidence.ToJSON()
}

// GetSessionInfo returns JSON-encoded session information.
func (m *MobileEngine) GetSessionInfo() string {
	info := m.engine.GetSessionInfo()
	if info == nil {
		return ""
	}

	data, err := json.Marshal(map[string]interface{}{
		"id":           info.ID,
		"start_time":   info.StartTime.Format("2006-01-02T15:04:05.000Z"),
		"app_id":       info.AppID,
		"doc_id":       info.DocID,
		"context":      info.Context,
		"sample_count": info.SampleCount,
		"doc_length":   info.DocLength,
	})
	if err != nil {
		return ""
	}
	return string(data)
}

// GetProfile returns JSON-encoded typing profile.
func (m *MobileEngine) GetProfile() string {
	profile := m.engine.GetProfile()

	data, err := json.Marshal(map[string]interface{}{
		"hand_alternation":   profile.HandAlternation,
		"total_transitions":  profile.TotalTransitions,
		"same_finger_hist":   profile.SameFingerHist,
		"same_hand_hist":     profile.SameHandHist,
		"alternating_hist":   profile.AlternatingHist,
	})
	if err != nil {
		return "{}"
	}
	return string(data)
}

// mobileEvidence is a JSON-friendly version of Evidence for mobile platforms.
// Uses hex strings for byte arrays since gomobile doesn't support [32]byte.
type mobileEvidence struct {
	SessionID         string        `json:"session_id"`
	StartTime         string        `json:"start_time"`
	EndTime           string        `json:"end_time"`
	AppID             string        `json:"app_id"`
	DocID             string        `json:"doc_id"`
	Context           string        `json:"context,omitempty"`
	FinalHash         string        `json:"final_hash"`
	TotalKeystrokes   uint64        `json:"total_keystrokes"`
	DocumentEvolution int           `json:"document_evolution"`
	TypingRateKPM     float64       `json:"typing_rate_kpm"`
	SampleCount       int           `json:"sample_count"`
	Profile           mobileProfile `json:"profile"`
}

type mobileProfile struct {
	HandAlternation  float32 `json:"hand_alternation"`
	TotalTransitions uint64  `json:"total_transitions"`
}

// encodeEvidenceJSON converts evidence to JSON string for mobile.
func encodeEvidenceJSON(e *Evidence) (string, error) {
	me := mobileEvidence{
		SessionID:         e.SessionID,
		StartTime:         e.StartTime.Format("2006-01-02T15:04:05.000Z"),
		EndTime:           e.EndTime.Format("2006-01-02T15:04:05.000Z"),
		AppID:             e.AppID,
		DocID:             e.DocID,
		Context:           e.Context,
		FinalHash:         hex.EncodeToString(e.FinalHash[:]),
		TotalKeystrokes:   e.TotalKeystrokes,
		DocumentEvolution: e.DocumentEvolution,
		TypingRateKPM:     e.TypingRateKPM,
		SampleCount:       len(e.Samples),
		Profile: mobileProfile{
			HandAlternation:  e.Profile.HandAlternation,
			TotalTransitions: e.Profile.TotalTransitions,
		},
	}

	data, err := json.Marshal(me)
	if err != nil {
		return "", fmt.Errorf("failed to encode evidence: %w", err)
	}
	return string(data), nil
}

// MobileZoneMapping provides zone mapping for mobile touch keyboards.
// On mobile, we typically get characters, not keycodes.
type MobileZoneMapping struct{}

// CharToZone maps a character to keyboard zone.
// Mobile keyboards don't have fixed physical positions like desktop,
// but we can still use the standard QWERTY zone model since most
// mobile keyboards use QWERTY layout.
func (MobileZoneMapping) CharToZone(char rune) int {
	return zoneFromChar(char)
}

// KeyCodeToZone is not typically used on mobile.
// Characters are preferred since mobile keycodes vary by device/keyboard app.
func (MobileZoneMapping) KeyCodeToZone(keyCode uint16) int {
	return -1 // Use CharToZone instead
}

// ZoneFromPosition estimates zone from keyboard position.
// This is approximate since keyboard layouts vary.
// x: horizontal position (0.0 = left edge, 1.0 = right edge)
// y: vertical position (not currently used, but available for future enhancements)
func ZoneFromPosition(x, y float32) int {
	// Clamp x to valid range
	if x < 0 {
		x = 0
	}
	if x > 1 {
		x = 1
	}

	// Standard QWERTY layout zones based on x position
	// Assuming standard 10-key width per row
	col := int(x * 10)

	switch {
	case col <= 0:
		return 0 // Left pinky (Q/A/Z area)
	case col == 1:
		return 1 // Left ring (W/S/X area)
	case col == 2:
		return 2 // Left middle (E/D/C area)
	case col == 3 || col == 4:
		return 3 // Left index (R/T/F/G/V/B area)
	case col == 5 || col == 6:
		return 4 // Right index (Y/U/H/J/N/M area)
	case col == 7:
		return 5 // Right middle (I/K/, area)
	case col == 8:
		return 6 // Right ring (O/L/. area)
	default:
		return 7 // Right pinky (P/;// area)
	}
}
