//go:build darwin || linux || windows

// Package keystroke provides secure, tamper-evident keystroke counting and tracking.
package keystroke

import (
	"time"
)

// InputType categorizes different types of keyboard input.
type InputType int

const (
	InputTypeUnknown InputType = iota
	InputTypeCharacter         // Regular character keys (a-z, 0-9, symbols)
	InputTypeBackspace         // Backspace/Delete backward
	InputTypeDelete            // Delete forward
	InputTypeNavigation        // Arrow keys, Home, End, Page Up/Down
	InputTypeModifier          // Shift, Ctrl, Alt, Cmd
	InputTypeFunction          // F1-F12
	InputTypeReturn            // Enter/Return
	InputTypeTab               // Tab
	InputTypeEscape            // Escape
)

// InputSource indicates how the input was generated.
type InputSource int

const (
	InputSourceUnknown InputSource = iota
	InputSourceHardwareKeyboard    // Physical keyboard
	InputSourceVirtualKeyboard     // On-screen/touch keyboard
	InputSourceDictation           // Voice-to-text
	InputSourceIME                 // Input Method Editor composition
	InputSourcePaste               // Clipboard paste
	InputSourceAutocomplete        // System autocomplete/autocorrect
	InputSourceSynthetic           // Programmatically generated (CGEventPost, SendInput)
)

// InputEvent represents a single input event with full metadata.
type InputEvent struct {
	Timestamp   time.Time   `json:"timestamp"`
	Type        InputType   `json:"type"`
	Source      InputSource `json:"source"`
	KeyCode     uint16      `json:"key_code,omitempty"`
	Character   rune        `json:"character,omitempty"`
	IsRepeat    bool        `json:"is_repeat,omitempty"`
	Modifiers   Modifiers   `json:"modifiers,omitempty"`
	DeviceInfo  *DeviceInfo `json:"device_info,omitempty"`
}

// Modifiers tracks active modifier keys.
type Modifiers struct {
	Shift   bool `json:"shift,omitempty"`
	Control bool `json:"control,omitempty"`
	Alt     bool `json:"alt,omitempty"`
	Command bool `json:"command,omitempty"` // macOS Cmd, Windows Win key
	CapsLock bool `json:"caps_lock,omitempty"`
}

// DeviceInfo contains information about the input device.
type DeviceInfo struct {
	VendorID     uint16 `json:"vendor_id,omitempty"`
	ProductID    uint16 `json:"product_id,omitempty"`
	DeviceName   string `json:"device_name,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
	ConnectionType string `json:"connection_type,omitempty"` // "usb", "bluetooth", "internal"
}

// InputStats tracks statistics about different input types.
type InputStats struct {
	// Counts by type
	CharacterCount   uint64 `json:"character_count"`
	BackspaceCount   uint64 `json:"backspace_count"`
	DeleteCount      uint64 `json:"delete_count"`
	NavigationCount  uint64 `json:"navigation_count"`
	ReturnCount      uint64 `json:"return_count"`
	TabCount         uint64 `json:"tab_count"`
	FunctionCount    uint64 `json:"function_count"`

	// Counts by source
	HardwareCount    uint64 `json:"hardware_count"`
	VirtualCount     uint64 `json:"virtual_count"`
	DictationCount   uint64 `json:"dictation_count"`
	PasteCount       uint64 `json:"paste_count"`
	SyntheticCount   uint64 `json:"synthetic_count"`

	// Derived metrics
	EditRatio        float64 `json:"edit_ratio"` // (backspace+delete) / total
	DictationRatio   float64 `json:"dictation_ratio"`
}

// InputTracker tracks input events and maintains statistics.
type InputTracker struct {
	events []InputEvent
	stats  InputStats
	maxEvents int
}

// NewInputTracker creates an input tracker.
func NewInputTracker(maxEvents int) *InputTracker {
	if maxEvents <= 0 {
		maxEvents = 10000
	}
	return &InputTracker{
		events:    make([]InputEvent, 0, maxEvents),
		maxEvents: maxEvents,
	}
}

// Record records an input event.
func (it *InputTracker) Record(event InputEvent) {
	// Update stats
	it.updateStats(event)

	// Store event (with size limit)
	if len(it.events) >= it.maxEvents {
		// Remove oldest events
		it.events = it.events[len(it.events)/2:]
	}
	it.events = append(it.events, event)
}

// updateStats updates statistics based on an event.
func (it *InputTracker) updateStats(event InputEvent) {
	// Count by type
	switch event.Type {
	case InputTypeCharacter:
		it.stats.CharacterCount++
	case InputTypeBackspace:
		it.stats.BackspaceCount++
	case InputTypeDelete:
		it.stats.DeleteCount++
	case InputTypeNavigation:
		it.stats.NavigationCount++
	case InputTypeReturn:
		it.stats.ReturnCount++
	case InputTypeTab:
		it.stats.TabCount++
	case InputTypeFunction:
		it.stats.FunctionCount++
	}

	// Count by source
	switch event.Source {
	case InputSourceHardwareKeyboard:
		it.stats.HardwareCount++
	case InputSourceVirtualKeyboard:
		it.stats.VirtualCount++
	case InputSourceDictation:
		it.stats.DictationCount++
	case InputSourcePaste:
		it.stats.PasteCount++
	case InputSourceSynthetic:
		it.stats.SyntheticCount++
	}

	// Update ratios
	total := it.stats.CharacterCount + it.stats.BackspaceCount + it.stats.DeleteCount
	if total > 0 {
		it.stats.EditRatio = float64(it.stats.BackspaceCount+it.stats.DeleteCount) / float64(total)
	}

	allInput := it.stats.HardwareCount + it.stats.VirtualCount + it.stats.DictationCount + it.stats.PasteCount
	if allInput > 0 {
		it.stats.DictationRatio = float64(it.stats.DictationCount) / float64(allInput)
	}
}

// Stats returns the current input statistics.
func (it *InputTracker) Stats() InputStats {
	return it.stats
}

// RecentEvents returns events from the last duration.
func (it *InputTracker) RecentEvents(d time.Duration) []InputEvent {
	cutoff := time.Now().Add(-d)
	var recent []InputEvent
	for i := len(it.events) - 1; i >= 0; i-- {
		if it.events[i].Timestamp.Before(cutoff) {
			break
		}
		recent = append([]InputEvent{it.events[i]}, recent...)
	}
	return recent
}

// ClassifyKeyCode converts a key code to an InputType.
// Platform-specific implementations should call this with their key codes.
func ClassifyKeyCode(keyCode uint16) InputType {
	// Common key codes across platforms (approximate)
	// macOS key codes
	switch keyCode {
	case 51: // macOS backspace
		return InputTypeBackspace
	case 117: // macOS forward delete
		return InputTypeDelete
	case 36, 76: // macOS return, keypad enter
		return InputTypeReturn
	case 48: // macOS tab
		return InputTypeTab
	case 53: // macOS escape
		return InputTypeEscape
	case 123, 124, 125, 126, 115, 116, 119, 121: // arrows, home, end, page up/down
		return InputTypeNavigation
	case 56, 57, 58, 59, 55, 54, 63: // shift, caps, option, control, cmd, right cmd, fn
		return InputTypeModifier
	case 122, 120, 99, 118, 96, 97, 98, 100, 101, 109, 103, 111: // F1-F12
		return InputTypeFunction
	default:
		return InputTypeCharacter
	}
}

// DictationDetector detects potential dictation input.
type DictationDetector struct {
	// Thresholds
	minBurstSize        int           // Minimum characters for a "burst"
	maxBurstInterval    time.Duration // Max time between burst chars
	dictationBurstRatio float64       // Chars/second that suggests dictation

	// State
	lastCharTime   time.Time
	burstStartTime time.Time
	burstCharCount int
	inBurst        bool
}

// NewDictationDetector creates a dictation detector.
func NewDictationDetector() *DictationDetector {
	return &DictationDetector{
		minBurstSize:        20,               // 20+ chars in quick succession
		maxBurstInterval:    100 * time.Millisecond, // <100ms between chars
		dictationBurstRatio: 15.0,             // >15 chars/sec suggests dictation
	}
}

// OnCharacter processes a character input and returns true if it looks like dictation.
func (dd *DictationDetector) OnCharacter(now time.Time) bool {
	if dd.lastCharTime.IsZero() {
		dd.lastCharTime = now
		dd.burstStartTime = now
		dd.burstCharCount = 1
		dd.inBurst = true
		return false
	}

	interval := now.Sub(dd.lastCharTime)
	dd.lastCharTime = now

	if interval <= dd.maxBurstInterval {
		// Continue burst
		if !dd.inBurst {
			dd.burstStartTime = now
			dd.burstCharCount = 0
		}
		dd.inBurst = true
		dd.burstCharCount++

		// Check if burst looks like dictation
		if dd.burstCharCount >= dd.minBurstSize {
			burstDuration := now.Sub(dd.burstStartTime).Seconds()
			if burstDuration > 0 {
				charsPerSecond := float64(dd.burstCharCount) / burstDuration
				if charsPerSecond >= dd.dictationBurstRatio {
					return true // Looks like dictation
				}
			}
		}
	} else {
		// Burst ended
		dd.inBurst = false
		dd.burstCharCount = 1
		dd.burstStartTime = now
	}

	return false
}

// Reset resets the detector state.
func (dd *DictationDetector) Reset() {
	dd.lastCharTime = time.Time{}
	dd.burstStartTime = time.Time{}
	dd.burstCharCount = 0
	dd.inBurst = false
}
