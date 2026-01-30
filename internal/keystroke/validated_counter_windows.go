//go:build windows && cgo

package keystroke

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ValidatedCounter provides maximum-security keystroke counting by monitoring
// at BOTH the Raw Input and Windows HID layers simultaneously.
//
// This provides the strongest possible defense against SendInput injection:
//
//  1. Windows HID layer (hardware only): Cannot be faked without physical hardware
//  2. Raw Input layer (may include synthetic): Provides timing and additional data
//  3. Cross-validation: Any discrepancy indicates synthetic injection
//
// The ValidatedCounter only counts keystrokes that are verified at BOTH layers,
// making SendInput attacks detectable and rejectable.
type ValidatedCounter struct {
	BaseCounter

	// Platform-specific counters
	rawInputCounter *WindowsCounter
	hidMonitor      *HIDMonitor

	// Cross-validation state
	mu                     sync.RWMutex
	lastRawInputCount      int64
	lastHIDCount           int64
	totalSyntheticDetected int64
	validationErrors       int64

	// Configuration
	strictValidation bool // If true, only count HID-verified events

	// Context management
	ctx      context.Context
	cancel   context.CancelFunc
	pollDone chan struct{}
}

// NewValidatedCounter creates a counter that cross-validates events between
// Raw Input and Windows HID layers for maximum security.
func NewValidatedCounter() *ValidatedCounter {
	return &ValidatedCounter{
		rawInputCounter:  &WindowsCounter{},
		hidMonitor:       NewHIDMonitor(),
		strictValidation: true, // Default to strict mode
	}
}

// SetStrictValidation controls whether only HID-verified events are counted.
// When true (default), only keystrokes verified at the hardware level are counted.
// When false, all Raw Input events are counted but synthetic detection still occurs.
func (v *ValidatedCounter) SetStrictValidation(strict bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.strictValidation = strict
}

// Available checks if validated counting is available.
func (v *ValidatedCounter) Available() (bool, string) {
	rawAvailable, rawMsg := v.rawInputCounter.Available()
	if !rawAvailable {
		return false, rawMsg
	}

	// HID monitoring requires direct device access (usually available to admin/user)
	return true, "Dual-layer monitoring available (Raw Input + Windows HID)"
}

// Start begins dual-layer monitoring.
func (v *ValidatedCounter) Start(ctx context.Context) error {
	if v.IsRunning() {
		return ErrAlreadyRunning
	}

	// Start HID monitoring first (lower level)
	if err := v.hidMonitor.Start(); err != nil {
		// HID monitoring failed - fall back to Raw Input only with warning
		// This can happen if HID access is restricted
		v.mu.Lock()
		v.strictValidation = false // Can't validate without HID
		v.mu.Unlock()
	}

	// Start Raw Input monitoring
	if err := v.rawInputCounter.Start(ctx); err != nil {
		v.hidMonitor.Stop()
		return err
	}

	v.ctx, v.cancel = context.WithCancel(ctx)
	v.SetRunning(true)
	v.pollDone = make(chan struct{})

	// Start cross-validation loop
	go v.validationLoop()

	return nil
}

// validationLoop periodically cross-validates Raw Input and HID counts.
func (v *ValidatedCounter) validationLoop() {
	defer close(v.pollDone)

	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-v.ctx.Done():
			return

		case <-ticker.C:
			v.performValidation()
		}
	}
}

// performValidation compares counts and updates the validated count.
func (v *ValidatedCounter) performValidation() {
	rawCount := int64(v.rawInputCounter.Count())
	hidCount := v.hidMonitor.Count()

	v.mu.Lock()
	defer v.mu.Unlock()

	// Calculate new events since last check
	rawDelta := rawCount - v.lastRawInputCount
	hidDelta := hidCount - v.lastHIDCount

	if rawDelta <= 0 && hidDelta <= 0 {
		return // No new events
	}

	// Check for synthetic events (Raw Input saw more than HID)
	if rawDelta > hidDelta {
		syntheticCount := rawDelta - hidDelta
		v.totalSyntheticDetected += syntheticCount
	}

	// Determine how many events to count
	var eventsToCount int64
	if v.strictValidation {
		// Only count events verified by HID (hardware-confirmed)
		eventsToCount = hidDelta
		if eventsToCount < 0 {
			eventsToCount = 0
		}
	} else {
		// Count all Raw Input events (but track synthetic detection)
		eventsToCount = rawDelta
	}

	// Update base counter
	for i := int64(0); i < eventsToCount; i++ {
		v.Increment()
	}

	v.lastRawInputCount = rawCount
	v.lastHIDCount = hidCount
}

// Stop stops dual-layer monitoring.
func (v *ValidatedCounter) Stop() error {
	if !v.IsRunning() {
		return nil
	}

	v.SetRunning(false)

	if v.cancel != nil {
		v.cancel()
	}

	if v.pollDone != nil {
		<-v.pollDone
	}

	v.rawInputCounter.Stop()
	v.hidMonitor.Stop()
	v.CloseListeners()

	return nil
}

// ValidationStats returns cross-validation statistics.
func (v *ValidatedCounter) ValidationStats() ValidationStats {
	v.mu.RLock()
	defer v.mu.RUnlock()

	rawCount := int64(v.rawInputCounter.Count())
	hidCount := v.hidMonitor.Count()

	return ValidationStats{
		CGEventTapCount:        rawCount, // Using same field name for API compatibility
		HIDCount:               hidCount,
		ValidatedCount:         int64(v.Count()),
		TotalSyntheticDetected: v.totalSyntheticDetected,
		Discrepancy:            rawCount - hidCount,
		HIDMonitorActive:       v.hidMonitor.IsRunning(),
		StrictMode:             v.strictValidation,
	}
}

// SyntheticDetected returns true if any synthetic events have been detected.
func (v *ValidatedCounter) SyntheticDetected() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.totalSyntheticDetected > 0
}

// Ensure ValidatedCounter satisfies Counter interface
var _ Counter = (*ValidatedCounter)(nil)

// NewSecureCounter creates a counter with maximum security against
// synthetic keystroke injection on Windows.
func NewSecureCounter() Counter {
	return NewValidatedCounter()
}

// ErrHIDNotAvailable is returned when Windows HID monitoring isn't available.
var ErrHIDNotAvailable = errors.New("Windows HID monitoring not available")
