//go:build linux

package keystroke

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ValidatedCounter provides security-enhanced keystroke counting by monitoring
// at multiple layers when possible.
//
// On Linux, this provides defense against synthetic injection via:
// - uinput (virtual input device)
// - xdotool/ydotool (X11/Wayland injection)
// - evemu (event replay)
//
// When hidraw access is available:
//  1. HID layer (hardware only): /dev/hidrawX - raw HID reports
//  2. Input layer (may include synthetic): /dev/input/eventX
//  3. Cross-validation: Compare counts to detect injection
//
// When hidraw isn't available, we use heuristics to identify physical devices.
type ValidatedCounter struct {
	BaseCounter

	// Platform-specific counters
	inputCounter *LinuxCounter
	hidMonitor   *HIDMonitor

	// Cross-validation state
	mu                     sync.RWMutex
	lastInputCount         int64
	lastHIDCount           int64
	totalSyntheticDetected int64
	validationErrors       int64

	// Configuration
	strictValidation bool // If true, only count HID-verified events
	hidAvailable     bool // Whether HID monitoring is active

	// Context management
	ctx      context.Context
	cancel   context.CancelFunc
	pollDone chan struct{}
}

// NewValidatedCounter creates a counter that cross-validates events between
// input and HID layers for enhanced security.
func NewValidatedCounter() *ValidatedCounter {
	return &ValidatedCounter{
		inputCounter:     &LinuxCounter{},
		hidMonitor:       NewHIDMonitor(),
		strictValidation: true, // Default to strict mode
	}
}

// SetStrictValidation controls whether only HID-verified events are counted.
// When true (default), only keystrokes verified at the hardware level are counted.
// When false, all input events are counted but synthetic detection still occurs.
func (v *ValidatedCounter) SetStrictValidation(strict bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.strictValidation = strict
}

// Available checks if validated counting is available.
func (v *ValidatedCounter) Available() (bool, string) {
	inputAvailable, inputMsg := v.inputCounter.Available()
	if !inputAvailable {
		return false, inputMsg
	}

	// Check if HID monitoring is available
	// This requires access to /dev/hidraw* devices
	return true, "Linux input monitoring available (hidraw optional for cross-validation)"
}

// Start begins dual-layer monitoring when possible.
func (v *ValidatedCounter) Start(ctx context.Context) error {
	if v.IsRunning() {
		return ErrAlreadyRunning
	}

	// Try to start HID monitoring (may fail if no access to hidraw)
	if err := v.hidMonitor.Start(); err != nil {
		// HID monitoring failed - use input-only with physical device filter
		v.mu.Lock()
		v.hidAvailable = false
		v.strictValidation = false // Can't validate without HID
		v.mu.Unlock()
	} else {
		v.mu.Lock()
		v.hidAvailable = true
		v.mu.Unlock()
	}

	// Start input monitoring
	if err := v.inputCounter.Start(ctx); err != nil {
		if v.hidAvailable {
			v.hidMonitor.Stop()
		}
		return err
	}

	v.ctx, v.cancel = context.WithCancel(ctx)
	v.SetRunning(true)
	v.pollDone = make(chan struct{})

	// Start cross-validation loop
	go v.validationLoop()

	return nil
}

// validationLoop periodically cross-validates input and HID counts.
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
	inputCount := int64(v.inputCounter.Count())

	v.mu.Lock()
	defer v.mu.Unlock()

	var hidCount int64
	if v.hidAvailable {
		hidCount = v.hidMonitor.Count()
	}

	// Calculate new events since last check
	inputDelta := inputCount - v.lastInputCount
	hidDelta := hidCount - v.lastHIDCount

	if inputDelta <= 0 && hidDelta <= 0 {
		return // No new events
	}

	// Check for synthetic events (input saw more than HID)
	if v.hidAvailable && inputDelta > hidDelta {
		syntheticCount := inputDelta - hidDelta
		v.totalSyntheticDetected += syntheticCount
	}

	// Determine how many events to count
	var eventsToCount int64
	if v.strictValidation && v.hidAvailable {
		// Only count events verified by HID (hardware-confirmed)
		eventsToCount = hidDelta
		if eventsToCount < 0 {
			eventsToCount = 0
		}
	} else {
		// Count all input events (but track synthetic detection)
		eventsToCount = inputDelta
	}

	// Update base counter
	for i := int64(0); i < eventsToCount; i++ {
		v.Increment()
	}

	v.lastInputCount = inputCount
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

	v.inputCounter.Stop()
	if v.hidAvailable {
		v.hidMonitor.Stop()
	}
	v.CloseListeners()

	return nil
}

// ValidationStats returns cross-validation statistics.
func (v *ValidatedCounter) ValidationStats() ValidationStats {
	v.mu.RLock()
	defer v.mu.RUnlock()

	inputCount := int64(v.inputCounter.Count())
	var hidCount int64
	if v.hidAvailable {
		hidCount = v.hidMonitor.Count()
	}

	return ValidationStats{
		CGEventTapCount:        inputCount, // Using same field for API compatibility
		HIDCount:               hidCount,
		ValidatedCount:         int64(v.Count()),
		TotalSyntheticDetected: v.totalSyntheticDetected,
		Discrepancy:            inputCount - hidCount,
		HIDMonitorActive:       v.hidAvailable && v.hidMonitor.IsRunning(),
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

// NewSecureCounter creates a counter with enhanced security against
// synthetic keystroke injection on Linux.
func NewSecureCounter() Counter {
	return NewValidatedCounter()
}

// ErrHIDNotAvailable is returned when hidraw monitoring isn't available.
var ErrHIDNotAvailable = errors.New("hidraw monitoring not available (may need root or hidraw access)")
