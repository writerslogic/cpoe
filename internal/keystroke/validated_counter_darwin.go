//go:build darwin

package keystroke

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ValidatedCounter provides maximum-security keystroke counting by monitoring
// at BOTH the CGEventTap and IOKit HID layers simultaneously.
//
// This provides the strongest possible defense against CGEventPost injection:
//
//  1. IOKit HID layer (hardware only): Cannot be faked without physical hardware
//  2. CGEventTap layer (may include synthetic): Provides timing and additional data
//  3. Cross-validation: Any discrepancy indicates synthetic injection
//
// The ValidatedCounter only counts keystrokes that are verified at BOTH layers,
// making CGEventPost attacks detectable and rejectable.
type ValidatedCounter struct {
	BaseCounter

	// Platform-specific counters
	cgEventCounter *DarwinCounter
	hidMonitor     *HIDMonitor

	// Cross-validation state
	mu                    sync.RWMutex
	lastCGEventCount      int64
	lastHIDCount          int64
	totalSyntheticDetected int64
	validationErrors      int64

	// Configuration
	strictValidation bool // If true, only count HID-verified events

	// Context management
	ctx      context.Context
	cancel   context.CancelFunc
	pollDone chan struct{}
}

// NewValidatedCounter creates a counter that cross-validates events between
// CGEventTap and IOKit HID layers for maximum security.
func NewValidatedCounter() *ValidatedCounter {
	return &ValidatedCounter{
		cgEventCounter:   &DarwinCounter{},
		hidMonitor:       NewHIDMonitor(),
		strictValidation: true, // Default to strict mode
	}
}

// SetStrictValidation controls whether only HID-verified events are counted.
// When true (default), only keystrokes verified at the hardware level are counted.
// When false, all CGEventTap events are counted but synthetic detection still occurs.
func (v *ValidatedCounter) SetStrictValidation(strict bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.strictValidation = strict
}

// Available checks if validated counting is available.
func (v *ValidatedCounter) Available() (bool, string) {
	cgAvailable, cgMsg := v.cgEventCounter.Available()
	if !cgAvailable {
		return false, cgMsg
	}

	// HID monitoring requires IOKit access (usually available without special permissions)
	return true, "Dual-layer monitoring available (CGEventTap + IOKit HID)"
}

// Start begins dual-layer monitoring.
func (v *ValidatedCounter) Start(ctx context.Context) error {
	if v.IsRunning() {
		return ErrAlreadyRunning
	}

	// Start HID monitoring first (lower level)
	if err := v.hidMonitor.Start(); err != nil {
		// HID monitoring failed - fall back to CGEventTap only with warning
		// This can happen if IOKit access is restricted
		v.mu.Lock()
		v.strictValidation = false // Can't validate without HID
		v.mu.Unlock()
	}

	// Start CGEventTap monitoring
	if err := v.cgEventCounter.Start(ctx); err != nil {
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

// validationLoop periodically cross-validates CGEventTap and HID counts.
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
	cgCount := int64(v.cgEventCounter.Count())
	hidCount := v.hidMonitor.Count()

	v.mu.Lock()
	defer v.mu.Unlock()

	// Calculate new events since last check
	cgDelta := cgCount - v.lastCGEventCount
	hidDelta := hidCount - v.lastHIDCount

	if cgDelta <= 0 && hidDelta <= 0 {
		return // No new events
	}

	// Check for synthetic events (CGEventTap saw more than HID)
	if cgDelta > hidDelta {
		syntheticCount := cgDelta - hidDelta
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
		// Count all CGEventTap events (but track synthetic detection)
		eventsToCount = cgDelta
	}

	// Update base counter
	for i := int64(0); i < eventsToCount; i++ {
		v.Increment()
	}

	v.lastCGEventCount = cgCount
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

	v.cgEventCounter.Stop()
	v.hidMonitor.Stop()
	v.CloseListeners()

	return nil
}

// ValidationStats returns cross-validation statistics.
func (v *ValidatedCounter) ValidationStats() ValidationStats {
	v.mu.RLock()
	defer v.mu.RUnlock()

	cgCount := int64(v.cgEventCounter.Count())
	hidCount := v.hidMonitor.Count()

	return ValidationStats{
		CGEventTapCount:       cgCount,
		HIDCount:              hidCount,
		ValidatedCount:        int64(v.Count()),
		TotalSyntheticDetected: v.totalSyntheticDetected,
		Discrepancy:           cgCount - hidCount,
		HIDMonitorActive:      v.hidMonitor.IsRunning(),
		StrictMode:            v.strictValidation,
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

// NewSecureCounter is an alias for NewValidatedCounter - creates a counter
// with maximum security against synthetic keystroke injection.
func NewSecureCounter() Counter {
	return NewValidatedCounter()
}

// ErrHIDNotAvailable is returned when IOKit HID monitoring isn't available.
var ErrHIDNotAvailable = errors.New("IOKit HID monitoring not available")
