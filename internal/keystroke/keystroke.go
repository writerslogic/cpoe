// Package keystroke provides keyboard event counting.
//
// IMPORTANT: This package counts keyboard events - it does NOT capture
// or record which keys are pressed. This is a critical privacy distinction:
// - Keylogger: Records "h", "e", "l", "l", "o" → "hello"
// - This package: Records "5 keystrokes occurred"
//
// The count is used to:
// 1. Trigger periodic document hash sampling
// 2. Compute cryptographically-bound jitter values
// 3. Prove real typing occurred over time
//
// Platform support:
// - macOS: Uses CGEventTap (requires Accessibility permission)
// - Linux: Uses /dev/input/event* (requires input group or root)
// - Windows: Uses SetWindowsHookEx (user-mode hook)
package keystroke

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Counter counts keyboard events without capturing content.
type Counter interface {
	// Start begins counting keyboard events.
	Start(ctx context.Context) error

	// Stop stops counting.
	Stop() error

	// Count returns the current keystroke count.
	Count() uint64

	// Subscribe returns a channel that receives notifications
	// every N keystrokes. Close the context to unsubscribe.
	Subscribe(interval uint64) <-chan Event

	// Available returns true if keyboard counting is available
	// on this platform with current permissions.
	Available() (bool, string)
}

// Event is sent when a keystroke threshold is reached.
type Event struct {
	Count     uint64
	Timestamp time.Time
}

// listener handles subscriber notifications.
type listener struct {
	interval uint64
	ch       chan Event
	lastSent uint64
}

// BaseCounter provides common functionality for platform implementations.
type BaseCounter struct {
	mu        sync.RWMutex
	count     uint64
	running   bool
	listeners []*listener
}

// Count returns the current keystroke count.
func (b *BaseCounter) Count() uint64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.count
}

// Subscribe returns a channel that receives events every N keystrokes.
func (b *BaseCounter) Subscribe(interval uint64) <-chan Event {
	b.mu.Lock()
	defer b.mu.Unlock()

	ch := make(chan Event, 10)
	l := &listener{
		interval: interval,
		ch:       ch,
		lastSent: b.count,
	}
	b.listeners = append(b.listeners, l)
	return ch
}

// Increment adds to the count and notifies listeners.
func (b *BaseCounter) Increment() {
	b.mu.Lock()
	b.count++
	count := b.count
	now := time.Now()

	// Notify listeners
	for _, l := range b.listeners {
		if count-l.lastSent >= l.interval {
			select {
			case l.ch <- Event{Count: count, Timestamp: now}:
				l.lastSent = count
			default:
				// Channel full, skip
			}
		}
	}
	b.mu.Unlock()
}

// CloseListeners closes all listener channels.
func (b *BaseCounter) CloseListeners() {
	b.mu.Lock()
	defer b.mu.Unlock()

	for _, l := range b.listeners {
		close(l.ch)
	}
	b.listeners = nil
}

// SetRunning sets the running state.
func (b *BaseCounter) SetRunning(running bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.running = running
}

// IsRunning returns the running state.
func (b *BaseCounter) IsRunning() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.running
}

// New creates a Counter for the current platform.
func New() Counter {
	return newPlatformCounter()
}

// ErrNotAvailable is returned when keyboard counting isn't available.
var ErrNotAvailable = errors.New("keyboard counting not available on this platform")

// CrossValidationResult contains the result of comparing application-layer and HID counts.
type CrossValidationResult struct {
	// CGEventTapCount is the count from the application layer (may include synthetic)
	// On macOS this is CGEventTap, on Windows this is Raw Input
	CGEventTapCount int64
	// HIDCount is the count from HID layer (hardware only)
	HIDCount int64
	// Discrepancy is CGEventTapCount - HIDCount (positive = synthetic detected)
	Discrepancy int64
	// SyntheticDetected is true if discrepancy suggests synthetic events
	SyntheticDetected bool
	// SyntheticPercentage is the estimated percentage of synthetic events
	SyntheticPercentage float64
}

// CrossValidate compares application-layer and HID counts to detect synthetic events.
// This is the strongest detection method because userspace injection APIs cannot
// inject at the HID layer.
//
// Returns:
//   - Discrepancy > 0: Synthetic events detected (app layer saw more than HID)
//   - Discrepancy = 0: All events appear to be hardware
//   - Discrepancy < 0: Unusual (HID saw more than app layer - timing issue?)
func CrossValidate(appLayerCount int64, hidCount int64) CrossValidationResult {
	discrepancy := appLayerCount - hidCount

	result := CrossValidationResult{
		CGEventTapCount:   appLayerCount,
		HIDCount:          hidCount,
		Discrepancy:       discrepancy,
		SyntheticDetected: discrepancy > 0,
	}

	if appLayerCount > 0 && discrepancy > 0 {
		result.SyntheticPercentage = float64(discrepancy) / float64(appLayerCount) * 100
	}

	return result
}

// ValidationStats contains cross-validation statistics for dual-layer monitoring.
type ValidationStats struct {
	// CGEventTapCount is total events seen at application layer
	// On macOS: CGEventTap, on Windows: Raw Input
	CGEventTapCount int64
	// HIDCount is total events seen at HID layer (hardware only)
	HIDCount int64
	// ValidatedCount is the count we're reporting (depends on strict mode)
	ValidatedCount int64
	// TotalSyntheticDetected is cumulative synthetic events detected
	TotalSyntheticDetected int64
	// Discrepancy is current difference between app layer and HID counts
	Discrepancy int64
	// HIDMonitorActive indicates if HID monitoring is working
	HIDMonitorActive bool
	// StrictMode indicates if only HID-verified events are counted
	StrictMode bool
}

// SyntheticEventStats contains statistics about detected synthetic event injection attempts.
// This is used for cross-validation between hardware and software layers.
type SyntheticEventStats struct {
	// TotalRejected is the total number of events rejected as likely synthetic
	TotalRejected int64
	// Suspicious is the count of events that were suspicious but accepted
	Suspicious int64
	// RejectedBadSourceState is events rejected for non-HID source state (macOS only)
	RejectedBadSourceState int64
	// RejectedBadKeyboardType is events rejected for invalid keyboard type (macOS only)
	RejectedBadKeyboardType int64
	// RejectedNonKernelPID is events rejected for non-kernel source PID (macOS only)
	RejectedNonKernelPID int64
	// RejectedZeroTimestamp is events rejected for missing timestamp (macOS only)
	RejectedZeroTimestamp int64
	// TotalEventsSeen is all events (accepted + rejected)
	TotalEventsSeen int64
}

// ErrPermissionDenied is returned when permissions are insufficient.
var ErrPermissionDenied = errors.New("insufficient permissions for keyboard counting")

// ErrAlreadyRunning is returned when Start is called while already running.
var ErrAlreadyRunning = errors.New("counter already running")

// SimulatedCounter is a counter for testing that doesn't hook real keyboard.
type SimulatedCounter struct {
	BaseCounter
	ctx    context.Context
	cancel context.CancelFunc
}

// NewSimulated creates a counter for testing.
func NewSimulated() *SimulatedCounter {
	return &SimulatedCounter{}
}

// Start begins the simulated counter.
func (s *SimulatedCounter) Start(ctx context.Context) error {
	if s.IsRunning() {
		return ErrAlreadyRunning
	}
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.SetRunning(true)
	return nil
}

// Stop stops the simulated counter.
func (s *SimulatedCounter) Stop() error {
	if !s.IsRunning() {
		return nil
	}
	if s.cancel != nil {
		s.cancel()
	}
	s.SetRunning(false)
	s.CloseListeners()
	return nil
}

// SimulateKeystroke simulates a keystroke for testing.
func (s *SimulatedCounter) SimulateKeystroke() {
	if s.IsRunning() {
		s.Increment()
	}
}

// SimulateKeystrokes simulates multiple keystrokes for testing.
func (s *SimulatedCounter) SimulateKeystrokes(n int) {
	for i := 0; i < n; i++ {
		s.SimulateKeystroke()
	}
}

// Available returns true (simulated is always available).
func (s *SimulatedCounter) Available() (bool, string) {
	return true, "simulated counter (for testing)"
}
