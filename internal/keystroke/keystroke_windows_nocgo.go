//go:build windows && !cgo

package keystroke

import (
	"context"
	"errors"
	"sync/atomic"
)

// WindowsCounter is a stub when CGO is not available.
// The full implementation requires CGO for Windows Raw Input API.
type WindowsCounter struct {
	BaseCounter
}

func newPlatformCounter() Counter {
	return &WindowsCounter{}
}

// Available returns false when CGO is not available.
func (w *WindowsCounter) Available() (bool, string) {
	return false, "Windows keystroke counting requires CGO (rebuild with CGO_ENABLED=1)"
}

// Start returns an error when CGO is not available.
func (w *WindowsCounter) Start(ctx context.Context) error {
	return ErrNotAvailable
}

// Stop is a no-op.
func (w *WindowsCounter) Stop() error {
	return nil
}

// SetStrictMode is a no-op.
func (w *WindowsCounter) SetStrictMode(strict bool) {}

// SyntheticEventStats returns empty stats.
func (w *WindowsCounter) SyntheticEventStats() SyntheticEventStats {
	return SyntheticEventStats{}
}

// InjectionAttemptDetected returns false.
func (w *WindowsCounter) InjectionAttemptDetected() bool {
	return false
}

// SyntheticRejectionRate returns 0.
func (w *WindowsCounter) SyntheticRejectionRate() float64 {
	return 0
}

// ResetAllCounters is a no-op.
func (w *WindowsCounter) ResetAllCounters() {}

// FocusedWindow returns an error.
func FocusedWindow() (string, error) {
	return "", errors.New("not available without CGO")
}

// HIDMonitor is a stub when CGO is not available.
type HIDMonitor struct {
	running atomic.Bool
}

// NewHIDMonitor creates a stub HID monitor.
func NewHIDMonitor() *HIDMonitor {
	return &HIDMonitor{}
}

// Start returns an error.
func (h *HIDMonitor) Start() error {
	return errors.New("HID monitoring requires CGO")
}

// Stop is a no-op.
func (h *HIDMonitor) Stop() {}

// Count returns 0.
func (h *HIDMonitor) Count() int64 {
	return 0
}

// Reset is a no-op.
func (h *HIDMonitor) Reset() {}

// IsRunning returns false.
func (h *HIDMonitor) IsRunning() bool {
	return false
}
