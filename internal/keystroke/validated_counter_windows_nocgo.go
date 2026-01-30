//go:build windows && !cgo

package keystroke

import (
	"context"
	"errors"
)

// ValidatedCounter is a stub when CGO is not available on Windows.
type ValidatedCounter struct {
	BaseCounter
}

// NewValidatedCounter creates a stub validated counter.
func NewValidatedCounter() *ValidatedCounter {
	return &ValidatedCounter{}
}

// SetStrictValidation is a no-op.
func (v *ValidatedCounter) SetStrictValidation(strict bool) {}

// Available returns false when CGO is not available.
func (v *ValidatedCounter) Available() (bool, string) {
	return false, "Validated keystroke counting requires CGO (rebuild with CGO_ENABLED=1)"
}

// Start returns an error.
func (v *ValidatedCounter) Start(ctx context.Context) error {
	return ErrNotAvailable
}

// Stop is a no-op.
func (v *ValidatedCounter) Stop() error {
	return nil
}

// ValidationStats returns empty stats.
func (v *ValidatedCounter) ValidationStats() ValidationStats {
	return ValidationStats{}
}

// SyntheticDetected returns false.
func (v *ValidatedCounter) SyntheticDetected() bool {
	return false
}

// Ensure ValidatedCounter satisfies Counter interface
var _ Counter = (*ValidatedCounter)(nil)

// NewSecureCounter creates a stub counter.
func NewSecureCounter() Counter {
	return NewValidatedCounter()
}

// ErrHIDNotAvailable is returned when Windows HID monitoring isn't available.
var ErrHIDNotAvailable = errors.New("Windows HID monitoring not available (requires CGO)")
