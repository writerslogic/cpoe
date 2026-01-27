// +build !darwin,!linux

package keystroke

import (
	"context"
)

// StubCounter is used on unsupported platforms.
type StubCounter struct {
	BaseCounter
}

func newPlatformCounter() Counter {
	return &StubCounter{}
}

// Available returns false on unsupported platforms.
func (s *StubCounter) Available() (bool, string) {
	return false, "keyboard counting not implemented for this platform"
}

// Start returns an error on unsupported platforms.
func (s *StubCounter) Start(ctx context.Context) error {
	return ErrNotAvailable
}

// Stop is a no-op on unsupported platforms.
func (s *StubCounter) Stop() error {
	return nil
}
