// +build darwin

package keystroke

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework ApplicationServices -framework Foundation

#include <ApplicationServices/ApplicationServices.h>

// We only count events - we do NOT examine the keycode
static int keystrokeCount = 0;

CGEventRef eventCallback(CGEventTapProxy proxy, CGEventType type, CGEventRef event, void *refcon) {
    if (type == kCGEventKeyDown) {
        keystrokeCount++;
    }
    return event;
}

static CFMachPortRef eventTap = NULL;
static CFRunLoopSourceRef runLoopSource = NULL;

int startEventTap() {
    if (eventTap != NULL) {
        return 1; // Already running
    }

    CGEventMask eventMask = CGEventMaskBit(kCGEventKeyDown);

    eventTap = CGEventTapCreate(
        kCGSessionEventTap,
        kCGHeadInsertEventTap,
        kCGEventTapOptionListenOnly, // Read-only, we don't modify events
        eventMask,
        eventCallback,
        NULL
    );

    if (eventTap == NULL) {
        return -1; // Permission denied or not available
    }

    runLoopSource = CFMachPortCreateRunLoopSource(kCFAllocatorDefault, eventTap, 0);
    CFRunLoopAddSource(CFRunLoopGetCurrent(), runLoopSource, kCFRunLoopCommonModes);
    CGEventTapEnable(eventTap, true);

    return 0;
}

void stopEventTap() {
    if (eventTap != NULL) {
        CGEventTapEnable(eventTap, false);
        CFRunLoopRemoveSource(CFRunLoopGetCurrent(), runLoopSource, kCFRunLoopCommonModes);
        CFRelease(runLoopSource);
        CFRelease(eventTap);
        eventTap = NULL;
        runLoopSource = NULL;
    }
}

int getCount() {
    return keystrokeCount;
}

void resetCount() {
    keystrokeCount = 0;
}

int checkAccessibility() {
    // Check if we have accessibility permissions
    NSDictionary *options = @{(__bridge id)kAXTrustedCheckOptionPrompt: @NO};
    return AXIsProcessTrustedWithOptions((__bridge CFDictionaryRef)options) ? 1 : 0;
}
*/
import "C"

import (
	"context"
	"errors"
	"sync"
	"time"
)

// DarwinCounter uses CGEventTap for macOS keyboard counting.
type DarwinCounter struct {
	BaseCounter
	ctx      context.Context
	cancel   context.CancelFunc
	pollDone chan struct{}
}

func newPlatformCounter() Counter {
	return &DarwinCounter{}
}

// Available checks if CGEventTap is available.
func (d *DarwinCounter) Available() (bool, string) {
	if C.checkAccessibility() == 1 {
		return true, "CGEventTap available"
	}
	return false, "Accessibility permission required. Go to System Preferences > Security & Privacy > Privacy > Accessibility and add this application."
}

// Start begins counting keyboard events.
func (d *DarwinCounter) Start(ctx context.Context) error {
	if d.IsRunning() {
		return ErrAlreadyRunning
	}

	// Check permissions
	if C.checkAccessibility() != 1 {
		return errors.New("accessibility permission required: go to System Preferences > Security & Privacy > Privacy > Accessibility")
	}

	// Reset the C-side counter
	C.resetCount()

	// Start the event tap
	result := C.startEventTap()
	if result == 1 {
		return ErrAlreadyRunning
	}
	if result == -1 {
		return ErrPermissionDenied
	}

	d.ctx, d.cancel = context.WithCancel(ctx)
	d.SetRunning(true)
	d.pollDone = make(chan struct{})

	// Start polling the C counter
	go d.pollLoop()

	return nil
}

// pollLoop periodically syncs the C counter with Go and notifies listeners.
func (d *DarwinCounter) pollLoop() {
	defer close(d.pollDone)

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	var lastCount uint64

	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			cCount := uint64(C.getCount())
			if cCount > lastCount {
				// Notify for each new keystroke
				for i := lastCount; i < cCount; i++ {
					d.Increment()
				}
				lastCount = cCount
			}
		}
	}
}

// Stop stops counting.
func (d *DarwinCounter) Stop() error {
	if !d.IsRunning() {
		return nil
	}

	if d.cancel != nil {
		d.cancel()
	}

	// Wait for poll loop to finish
	if d.pollDone != nil {
		<-d.pollDone
	}

	C.stopEventTap()
	d.SetRunning(false)
	d.CloseListeners()

	return nil
}

// Ensure DarwinCounter satisfies Counter interface
var _ Counter = (*DarwinCounter)(nil)

// Note: For CGEventTap to work, the binary needs to be run from Terminal
// and Terminal needs accessibility permissions, OR the binary itself
// needs accessibility permissions if it's a signed app bundle.
//
// Alternative approach using IOKit for USB HID devices could work
// without accessibility permissions but is more complex.

// fallbackCounter is used when CGEventTap isn't available
type fallbackCounter struct {
	mu      sync.RWMutex
	count   uint64
	running bool
}

func (f *fallbackCounter) Start(ctx context.Context) error {
	return ErrNotAvailable
}

func (f *fallbackCounter) Stop() error {
	return nil
}

func (f *fallbackCounter) Count() uint64 {
	return 0
}

func (f *fallbackCounter) Subscribe(interval uint64) <-chan Event {
	ch := make(chan Event)
	close(ch)
	return ch
}

func (f *fallbackCounter) Available() (bool, string) {
	return false, "keyboard counting not available"
}
