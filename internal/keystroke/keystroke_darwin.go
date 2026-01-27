//go:build darwin

package keystroke

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework ApplicationServices -framework Foundation

#include <ApplicationServices/ApplicationServices.h>
#include <pthread.h>
#include <unistd.h>

// We only count events - we do NOT examine the keycode
static volatile int keystrokeCount = 0;

// Jitter configuration (prepared for future use)
static volatile int jitterMicros = 0;

// Run loop state
static CFRunLoopRef tapRunLoop = NULL;
static volatile int tapEnabled = 0;
static volatile int tapDisabledBySystem = 0;

// Forward declarations
static void stopEventTap(void);

// Event tap and run loop source (declared before callback so it can use them)
static CFMachPortRef eventTap = NULL;
static CFRunLoopSourceRef runLoopSource = NULL;

CGEventRef eventCallback(CGEventTapProxy proxy, CGEventType type, CGEventRef event, void *refcon) {
    (void)proxy;  // unused
    (void)refcon; // unused

    // Handle system disabling the tap (happens if callback is too slow)
    if (type == kCGEventTapDisabledByUserInput || type == kCGEventTapDisabledByTimeout) {
        tapDisabledBySystem = 1;
        // Re-enable the tap using the global eventTap
        if (eventTap != NULL) {
            CGEventTapEnable(eventTap, true);
        }
        return event;
    }

    if (type == kCGEventKeyDown) {
        keystrokeCount++;

        // Future: Apply jitter delay here
        // if (jitterMicros > 0) {
        //     usleep(jitterMicros);
        // }
    }
    return event;
}

// Thread function that runs the event tap run loop
static void* runLoopThread(void* arg) {
    (void)arg;

    // Store reference to this run loop so we can stop it
    tapRunLoop = CFRunLoopGetCurrent();

    // Add the source to THIS thread's run loop
    CFRunLoopAddSource(tapRunLoop, runLoopSource, kCFRunLoopCommonModes);
    CGEventTapEnable(eventTap, true);
    tapEnabled = 1;

    // Run the loop - this blocks until CFRunLoopStop is called
    CFRunLoopRun();

    // Cleanup when loop stops
    tapEnabled = 0;
    tapRunLoop = NULL;

    return NULL;
}

static pthread_t runLoopThreadHandle;
static volatile int threadRunning = 0;

static int startEventTap(void) {
    if (eventTap != NULL) {
        return 1; // Already running
    }

    CGEventMask eventMask = CGEventMaskBit(kCGEventKeyDown);

    // Use kCGEventTapOptionDefault to allow future jitter injection
    // For now we still just return the event unmodified
    eventTap = CGEventTapCreate(
        kCGSessionEventTap,
        kCGHeadInsertEventTap,
        kCGEventTapOptionDefault,  // Changed from ListenOnly for future jitter support
        eventMask,
        eventCallback,
        NULL
    );

    if (eventTap == NULL) {
        return -1; // Permission denied or not available
    }

    runLoopSource = CFMachPortCreateRunLoopSource(kCFAllocatorDefault, eventTap, 0);
    if (runLoopSource == NULL) {
        CFRelease(eventTap);
        eventTap = NULL;
        return -2; // Failed to create run loop source
    }

    // Start the run loop thread
    threadRunning = 1;
    if (pthread_create(&runLoopThreadHandle, NULL, runLoopThread, NULL) != 0) {
        CFRelease(runLoopSource);
        CFRelease(eventTap);
        runLoopSource = NULL;
        eventTap = NULL;
        threadRunning = 0;
        return -3; // Failed to create thread
    }

    // Wait for the tap to be enabled (with timeout)
    for (int i = 0; i < 100 && !tapEnabled; i++) {
        usleep(10000); // 10ms
    }

    if (!tapEnabled) {
        stopEventTap();
        return -4; // Timeout waiting for tap to enable
    }

    return 0;
}

static void stopEventTap(void) {
    if (eventTap == NULL) {
        return;
    }

    // Disable the tap first
    CGEventTapEnable(eventTap, false);
    tapEnabled = 0;

    // Stop the run loop
    if (tapRunLoop != NULL) {
        CFRunLoopStop(tapRunLoop);
    }

    // Wait for thread to finish
    if (threadRunning) {
        pthread_join(runLoopThreadHandle, NULL);
        threadRunning = 0;
    }

    // Cleanup
    if (runLoopSource != NULL) {
        // Note: Don't remove from run loop here - it's already stopped
        CFRelease(runLoopSource);
        runLoopSource = NULL;
    }

    if (eventTap != NULL) {
        CFRelease(eventTap);
        eventTap = NULL;
    }

    tapRunLoop = NULL;
}

int getCount() {
    return keystrokeCount;
}

void resetCount() {
    keystrokeCount = 0;
}

int isTapEnabled() {
    return tapEnabled;
}

int wasTapDisabledBySystem() {
    int val = tapDisabledBySystem;
    tapDisabledBySystem = 0;  // Reset after reading
    return val;
}

// Prepare for jitter injection (not yet used)
void setJitterMicros(int micros) {
    jitterMicros = micros;
}

int getJitterMicros() {
    return jitterMicros;
}

int checkAccessibility() {
    // Check if we have accessibility permissions
    NSDictionary *options = @{(__bridge id)kAXTrustedCheckOptionPrompt: @NO};
    return AXIsProcessTrustedWithOptions((__bridge CFDictionaryRef)options) ? 1 : 0;
}

int promptAccessibility() {
    // Check and prompt for accessibility permissions
    NSDictionary *options = @{(__bridge id)kAXTrustedCheckOptionPrompt: @YES};
    return AXIsProcessTrustedWithOptions((__bridge CFDictionaryRef)options) ? 1 : 0;
}
*/
import "C"

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// DarwinCounter uses CGEventTap for macOS keyboard counting.
type DarwinCounter struct {
	BaseCounter
	ctx      context.Context
	cancel   context.CancelFunc
	pollDone chan struct{}

	// Track if we've seen the tap get disabled by the system
	tapDisableCount atomic.Int64
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

// CheckAccessibility returns true if accessibility permissions are granted.
func CheckAccessibility() bool {
	return C.checkAccessibility() == 1
}

// PromptAccessibility checks permissions and prompts the user if not granted.
func PromptAccessibility() bool {
	return C.promptAccessibility() == 1
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
	switch result {
	case 1:
		return ErrAlreadyRunning
	case -1:
		return ErrPermissionDenied
	case -2:
		return errors.New("failed to create run loop source")
	case -3:
		return errors.New("failed to create run loop thread")
	case -4:
		return errors.New("timeout waiting for event tap to start")
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

	// Health check ticker - less frequent
	healthTicker := time.NewTicker(1 * time.Second)
	defer healthTicker.Stop()

	var lastCount uint64

	for {
		select {
		case <-d.ctx.Done():
			return

		case <-healthTicker.C:
			// Check if the tap was disabled by the system
			if C.wasTapDisabledBySystem() == 1 {
				d.tapDisableCount.Add(1)
				// The C code automatically re-enables the tap
				// We just track it for diagnostics
			}

			// Check if tap is still enabled
			if C.isTapEnabled() != 1 && d.IsRunning() {
				// Tap stopped unexpectedly - could be permission revocation
				// Stop cleanly to avoid spinning
				go func() {
					d.Stop()
				}()
				return
			}

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

	// Mark as not running first to prevent re-entry
	d.SetRunning(false)

	if d.cancel != nil {
		d.cancel()
	}

	// Wait for poll loop to finish
	if d.pollDone != nil {
		<-d.pollDone
	}

	C.stopEventTap()
	d.CloseListeners()

	return nil
}

// TapDisableCount returns how many times the system disabled the tap.
// This can happen if the callback is too slow.
func (d *DarwinCounter) TapDisableCount() int64 {
	return d.tapDisableCount.Load()
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

func (f *fallbackCounter) IsRunning() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.running
}
