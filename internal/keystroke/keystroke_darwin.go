//go:build darwin

package keystroke

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework ApplicationServices -framework Foundation

#include <ApplicationServices/ApplicationServices.h>
#include <pthread.h>
#include <unistd.h>

// ============================================================================
// Synthetic Event Detection for CGEventPost Attack Mitigation
// ============================================================================
//
// CGEventPost() can inject synthetic keyboard events that appear at the
// CGEventTap layer. We use multiple heuristics to detect and reject these:
//
// 1. Event Source State ID:
//    - kCGEventSourceStateHIDSystemState (1): Hardware events from HID system
//    - kCGEventSourceStateCombinedSessionState (0): Often synthetic
//    - kCGEventSourceStatePrivate (-1): Synthetic from CGEventSourceCreate
//
// 2. Keyboard Type:
//    - Hardware keyboards report a non-zero keyboard type
//    - Synthetic events often have keyboard type 0 or invalid values
//
// 3. Event Source PID:
//    - Hardware events have source PID of 0 (kernel)
//    - CGEventPost events have the posting process's PID
//
// 4. Event Flags:
//    - Some synthetic events have unusual flag combinations
//
// Note: A sophisticated attacker can potentially forge these fields, but
// this raises the bar significantly above naive CGEventPost() attacks.
// ============================================================================

// Counters for keystroke events
static volatile int64_t keystrokeCount = 0;           // Verified hardware keystrokes
static volatile int64_t syntheticRejectedCount = 0;   // Rejected as likely synthetic
static volatile int64_t suspiciousCount = 0;          // Passed but flagged as suspicious

// Detailed rejection reason counters
static volatile int64_t rejectedBadSourceState = 0;   // Non-HID source state
static volatile int64_t rejectedBadKeyboardType = 0;  // Invalid keyboard type
static volatile int64_t rejectedNonKernelPID = 0;     // Non-zero source PID
static volatile int64_t rejectedZeroTimestamp = 0;    // Missing timestamp

// Jitter configuration (prepared for future use)
static volatile int jitterMicros = 0;

// Strictness mode: 0 = permissive (warn only), 1 = strict (reject suspicious)
static volatile int strictMode = 1;

// Run loop state
static CFRunLoopRef tapRunLoop = NULL;
static volatile int tapEnabled = 0;
static volatile int tapDisabledBySystem = 0;

// Forward declarations
static void stopEventTap(void);

// Event tap and run loop source (declared before callback so it can use them)
static CFMachPortRef eventTap = NULL;
static CFRunLoopSourceRef runLoopSource = NULL;

// Check if an event appears to be from hardware (not CGEventPost)
// Returns: 0 = likely synthetic (reject), 1 = likely hardware (accept), 2 = suspicious but accept
static int verifyEventSource(CGEventRef event) {
    // -------------------------------------------------------------------------
    // Check 1: Event Source State ID
    // -------------------------------------------------------------------------
    // Hardware keyboard events come from kCGEventSourceStateHIDSystemState (1)
    // CGEventPost typically uses kCGEventSourceStateCombinedSessionState (0)
    // or kCGEventSourceStatePrivate (-1)
    int64_t sourceStateID = CGEventGetIntegerValueField(event, kCGEventSourceStateID);

    // kCGEventSourceStateHIDSystemState = 1 (hardware)
    // kCGEventSourceStateCombinedSessionState = 0 (session, often synthetic)
    // kCGEventSourceStatePrivate = -1 (definitely synthetic)
    if (sourceStateID == -1) {
        // Private source state - definitely synthetic
        rejectedBadSourceState++;
        return 0;
    }

    int suspicious = 0;
    if (sourceStateID != 1) {
        // Not from HID system - suspicious but could be legitimate in some cases
        // (e.g., virtual keyboard, remote desktop)
        suspicious = 1;
    }

    // -------------------------------------------------------------------------
    // Check 2: Keyboard Type
    // -------------------------------------------------------------------------
    // Real keyboards report their type (e.g., ANSI, ISO, JIS)
    // Synthetic events often have keyboard type 0
    int64_t keyboardType = CGEventGetIntegerValueField(event, kCGKeyboardEventKeyboardType);

    if (keyboardType == 0) {
        // Zero keyboard type - very suspicious for key events
        // Some legitimate virtual keyboards might have this, but it's rare
        if (strictMode) {
            rejectedBadKeyboardType++;
            return 0;
        }
        suspicious = 1;
    }

    // Sanity check: keyboard type should be reasonable (< 100)
    if (keyboardType > 100) {
        rejectedBadKeyboardType++;
        return 0;
    }

    // -------------------------------------------------------------------------
    // Check 3: Source Unix Process ID
    // -------------------------------------------------------------------------
    // Hardware events from the HID system have source PID of 0 (kernel)
    // CGEventPost events have the PID of the process that posted them
    int64_t sourcePID = CGEventGetIntegerValueField(event, kCGEventSourceUnixProcessID);

    if (sourcePID != 0) {
        // Non-kernel source - this is a strong indicator of synthetic events
        // CGEventPost sets this to the calling process's PID
        if (strictMode) {
            rejectedNonKernelPID++;
            return 0;
        }
        suspicious = 1;
    }

    // -------------------------------------------------------------------------
    // Check 4: Event Timestamp
    // -------------------------------------------------------------------------
    // Real events have valid timestamps from the event system
    // Some synthetic events may have zero or stale timestamps
    CGEventTimestamp timestamp = CGEventGetTimestamp(event);

    if (timestamp == 0) {
        // Zero timestamp is suspicious - real events always have timestamps
        if (strictMode) {
            rejectedZeroTimestamp++;
            return 0;
        }
        suspicious = 1;
    }

    // -------------------------------------------------------------------------
    // Check 5: Autorepeat flag (informational)
    // -------------------------------------------------------------------------
    // Note: We don't reject based on autorepeat, but it's useful context
    // Synthetic attacks often don't set autorepeat correctly for held keys
    // int64_t autorepeat = CGEventGetIntegerValueField(event, kCGKeyboardEventAutorepeat);

    if (suspicious) {
        return 2;  // Suspicious but accepted
    }

    return 1;  // Verified as likely hardware
}

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
        // Verify the event source to detect CGEventPost injection attacks
        int verifyResult = verifyEventSource(event);

        if (verifyResult == 0) {
            // Likely synthetic - reject and don't count
            syntheticRejectedCount++;
            // Still return the event (we're monitoring, not blocking)
            return event;
        }

        if (verifyResult == 2) {
            // Suspicious but accepted
            suspiciousCount++;
        }

        // Verified or accepted - count this keystroke
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

// ============================================================================
// Accessor Functions
// ============================================================================

int64_t getCount() {
    return keystrokeCount;
}

void resetCount() {
    keystrokeCount = 0;
}

void resetAllCounters() {
    keystrokeCount = 0;
    syntheticRejectedCount = 0;
    suspiciousCount = 0;
    rejectedBadSourceState = 0;
    rejectedBadKeyboardType = 0;
    rejectedNonKernelPID = 0;
    rejectedZeroTimestamp = 0;
}

int isTapEnabled() {
    return tapEnabled;
}

int wasTapDisabledBySystem() {
    int val = tapDisabledBySystem;
    tapDisabledBySystem = 0;  // Reset after reading
    return val;
}

// ============================================================================
// Synthetic Event Detection Statistics
// ============================================================================

int64_t getSyntheticRejectedCount() {
    return syntheticRejectedCount;
}

int64_t getSuspiciousCount() {
    return suspiciousCount;
}

// Detailed rejection reason accessors
int64_t getRejectedBadSourceState() {
    return rejectedBadSourceState;
}

int64_t getRejectedBadKeyboardType() {
    return rejectedBadKeyboardType;
}

int64_t getRejectedNonKernelPID() {
    return rejectedNonKernelPID;
}

int64_t getRejectedZeroTimestamp() {
    return rejectedZeroTimestamp;
}

// Get total events seen (accepted + rejected)
int64_t getTotalEventsSeen() {
    return keystrokeCount + syntheticRejectedCount;
}

// Strictness mode control
void setStrictMode(int strict) {
    strictMode = strict ? 1 : 0;
}

int getStrictMode() {
    return strictMode;
}

// ============================================================================
// Jitter Configuration (Future Use)
// ============================================================================

void setJitterMicros(int micros) {
    jitterMicros = micros;
}

int getJitterMicros() {
    return jitterMicros;
}

// ============================================================================
// Accessibility Permissions
// ============================================================================

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

	// Strict mode rejects suspicious events; permissive mode only warns
	strictMode bool
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

	// Reset all C-side counters (keystroke count and synthetic event stats)
	C.resetAllCounters()

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
				// Notify for each new keystroke (only verified hardware events)
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

// SetStrictMode controls whether suspicious events are rejected (true) or
// only flagged (false). Default is strict mode (true).
//
// In strict mode, events that fail any verification check are rejected.
// In permissive mode, suspicious events are counted but flagged for review.
//
// Use permissive mode for debugging or when false positives are a concern
// (e.g., virtual keyboards, remote desktop).
func (d *DarwinCounter) SetStrictMode(strict bool) {
	d.strictMode = strict
	if strict {
		C.setStrictMode(1)
	} else {
		C.setStrictMode(0)
	}
}

// StrictMode returns whether strict mode is enabled.
func (d *DarwinCounter) StrictMode() bool {
	return C.getStrictMode() == 1
}

// SyntheticEventStats returns statistics about detected synthetic event
// injection attempts. This is useful for:
// - Detecting CGEventPost-based attacks
// - Debugging virtual keyboard issues
// - Auditing keystroke evidence integrity
func (d *DarwinCounter) SyntheticEventStats() SyntheticEventStats {
	return SyntheticEventStats{
		TotalRejected:           int64(C.getSyntheticRejectedCount()),
		Suspicious:              int64(C.getSuspiciousCount()),
		RejectedBadSourceState:  int64(C.getRejectedBadSourceState()),
		RejectedBadKeyboardType: int64(C.getRejectedBadKeyboardType()),
		RejectedNonKernelPID:    int64(C.getRejectedNonKernelPID()),
		RejectedZeroTimestamp:   int64(C.getRejectedZeroTimestamp()),
		TotalEventsSeen:         int64(C.getTotalEventsSeen()),
	}
}

// ResetAllCounters resets all counters including synthetic event statistics.
func (d *DarwinCounter) ResetAllCounters() {
	C.resetAllCounters()
}

// InjectionAttemptDetected returns true if any events have been rejected
// as likely synthetic injections.
func (d *DarwinCounter) InjectionAttemptDetected() bool {
	return C.getSyntheticRejectedCount() > 0
}

// SyntheticRejectionRate returns the percentage of events rejected as synthetic.
// Returns 0 if no events have been seen.
func (d *DarwinCounter) SyntheticRejectionRate() float64 {
	total := int64(C.getTotalEventsSeen())
	if total == 0 {
		return 0
	}
	rejected := int64(C.getSyntheticRejectedCount())
	return float64(rejected) / float64(total) * 100
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
