//go:build darwin

package keystroke

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework IOKit -framework CoreFoundation -framework Foundation

#include <IOKit/hid/IOHIDManager.h>
#include <CoreFoundation/CoreFoundation.h>
#include <pthread.h>

// ============================================================================
// IOKit HID Layer Monitoring
// ============================================================================
//
// This monitors keyboard events at the IOKit HID layer, which is BELOW the
// CGEvent layer where CGEventPost injects synthetic events.
//
// Architecture:
//
//   Physical Keyboard
//         │
//         ▼
//   USB/Bluetooth HID Driver (kernel)
//         │
//         ▼
//   ┌─────────────────────────────────┐
//   │  IOKit HID Layer  ◄── WE MONITOR HERE (hidKeystrokeCount)
//   │  (IOHIDManager)                 │
//   └─────────────────────────────────┘
//         │
//         ▼
//   ┌─────────────────────────────────┐
//   │  CGEvent Layer    ◄── CGEventPost INJECTS HERE
//   │  (CGEventTap)                   │
//   └─────────────────────────────────┘
//         │
//         ▼
//   Application
//
// By monitoring at BOTH layers and comparing counts:
// - If CGEventTap count > IOKit count → synthetic events detected
// - If counts match → likely all hardware events
//
// CGEventPost CANNOT inject at the IOKit layer because:
// 1. IOKit HID events come from kernel HID drivers
// 2. Only actual USB/Bluetooth HID reports trigger IOKit callbacks
// 3. There is no userspace API to inject at this level
//
// ============================================================================

// HID layer keystroke count (hardware only)
static volatile int64_t hidKeystrokeCount = 0;

// HID manager state
static IOHIDManagerRef hidManager = NULL;
static CFRunLoopRef hidRunLoop = NULL;
static pthread_t hidThread;
static volatile int hidEnabled = 0;
static volatile int hidThreadRunning = 0;
static volatile int hidManagerOpened = 0;

// Forward declarations
void stopHIDMonitoring(void);

// HID callback - called for each HID keyboard event from actual hardware
static void hidInputCallback(void *context, IOReturn result, void *sender, IOHIDValueRef value) {
    (void)context;
    (void)result;
    (void)sender;

    IOHIDElementRef element = IOHIDValueGetElement(value);
    uint32_t usagePage = IOHIDElementGetUsagePage(element);
    uint32_t usage = IOHIDElementGetUsage(element);

    // Filter to keyboard events only (usage page 0x07 = Keyboard/Keypad)
    if (usagePage != kHIDPage_KeyboardOrKeypad) {
        return;
    }

    // Filter to actual key codes (4-231 are standard keys)
    // Usage 0 = reserved, 1 = ErrorRollOver, 2 = POSTFail, 3 = ErrorUndefined
    if (usage < 4 || usage > 231) {
        return;
    }

    // Only count key-down events (value = 1)
    // Key-up events have value = 0
    CFIndex intValue = IOHIDValueGetIntegerValue(value);
    if (intValue != 1) {
        return;
    }

    // This is a genuine hardware keystroke
    hidKeystrokeCount++;
}

// Device matching callback
static void hidDeviceMatchingCallback(void *context, IOReturn result, void *sender, IOHIDDeviceRef device) {
    (void)context;
    (void)result;
    (void)sender;
    (void)device;
    // Device connected - we could log this for debugging
}

// Device removal callback
static void hidDeviceRemovalCallback(void *context, IOReturn result, void *sender, IOHIDDeviceRef device) {
    (void)context;
    (void)result;
    (void)sender;
    (void)device;
    // Device disconnected
}

// HID run loop thread
static void* hidRunLoopThread(void* arg) {
    (void)arg;

    CFRunLoopRef runLoop = CFRunLoopGetCurrent();
    hidRunLoop = runLoop;

    // Schedule HID manager with this run loop
    IOHIDManagerScheduleWithRunLoop(hidManager, runLoop, kCFRunLoopDefaultMode);

    // Open the HID manager
    IOReturn ret = IOHIDManagerOpen(hidManager, kIOHIDOptionsTypeNone);
    if (ret != kIOReturnSuccess) {
        // Failed to open - unschedule before exiting to clean up properly
        IOHIDManagerUnscheduleFromRunLoop(hidManager, runLoop, kCFRunLoopDefaultMode);
        hidEnabled = 0;
        hidManagerOpened = 0;
        hidRunLoop = NULL;
        return NULL;
    }

    hidManagerOpened = 1;
    hidEnabled = 1;

    // Run the loop
    CFRunLoopRun();

    // Cleanup
    hidEnabled = 0;
    hidRunLoop = NULL;

    return NULL;
}

// Start HID monitoring
int startHIDMonitoring(void) {
    if (hidManager != NULL) {
        return 1; // Already running
    }

    // Create HID manager
    hidManager = IOHIDManagerCreate(kCFAllocatorDefault, kIOHIDOptionsTypeNone);
    if (hidManager == NULL) {
        return -1;
    }

    // Create device matching dictionary for keyboards
    CFMutableDictionaryRef matchDict = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );

    // Match keyboard devices (usage page 1 = Generic Desktop, usage 6 = Keyboard)
    int usagePage = kHIDPage_GenericDesktop;
    int usage = kHIDUsage_GD_Keyboard;
    CFNumberRef pageNum = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &usagePage);
    CFNumberRef usageNum = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &usage);

    CFDictionarySetValue(matchDict, CFSTR(kIOHIDDeviceUsagePageKey), pageNum);
    CFDictionarySetValue(matchDict, CFSTR(kIOHIDDeviceUsageKey), usageNum);

    CFRelease(pageNum);
    CFRelease(usageNum);

    // Set device matching
    IOHIDManagerSetDeviceMatching(hidManager, matchDict);
    CFRelease(matchDict);

    // Register callbacks
    IOHIDManagerRegisterInputValueCallback(hidManager, hidInputCallback, NULL);
    IOHIDManagerRegisterDeviceMatchingCallback(hidManager, hidDeviceMatchingCallback, NULL);
    IOHIDManagerRegisterDeviceRemovalCallback(hidManager, hidDeviceRemovalCallback, NULL);

    // Start the run loop thread
    hidThreadRunning = 1;
    if (pthread_create(&hidThread, NULL, hidRunLoopThread, NULL) != 0) {
        CFRelease(hidManager);
        hidManager = NULL;
        hidThreadRunning = 0;
        return -2;
    }

    // Wait for HID monitoring to be enabled
    for (int i = 0; i < 100 && !hidEnabled; i++) {
        usleep(10000); // 10ms
    }

    if (!hidEnabled) {
        // HID monitoring failed to start (likely permissions issue)
        // Wait for thread to exit naturally then clean up safely
        if (hidThreadRunning) {
            pthread_join(hidThread, NULL);
            hidThreadRunning = 0;
        }
        // Release manager without calling Close (it was never opened successfully)
        if (hidManager != NULL) {
            CFRelease(hidManager);
            hidManager = NULL;
        }
        hidRunLoop = NULL;
        return -3;
    }

    return 0;
}

// Stop HID monitoring
void stopHIDMonitoring(void) {
    if (hidManager == NULL) {
        return;
    }

    hidEnabled = 0;

    // Stop the run loop first
    CFRunLoopRef runLoop = hidRunLoop;
    if (runLoop != NULL) {
        CFRunLoopStop(runLoop);
    }

    // Wait for thread to finish
    if (hidThreadRunning) {
        pthread_join(hidThread, NULL);
        hidThreadRunning = 0;
    }

    // Only close and unschedule if manager was successfully opened
    if (hidManagerOpened && hidManager != NULL) {
        // Note: IOHIDManagerClose internally unschedules from run loop
        IOHIDManagerClose(hidManager, kIOHIDOptionsTypeNone);
        hidManagerOpened = 0;
    }

    // Release the manager
    if (hidManager != NULL) {
        CFRelease(hidManager);
        hidManager = NULL;
    }

    hidRunLoop = NULL;
}

// Get HID keystroke count
int64_t getHIDCount(void) {
    return hidKeystrokeCount;
}

// Reset HID count
void resetHIDCount(void) {
    hidKeystrokeCount = 0;
}

// Check if HID monitoring is enabled
int isHIDEnabled(void) {
    return hidEnabled;
}
*/
import "C"

import (
	"errors"
	"sync/atomic"
)

// HIDMonitor provides direct hardware keyboard monitoring via IOKit.
// This monitors at a layer BELOW CGEventTap, where CGEventPost cannot inject.
type HIDMonitor struct {
	running atomic.Bool
}

// NewHIDMonitor creates a new HID monitor.
func NewHIDMonitor() *HIDMonitor {
	return &HIDMonitor{}
}

// Start begins HID monitoring.
func (h *HIDMonitor) Start() error {
	if h.running.Load() {
		return errors.New("HID monitor already running")
	}

	C.resetHIDCount()
	result := C.startHIDMonitoring()

	switch result {
	case 0:
		h.running.Store(true)
		return nil
	case 1:
		return errors.New("HID monitor already running")
	case -1:
		return errors.New("failed to create HID manager")
	case -2:
		return errors.New("failed to create HID run loop thread")
	case -3:
		return errors.New("timeout waiting for HID monitoring to start")
	default:
		return errors.New("unknown HID monitoring error")
	}
}

// Stop stops HID monitoring.
func (h *HIDMonitor) Stop() {
	if !h.running.Load() {
		return
	}
	C.stopHIDMonitoring()
	h.running.Store(false)
}

// Count returns the number of hardware keystrokes detected.
func (h *HIDMonitor) Count() int64 {
	return int64(C.getHIDCount())
}

// Reset resets the HID keystroke count.
func (h *HIDMonitor) Reset() {
	C.resetHIDCount()
}

// IsRunning returns whether HID monitoring is active.
func (h *HIDMonitor) IsRunning() bool {
	return h.running.Load() && C.isHIDEnabled() == 1
}
