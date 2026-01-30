//go:build windows && cgo

package keystroke

/*
#cgo LDFLAGS: -lhid -lsetupapi

#include <windows.h>
#include <setupapi.h>
#include <hidsdi.h>
#include <hidpi.h>
#include <stdint.h>
#include <stdbool.h>

// ============================================================================
// Windows HID Layer Monitoring
// ============================================================================
//
// This monitors keyboard events at the Windows HID layer, which is BELOW the
// layer where SendInput injects synthetic events.
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
//   │  Windows HID Layer ◄── WE MONITOR HERE (hidKeystrokeCount)
//   │  (HID API)                      │
//   └─────────────────────────────────┘
//         │
//         ▼
//   ┌─────────────────────────────────┐
//   │  Raw Input / Input Layer ◄── SendInput INJECTS HERE
//   │  (keyboard_event)               │
//   └─────────────────────────────────┘
//         │
//         ▼
//   Application
//
// By monitoring at BOTH layers and comparing counts:
// - If Raw Input count > HID count → synthetic events detected
// - If counts match → likely all hardware events
//
// SendInput CANNOT inject at the HID layer because:
// 1. HID events come from kernel HID drivers
// 2. Only actual USB/Bluetooth HID reports trigger HID callbacks
// 3. There is no userspace API to inject at this level
//
// ============================================================================

// HID layer keystroke count (hardware only)
static volatile int64_t hidKeystrokeCount = 0;

// Device handles
#define MAX_HID_DEVICES 16
static HANDLE hidDevices[MAX_HID_DEVICES];
static int numHidDevices = 0;

// Thread state
static HANDLE hidThread = NULL;
static volatile int hidEnabled = 0;
static volatile int hidThreadRunning = 0;
static HANDLE stopEvent = NULL;

// Forward declarations
void stopHIDMonitoringWindows(void);

// Find and open keyboard HID devices
static int openKeyboardDevices(void) {
    GUID hidGuid;
    HDEVINFO deviceInfoSet;
    SP_DEVICE_INTERFACE_DATA deviceInterfaceData;
    DWORD i;

    numHidDevices = 0;

    // Get the HID GUID
    HidD_GetHidGuid(&hidGuid);

    // Get device information set for all present HID devices
    deviceInfoSet = SetupDiGetClassDevsW(&hidGuid, NULL, NULL,
        DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (deviceInfoSet == INVALID_HANDLE_VALUE) {
        return -1;
    }

    deviceInterfaceData.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);

    // Enumerate HID devices
    for (i = 0; SetupDiEnumDeviceInterfaces(deviceInfoSet, NULL, &hidGuid, i, &deviceInterfaceData); i++) {
        if (numHidDevices >= MAX_HID_DEVICES) {
            break;
        }

        DWORD requiredSize = 0;
        SetupDiGetDeviceInterfaceDetailW(deviceInfoSet, &deviceInterfaceData, NULL, 0, &requiredSize, NULL);

        if (requiredSize == 0) {
            continue;
        }

        PSP_DEVICE_INTERFACE_DETAIL_DATA_W detailData = (PSP_DEVICE_INTERFACE_DETAIL_DATA_W)malloc(requiredSize);
        if (!detailData) {
            continue;
        }

        detailData->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);

        if (!SetupDiGetDeviceInterfaceDetailW(deviceInfoSet, &deviceInterfaceData, detailData, requiredSize, NULL, NULL)) {
            free(detailData);
            continue;
        }

        // Try to open the device
        HANDLE hDevice = CreateFileW(
            detailData->DevicePath,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED,
            NULL
        );

        free(detailData);

        if (hDevice == INVALID_HANDLE_VALUE) {
            continue;
        }

        // Check if it's a keyboard
        PHIDP_PREPARSED_DATA preparsedData = NULL;
        if (HidD_GetPreparsedData(hDevice, &preparsedData)) {
            HIDP_CAPS caps;
            if (HidP_GetCaps(preparsedData, &caps) == HIDP_STATUS_SUCCESS) {
                // Usage Page 0x01 (Generic Desktop), Usage 0x06 (Keyboard)
                if (caps.UsagePage == 0x01 && caps.Usage == 0x06) {
                    hidDevices[numHidDevices++] = hDevice;
                    HidD_FreePreparsedData(preparsedData);
                    continue;
                }
            }
            HidD_FreePreparsedData(preparsedData);
        }

        // Not a keyboard, close handle
        CloseHandle(hDevice);
    }

    SetupDiDestroyDeviceInfoList(deviceInfoSet);

    return numHidDevices;
}

// Close all HID devices
static void closeHidDevices(void) {
    for (int i = 0; i < numHidDevices; i++) {
        if (hidDevices[i] != INVALID_HANDLE_VALUE) {
            CloseHandle(hidDevices[i]);
            hidDevices[i] = INVALID_HANDLE_VALUE;
        }
    }
    numHidDevices = 0;
}

// HID monitoring thread
static DWORD WINAPI hidMonitorThread(LPVOID lpParam) {
    (void)lpParam;

    hidThreadRunning = 1;
    hidEnabled = 1;

    // Create overlapped events for each device
    HANDLE events[MAX_HID_DEVICES + 1];
    OVERLAPPED overlapped[MAX_HID_DEVICES];
    BYTE inputBuffer[MAX_HID_DEVICES][256];
    BOOL pendingRead[MAX_HID_DEVICES];

    events[0] = stopEvent;

    for (int i = 0; i < numHidDevices; i++) {
        memset(&overlapped[i], 0, sizeof(OVERLAPPED));
        overlapped[i].hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        events[i + 1] = overlapped[i].hEvent;
        pendingRead[i] = FALSE;
    }

    // Start overlapped reads
    for (int i = 0; i < numHidDevices; i++) {
        if (ReadFile(hidDevices[i], inputBuffer[i], sizeof(inputBuffer[i]), NULL, &overlapped[i])) {
            pendingRead[i] = TRUE;
        } else if (GetLastError() == ERROR_IO_PENDING) {
            pendingRead[i] = TRUE;
        }
    }

    // Main loop
    while (hidEnabled) {
        DWORD result = WaitForMultipleObjects(numHidDevices + 1, events, FALSE, 1000);

        if (result == WAIT_OBJECT_0) {
            // Stop event signaled
            break;
        } else if (result >= WAIT_OBJECT_0 + 1 && result < WAIT_OBJECT_0 + 1 + numHidDevices) {
            int deviceIndex = result - WAIT_OBJECT_0 - 1;

            DWORD bytesRead = 0;
            if (GetOverlappedResult(hidDevices[deviceIndex], &overlapped[deviceIndex], &bytesRead, FALSE)) {
                // Process HID report - look for key presses
                // HID keyboard reports typically have modifier byte + 6 key codes
                if (bytesRead >= 3) {
                    // Check for non-zero key codes (key pressed)
                    for (int j = 2; j < (int)bytesRead && j < 8; j++) {
                        if (inputBuffer[deviceIndex][j] != 0) {
                            hidKeystrokeCount++;
                            break; // Only count once per report
                        }
                    }
                }
            }

            // Start next read
            ResetEvent(overlapped[deviceIndex].hEvent);
            if (!ReadFile(hidDevices[deviceIndex], inputBuffer[deviceIndex], sizeof(inputBuffer[deviceIndex]), NULL, &overlapped[deviceIndex])) {
                if (GetLastError() != ERROR_IO_PENDING) {
                    pendingRead[deviceIndex] = FALSE;
                }
            }
        }
    }

    // Cleanup overlapped events
    for (int i = 0; i < numHidDevices; i++) {
        CancelIo(hidDevices[i]);
        CloseHandle(overlapped[i].hEvent);
    }

    hidEnabled = 0;
    hidThreadRunning = 0;

    return 0;
}

// Start HID monitoring
int startHIDMonitoringWindows(void) {
    if (hidThread != NULL) {
        return 1; // Already running
    }

    hidKeystrokeCount = 0;

    // Open keyboard devices
    if (openKeyboardDevices() <= 0) {
        return -1; // No keyboard HID devices found
    }

    // Create stop event
    stopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (stopEvent == NULL) {
        closeHidDevices();
        return -2;
    }

    // Start monitoring thread
    hidThread = CreateThread(NULL, 0, hidMonitorThread, NULL, 0, NULL);
    if (hidThread == NULL) {
        CloseHandle(stopEvent);
        stopEvent = NULL;
        closeHidDevices();
        return -3;
    }

    // Wait for thread to start
    for (int i = 0; i < 100 && !hidEnabled; i++) {
        Sleep(10);
    }

    if (!hidEnabled) {
        stopHIDMonitoringWindows();
        return -4;
    }

    return 0;
}

// Stop HID monitoring
void stopHIDMonitoringWindows(void) {
    if (hidThread == NULL) {
        return;
    }

    hidEnabled = 0;

    // Signal stop event
    if (stopEvent != NULL) {
        SetEvent(stopEvent);
    }

    // Wait for thread to exit
    if (hidThread != NULL) {
        WaitForSingleObject(hidThread, 5000);
        CloseHandle(hidThread);
        hidThread = NULL;
    }

    if (stopEvent != NULL) {
        CloseHandle(stopEvent);
        stopEvent = NULL;
    }

    closeHidDevices();
}

// Get HID keystroke count
int64_t getHIDCountWindows(void) {
    return hidKeystrokeCount;
}

// Reset HID count
void resetHIDCountWindows(void) {
    hidKeystrokeCount = 0;
}

// Check if HID monitoring is enabled
int isHIDEnabledWindows(void) {
    return hidEnabled;
}
*/
import "C"

import (
	"errors"
	"sync/atomic"
)

// HIDMonitor provides direct hardware keyboard monitoring via Windows HID API.
// This monitors at a layer BELOW Raw Input, where SendInput cannot inject.
type HIDMonitor struct {
	running atomic.Bool
}

// NewHIDMonitor creates a new HID monitor for Windows.
func NewHIDMonitor() *HIDMonitor {
	return &HIDMonitor{}
}

// Start begins HID monitoring.
func (h *HIDMonitor) Start() error {
	if h.running.Load() {
		return errors.New("HID monitor already running")
	}

	C.resetHIDCountWindows()
	result := C.startHIDMonitoringWindows()

	switch result {
	case 0:
		h.running.Store(true)
		return nil
	case 1:
		return errors.New("HID monitor already running")
	case -1:
		return errors.New("no keyboard HID devices found")
	case -2:
		return errors.New("failed to create stop event")
	case -3:
		return errors.New("failed to create HID monitoring thread")
	case -4:
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
	C.stopHIDMonitoringWindows()
	h.running.Store(false)
}

// Count returns the number of hardware keystrokes detected.
func (h *HIDMonitor) Count() int64 {
	return int64(C.getHIDCountWindows())
}

// Reset resets the HID keystroke count.
func (h *HIDMonitor) Reset() {
	C.resetHIDCountWindows()
}

// IsRunning returns whether HID monitoring is active.
func (h *HIDMonitor) IsRunning() bool {
	return h.running.Load() && C.isHIDEnabledWindows() == 1
}
