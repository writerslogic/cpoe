//go:build windows && cgo

package keystroke

/*
#cgo LDFLAGS: -luser32

#include <windows.h>
#include <stdint.h>

// ============================================================================
// Windows Raw Input API for Keystroke Monitoring
// ============================================================================
//
// We use the Raw Input API rather than SetWindowsHookEx because:
// 1. Raw Input receives data directly from the HID driver
// 2. It's harder to spoof than application-level hooks
// 3. It works even when the app is not focused (with RIDEV_INPUTSINK)
//
// However, synthetic keystrokes injected via SendInput DO appear in Raw Input.
// To detect synthetic events, we also check the LLKHF_INJECTED flag via a
// low-level keyboard hook.
//
// Architecture:
//
//   Physical Keyboard
//         │
//         ▼
//   HID Driver (kernel)
//         │
//         ▼
//   ┌─────────────────────────────────┐
//   │  Raw Input API    ◄── We monitor here (primary count)
//   └─────────────────────────────────┘
//         │
//         ▼
//   ┌─────────────────────────────────┐
//   │  Low-Level Hook   ◄── We check LLKHF_INJECTED flag here
//   │  (WH_KEYBOARD_LL)              │
//   └─────────────────────────────────┘
//         │
//         ▼
//   Application
//
// ============================================================================

// Keystroke counter (all raw input events)
static volatile int64_t keystrokeCount = 0;

// Synthetic/suspicious event counters
static volatile int64_t injectedCount = 0;
static volatile int64_t suspiciousCount = 0;
static volatile int64_t totalEventsSeen = 0;

// Mode control
static volatile int strictMode = 1;

// Window and thread handles
static HWND messageWindow = NULL;
static HANDLE threadHandle = NULL;
static DWORD threadId = 0;
static volatile int running = 0;

// Low-level keyboard hook handle
static HHOOK keyboardHook = NULL;

// Message window class name
static const wchar_t* CLASS_NAME = L"WitnessdKeystrokeClass";

// Forward declarations
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam);
DWORD WINAPI MessageThreadProc(LPVOID lpParam);

// Low-level keyboard hook procedure
// This is used to detect injected/synthetic events
LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION) {
        KBDLLHOOKSTRUCT* kb = (KBDLLHOOKSTRUCT*)lParam;

        // Check for injected events
        // LLKHF_INJECTED (0x10) is set for events injected via SendInput, keybd_event, etc.
        // LLKHF_LOWER_IL_INJECTED (0x02) is set for events from a lower integrity process
        if (kb->flags & 0x10) { // LLKHF_INJECTED
            injectedCount++;
        }
        if (kb->flags & 0x02) { // LLKHF_LOWER_IL_INJECTED
            suspiciousCount++;
        }
    }
    return CallNextHookEx(keyboardHook, nCode, wParam, lParam);
}

// Window procedure for receiving Raw Input messages
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    if (uMsg == WM_INPUT) {
        UINT dwSize = 0;

        // Get required buffer size
        GetRawInputData((HRAWINPUT)lParam, RID_INPUT, NULL, &dwSize, sizeof(RAWINPUTHEADER));

        if (dwSize > 0 && dwSize < 1024) {
            BYTE buffer[1024];

            if (GetRawInputData((HRAWINPUT)lParam, RID_INPUT, buffer, &dwSize, sizeof(RAWINPUTHEADER)) == dwSize) {
                RAWINPUT* raw = (RAWINPUT*)buffer;

                if (raw->header.dwType == RIM_TYPEKEYBOARD) {
                    totalEventsSeen++;

                    // Only count key down events (not key up)
                    // WM_KEYDOWN = 0x100, WM_SYSKEYDOWN = 0x104
                    USHORT msg = raw->data.keyboard.Message;
                    if (msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN) {
                        // In strict mode, don't count if we detected injection
                        if (strictMode && injectedCount > keystrokeCount) {
                            // More injected than counted - synthetic detected
                            suspiciousCount++;
                        } else {
                            keystrokeCount++;
                        }
                    }
                }
            }
        }

        return 0;
    }

    if (uMsg == WM_DESTROY) {
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hwnd, uMsg, wParam, lParam);
}

// Message loop thread
DWORD WINAPI MessageThreadProc(LPVOID lpParam) {
    (void)lpParam;

    // Register window class
    WNDCLASSEXW wc = {0};
    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = CLASS_NAME;

    if (!RegisterClassExW(&wc)) {
        running = 0;
        return 1;
    }

    // Create message-only window
    messageWindow = CreateWindowExW(
        0,
        CLASS_NAME,
        L"Witnessd Keystroke Monitor",
        0,
        0, 0, 0, 0,
        HWND_MESSAGE,  // Message-only window
        NULL,
        GetModuleHandleW(NULL),
        NULL
    );

    if (!messageWindow) {
        UnregisterClassW(CLASS_NAME, GetModuleHandleW(NULL));
        running = 0;
        return 1;
    }

    // Register for Raw Input from keyboards
    RAWINPUTDEVICE rid;
    rid.usUsagePage = 0x01;  // Generic Desktop
    rid.usUsage = 0x06;       // Keyboard
    rid.dwFlags = RIDEV_INPUTSINK;  // Receive input even when not focused
    rid.hwndTarget = messageWindow;

    if (!RegisterRawInputDevices(&rid, 1, sizeof(rid))) {
        DestroyWindow(messageWindow);
        UnregisterClassW(CLASS_NAME, GetModuleHandleW(NULL));
        messageWindow = NULL;
        running = 0;
        return 1;
    }

    // Install low-level keyboard hook for injection detection
    keyboardHook = SetWindowsHookExW(WH_KEYBOARD_LL, LowLevelKeyboardProc, GetModuleHandleW(NULL), 0);
    if (!keyboardHook) {
        // Continue without injection detection
        suspiciousCount = -1; // Indicate hook not available
    }

    running = 1;

    // Message loop
    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    // Cleanup
    if (keyboardHook) {
        UnhookWindowsHookEx(keyboardHook);
        keyboardHook = NULL;
    }

    if (messageWindow) {
        DestroyWindow(messageWindow);
        messageWindow = NULL;
    }

    UnregisterClassW(CLASS_NAME, GetModuleHandleW(NULL));
    running = 0;

    return 0;
}

// Start keystroke monitoring
int startWindowsMonitoring(void) {
    if (running) {
        return 1; // Already running
    }

    keystrokeCount = 0;
    injectedCount = 0;
    suspiciousCount = 0;
    totalEventsSeen = 0;

    threadHandle = CreateThread(NULL, 0, MessageThreadProc, NULL, 0, &threadId);
    if (!threadHandle) {
        return -1;
    }

    // Wait for thread to initialize
    for (int i = 0; i < 100 && !running; i++) {
        Sleep(10);
    }

    if (!running) {
        return -2;
    }

    return 0;
}

// Stop keystroke monitoring
void stopWindowsMonitoring(void) {
    if (!running) {
        return;
    }

    running = 0;

    if (messageWindow) {
        PostMessageW(messageWindow, WM_CLOSE, 0, 0);
    }

    if (threadHandle) {
        WaitForSingleObject(threadHandle, 5000);
        CloseHandle(threadHandle);
        threadHandle = NULL;
    }
}

// Get keystroke count
int64_t getWindowsKeystrokeCount(void) {
    return keystrokeCount;
}

// Get injection statistics
int64_t getWindowsInjectedCount(void) {
    return injectedCount;
}

int64_t getWindowsSuspiciousCount(void) {
    return suspiciousCount;
}

int64_t getWindowsTotalEventsSeen(void) {
    return totalEventsSeen;
}

// Reset counters
void resetWindowsCounters(void) {
    keystrokeCount = 0;
    injectedCount = 0;
    suspiciousCount = 0;
    totalEventsSeen = 0;
}

// Mode control
void setWindowsStrictMode(int strict) {
    strictMode = strict;
}

int getWindowsStrictMode(void) {
    return strictMode;
}

int isWindowsMonitoringRunning(void) {
    return running;
}
*/
import "C"

import (
	"context"
	"errors"
	"sync"
	"time"
)

// WindowsCounter uses Raw Input API for keyboard counting on Windows.
type WindowsCounter struct {
	BaseCounter
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}

	mu sync.RWMutex
}

func newPlatformCounter() Counter {
	return &WindowsCounter{}
}

// Available checks if keystroke monitoring is available.
func (w *WindowsCounter) Available() (bool, string) {
	// Raw Input API is always available on Windows
	return true, "Windows Raw Input API available"
}

// Start begins counting keyboard events.
func (w *WindowsCounter) Start(ctx context.Context) error {
	if w.IsRunning() {
		return ErrAlreadyRunning
	}

	C.resetWindowsCounters()
	result := C.startWindowsMonitoring()

	switch result {
	case 0:
		// Success
	case 1:
		return errors.New("monitoring already running")
	case -1:
		return errors.New("failed to create monitoring thread")
	case -2:
		return errors.New("timeout waiting for monitoring to start")
	default:
		return errors.New("unknown monitoring error")
	}

	w.ctx, w.cancel = context.WithCancel(ctx)
	w.done = make(chan struct{})
	w.SetRunning(true)

	// Start polling loop to sync counts
	go w.pollLoop()

	return nil
}

// pollLoop synchronizes the C counter with the Go counter.
func (w *WindowsCounter) pollLoop() {
	defer close(w.done)

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	var lastCount int64
	for {
		select {
		case <-w.ctx.Done():
			return
		case <-ticker.C:
			count := int64(C.getWindowsKeystrokeCount())
			if count > lastCount {
				delta := count - lastCount
				for i := int64(0); i < delta; i++ {
					w.Increment()
				}
				lastCount = count
			}
		}
	}
}

// Stop stops counting.
func (w *WindowsCounter) Stop() error {
	if !w.IsRunning() {
		return nil
	}

	w.SetRunning(false)

	if w.cancel != nil {
		w.cancel()
	}

	C.stopWindowsMonitoring()

	if w.done != nil {
		<-w.done
	}

	w.CloseListeners()
	return nil
}

// SetStrictMode controls whether injected events are counted.
func (w *WindowsCounter) SetStrictMode(strict bool) {
	if strict {
		C.setWindowsStrictMode(1)
	} else {
		C.setWindowsStrictMode(0)
	}
}

// SyntheticEventStats returns statistics about detected synthetic events.
func (w *WindowsCounter) SyntheticEventStats() SyntheticEventStats {
	return SyntheticEventStats{
		TotalRejected:   int64(C.getWindowsInjectedCount()),
		Suspicious:      int64(C.getWindowsSuspiciousCount()),
		TotalEventsSeen: int64(C.getWindowsTotalEventsSeen()),
	}
}

// InjectionAttemptDetected returns true if synthetic injection was detected.
func (w *WindowsCounter) InjectionAttemptDetected() bool {
	return int64(C.getWindowsInjectedCount()) > 0
}

// SyntheticRejectionRate returns the percentage of events that were synthetic.
func (w *WindowsCounter) SyntheticRejectionRate() float64 {
	total := int64(C.getWindowsTotalEventsSeen())
	if total == 0 {
		return 0
	}
	injected := int64(C.getWindowsInjectedCount())
	return float64(injected) / float64(total) * 100
}

// ResetAllCounters resets keystroke and synthetic detection counters.
func (w *WindowsCounter) ResetAllCounters() {
	C.resetWindowsCounters()
	w.mu.Lock()
	w.count = 0
	w.mu.Unlock()
}

// FocusedWindow returns the currently focused window title.
func FocusedWindow() (string, error) {
	// Could use GetForegroundWindow + GetWindowText
	return "", errors.New("not implemented")
}
