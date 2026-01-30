//go:build windows && cgo

package keystroke

/*
#cgo LDFLAGS: -lhid -lsetupapi

#include <windows.h>
#include <setupapi.h>
#include <hidsdi.h>
#include <hidpi.h>
#include <cfgmgr32.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

// Maximum devices we can track
#define MAX_KEYBOARD_DEVICES_WIN 32

// Device info structure
typedef struct {
    uint16_t vendorID;
    uint16_t productID;
    uint16_t versionNum;
    wchar_t vendorName[256];
    wchar_t productName[256];
    wchar_t serialNumber[256];
    wchar_t devicePath[512];
    int connectionType; // 0=unknown, 1=usb, 2=bluetooth, 3=ps2, 4=internal, 5=virtual
} KeyboardDeviceInfoWin;

// Determine connection type from device path
static int determineConnectionTypeWin(const wchar_t* devicePath) {
    // USB devices typically have paths like \\?\HID#VID_046D&PID_C52B
    if (wcsstr(devicePath, L"USB") != NULL ||
        wcsstr(devicePath, L"HID#VID_") != NULL) {
        return 1; // USB
    }

    // Bluetooth devices have paths with BTHLE or BTH
    if (wcsstr(devicePath, L"BTHLE") != NULL ||
        wcsstr(devicePath, L"BTH") != NULL) {
        return 2; // Bluetooth
    }

    // PS/2 devices (rare on modern systems)
    if (wcsstr(devicePath, L"ACPI") != NULL ||
        wcsstr(devicePath, L"PS2") != NULL) {
        return 3; // PS/2
    }

    // Virtual devices
    if (wcsstr(devicePath, L"VIRTUAL") != NULL ||
        wcsstr(devicePath, L"Root#RDP") != NULL) {
        return 5; // Virtual
    }

    return 0; // Unknown
}

// Enumerate all keyboard HID devices
int enumerateKeyboardsWindows(KeyboardDeviceInfoWin* devices, int maxDevices) {
    GUID hidGuid;
    HDEVINFO deviceInfoSet;
    SP_DEVICE_INTERFACE_DATA deviceInterfaceData;
    DWORD i;
    int count = 0;

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
        if (count >= maxDevices) {
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

        SP_DEVINFO_DATA devInfoData;
        devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

        if (!SetupDiGetDeviceInterfaceDetailW(deviceInfoSet, &deviceInterfaceData, detailData, requiredSize, NULL, &devInfoData)) {
            free(detailData);
            continue;
        }

        // Try to open the device
        HANDLE hDevice = CreateFileW(
            detailData->DevicePath,
            0,  // Just query, no read/write needed for info
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            0,
            NULL
        );

        if (hDevice == INVALID_HANDLE_VALUE) {
            free(detailData);
            continue;
        }

        // Check if it's a keyboard
        PHIDP_PREPARSED_DATA preparsedData = NULL;
        BOOLEAN gotPreparsed = HidD_GetPreparsedData(hDevice, &preparsedData);

        if (gotPreparsed) {
            HIDP_CAPS caps;
            if (HidP_GetCaps(preparsedData, &caps) == HIDP_STATUS_SUCCESS) {
                // Usage Page 0x01 (Generic Desktop), Usage 0x06 (Keyboard)
                if (caps.UsagePage == 0x01 && caps.Usage == 0x06) {
                    KeyboardDeviceInfoWin* dev = &devices[count];
                    memset(dev, 0, sizeof(KeyboardDeviceInfoWin));

                    // Get attributes (VID, PID, Version)
                    HIDD_ATTRIBUTES attributes;
                    attributes.Size = sizeof(HIDD_ATTRIBUTES);
                    if (HidD_GetAttributes(hDevice, &attributes)) {
                        dev->vendorID = attributes.VendorID;
                        dev->productID = attributes.ProductID;
                        dev->versionNum = attributes.VersionNumber;
                    }

                    // Get manufacturer string
                    HidD_GetManufacturerString(hDevice, dev->vendorName, sizeof(dev->vendorName));

                    // Get product string
                    HidD_GetProductString(hDevice, dev->productName, sizeof(dev->productName));

                    // Get serial number
                    HidD_GetSerialNumberString(hDevice, dev->serialNumber, sizeof(dev->serialNumber));

                    // Store device path
                    wcsncpy(dev->devicePath, detailData->DevicePath, 511);
                    dev->devicePath[511] = L'\0';

                    // Determine connection type
                    dev->connectionType = determineConnectionTypeWin(detailData->DevicePath);

                    count++;
                }
            }
            HidD_FreePreparsedData(preparsedData);
        }

        CloseHandle(hDevice);
        free(detailData);
    }

    SetupDiDestroyDeviceInfoList(deviceInfoSet);

    return count;
}

// Device notification for watching
static HDEVNOTIFY g_deviceNotify = NULL;
static HWND g_notifyWindow = NULL;
static HANDLE g_watchThread = NULL;
static volatile int g_watchEnabled = 0;

// Callback function type
typedef void (*DeviceChangeCallbackWin)(KeyboardDeviceInfoWin*, int);
static DeviceChangeCallbackWin g_changeCallbackWin = NULL;

// Window class name for device notifications
static const wchar_t* NOTIFY_WINDOW_CLASS = L"WitnessdDeviceNotify";

// Window procedure for device notifications
static LRESULT CALLBACK notifyWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_DEVICECHANGE) {
        if (wParam == DBT_DEVICEARRIVAL || wParam == DBT_DEVICEREMOVECOMPLETE) {
            // Device added or removed - re-enumerate and notify
            if (g_changeCallbackWin) {
                KeyboardDeviceInfoWin devices[MAX_KEYBOARD_DEVICES_WIN];
                int count = enumerateKeyboardsWindows(devices, MAX_KEYBOARD_DEVICES_WIN);

                // For simplicity, just notify about device changes
                // A proper implementation would track and compare device lists
                for (int i = 0; i < count; i++) {
                    g_changeCallbackWin(&devices[i], (wParam == DBT_DEVICEARRIVAL) ? 0 : 1);
                }
            }
        }
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

// Watch thread
static DWORD WINAPI watchThreadWin(LPVOID lpParam) {
    (void)lpParam;

    // Register window class
    WNDCLASSEXW wc;
    memset(&wc, 0, sizeof(wc));
    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.lpfnWndProc = notifyWndProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = NOTIFY_WINDOW_CLASS;
    RegisterClassExW(&wc);

    // Create message-only window
    g_notifyWindow = CreateWindowExW(
        0,
        NOTIFY_WINDOW_CLASS,
        L"Witnessd Device Notify",
        0,
        0, 0, 0, 0,
        HWND_MESSAGE,
        NULL,
        GetModuleHandle(NULL),
        NULL
    );

    if (!g_notifyWindow) {
        return 1;
    }

    // Register for device notifications
    DEV_BROADCAST_DEVICEINTERFACE_W notifyFilter;
    memset(&notifyFilter, 0, sizeof(notifyFilter));
    notifyFilter.dbcc_size = sizeof(DEV_BROADCAST_DEVICEINTERFACE_W);
    notifyFilter.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;

    GUID hidGuid;
    HidD_GetHidGuid(&hidGuid);
    notifyFilter.dbcc_classguid = hidGuid;

    g_deviceNotify = RegisterDeviceNotificationW(
        g_notifyWindow,
        &notifyFilter,
        DEVICE_NOTIFY_WINDOW_HANDLE
    );

    g_watchEnabled = 1;

    // Message loop
    MSG msg;
    while (g_watchEnabled && GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    // Cleanup
    if (g_deviceNotify) {
        UnregisterDeviceNotification(g_deviceNotify);
        g_deviceNotify = NULL;
    }

    if (g_notifyWindow) {
        DestroyWindow(g_notifyWindow);
        g_notifyWindow = NULL;
    }

    UnregisterClassW(NOTIFY_WINDOW_CLASS, GetModuleHandle(NULL));

    return 0;
}

// Start watching for device changes
int startDeviceWatchingWindows(DeviceChangeCallbackWin callback) {
    if (g_watchThread) {
        return 1; // Already watching
    }

    g_changeCallbackWin = callback;
    g_watchEnabled = 0;

    g_watchThread = CreateThread(NULL, 0, watchThreadWin, NULL, 0, NULL);
    if (!g_watchThread) {
        return -1;
    }

    // Wait for thread to start
    for (int i = 0; i < 100 && !g_watchEnabled; i++) {
        Sleep(10);
    }

    return g_watchEnabled ? 0 : -2;
}

// Stop watching for device changes
void stopDeviceWatchingWindows(void) {
    if (!g_watchThread) {
        return;
    }

    g_watchEnabled = 0;

    // Post quit message to window
    if (g_notifyWindow) {
        PostMessageW(g_notifyWindow, WM_QUIT, 0, 0);
    }

    WaitForSingleObject(g_watchThread, 5000);
    CloseHandle(g_watchThread);
    g_watchThread = NULL;
    g_changeCallbackWin = NULL;
}
*/
import "C"

import (
	"errors"
	"sync"
	"syscall"
	"unsafe"
)

// windowsDeviceAccessor implements DeviceAccessor for Windows.
type windowsDeviceAccessor struct {
	mu       sync.Mutex
	callback func(KeyboardDevice, DeviceEventType)
	watching bool
}

// newPlatformDeviceAccessor creates a Windows device accessor.
func newPlatformDeviceAccessor() DeviceAccessor {
	return &windowsDeviceAccessor{}
}

// EnumerateKeyboards returns all connected keyboard devices.
func (d *windowsDeviceAccessor) EnumerateKeyboards() ([]KeyboardDevice, error) {
	const maxDevices = 32
	var cDevices [maxDevices]C.KeyboardDeviceInfoWin

	count := C.enumerateKeyboardsWindows(&cDevices[0], C.int(maxDevices))
	if count < 0 {
		return nil, errors.New("failed to enumerate keyboards")
	}

	devices := make([]KeyboardDevice, 0, count)
	for i := 0; i < int(count); i++ {
		dev := cDeviceWinToGo(&cDevices[i])
		devices = append(devices, dev)
	}

	return devices, nil
}

// cDeviceWinToGo converts a C KeyboardDeviceInfoWin to Go KeyboardDevice.
func cDeviceWinToGo(cDev *C.KeyboardDeviceInfoWin) KeyboardDevice {
	dev := KeyboardDevice{
		VendorID:       uint16(cDev.vendorID),
		ProductID:      uint16(cDev.productID),
		VersionNum:     uint16(cDev.versionNum),
		VendorName:     wcharToString(&cDev.vendorName[0], 256),
		ProductName:    wcharToString(&cDev.productName[0], 256),
		SerialNumber:   wcharToString(&cDev.serialNumber[0], 256),
		DevicePath:     wcharToString(&cDev.devicePath[0], 512),
		ConnectionType: ConnectionType(cDev.connectionType),
	}

	// Look up vendor name if not provided by HID
	if dev.VendorName == "" {
		dev.VendorName = LookupVendorName(dev.VendorID)
	}

	return dev
}

// wcharToString converts a wide character array to Go string.
func wcharToString(wstr *C.wchar_t, maxLen int) string {
	if wstr == nil {
		return ""
	}

	// Find string length
	ptr := (*[1 << 20]uint16)(unsafe.Pointer(wstr))
	length := 0
	for i := 0; i < maxLen && ptr[i] != 0; i++ {
		length++
	}

	if length == 0 {
		return ""
	}

	return syscall.UTF16ToString(ptr[:length])
}

// StartWatching begins watching for device changes.
func (d *windowsDeviceAccessor) StartWatching(callback func(KeyboardDevice, DeviceEventType)) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.watching {
		return errors.New("already watching")
	}

	d.callback = callback

	// For Windows, we use polling approach since the C callback integration is complex
	d.watching = true
	go d.pollDevices()

	return nil
}

// pollDevices polls for device changes periodically.
func (d *windowsDeviceAccessor) pollDevices() {
	initialDevices, _ := d.EnumerateKeyboards()
	knownDevices := make(map[string]KeyboardDevice)
	for _, dev := range initialDevices {
		knownDevices[dev.DevicePath] = dev
	}

	ticker := make(chan struct{})
	go func() {
		for d.watching {
			C.Sleep(2000) // 2 second poll interval
			select {
			case ticker <- struct{}{}:
			default:
			}
		}
		close(ticker)
	}()

	for range ticker {
		if !d.watching {
			return
		}

		newDevices, err := d.EnumerateKeyboards()
		if err != nil {
			continue
		}

		newKnown := make(map[string]KeyboardDevice)
		for _, dev := range newDevices {
			newKnown[dev.DevicePath] = dev
			if _, exists := knownDevices[dev.DevicePath]; !exists {
				d.mu.Lock()
				cb := d.callback
				d.mu.Unlock()
				if cb != nil {
					cb(dev, DeviceConnected)
				}
			}
		}

		for path, dev := range knownDevices {
			if _, exists := newKnown[path]; !exists {
				d.mu.Lock()
				cb := d.callback
				d.mu.Unlock()
				if cb != nil {
					cb(dev, DeviceDisconnected)
				}
			}
		}

		knownDevices = newKnown
	}
}

// StopWatching stops watching for device changes.
func (d *windowsDeviceAccessor) StopWatching() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.watching {
		return nil
	}

	d.watching = false
	d.callback = nil
	return nil
}
