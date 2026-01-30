//go:build darwin

package keystroke

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework IOKit -framework CoreFoundation -framework Foundation

#include <IOKit/hid/IOHIDManager.h>
#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
#include <string.h>

// Device info structure - use unique prefix to avoid conflicts
typedef struct {
    uint16_t vendorID;
    uint16_t productID;
    uint16_t versionNum;
    char vendorName[256];
    char productName[256];
    char serialNumber[256];
    char devicePath[512];
    int connectionType;
} WitnessdKbdDevInfo;

// All helper functions are static to avoid duplicate symbol issues
static void wkdi_getStringProp(IOHIDDeviceRef device, CFStringRef key, char* buffer, size_t bufSize) {
    buffer[0] = '\0';
    CFTypeRef prop = IOHIDDeviceGetProperty(device, key);
    if (prop && CFGetTypeID(prop) == CFStringGetTypeID()) {
        CFStringGetCString((CFStringRef)prop, buffer, bufSize, kCFStringEncodingUTF8);
    }
}

static uint32_t wkdi_getIntProp(IOHIDDeviceRef device, CFStringRef key) {
    CFTypeRef prop = IOHIDDeviceGetProperty(device, key);
    if (prop && CFGetTypeID(prop) == CFNumberGetTypeID()) {
        int32_t value = 0;
        CFNumberGetValue((CFNumberRef)prop, kCFNumberSInt32Type, &value);
        return (uint32_t)value;
    }
    return 0;
}

static int wkdi_connType(IOHIDDeviceRef device) {
    char transport[64] = "";
    wkdi_getStringProp(device, CFSTR(kIOHIDTransportKey), transport, sizeof(transport));

    if (strcasecmp(transport, "USB") == 0) return 1;
    if (strcasecmp(transport, "Bluetooth") == 0 ||
        strcasecmp(transport, "BluetoothLowEnergy") == 0) return 2;
    if (strcasecmp(transport, "ADB") == 0) return 3;
    if (strcasecmp(transport, "SPI") == 0 ||
        strcasecmp(transport, "Built-in") == 0) return 4;

    uint16_t vid = wkdi_getIntProp(device, CFSTR(kIOHIDVendorIDKey));
    char product[256] = "";
    wkdi_getStringProp(device, CFSTR(kIOHIDProductKey), product, sizeof(product));
    if (vid == 0x05AC && (strstr(product, "Internal") || strstr(product, "TouchBar"))) {
        return 4;
    }
    return 0;
}

static void wkdi_populate(IOHIDDeviceRef device, WitnessdKbdDevInfo* info) {
    memset(info, 0, sizeof(WitnessdKbdDevInfo));
    info->vendorID = (uint16_t)wkdi_getIntProp(device, CFSTR(kIOHIDVendorIDKey));
    info->productID = (uint16_t)wkdi_getIntProp(device, CFSTR(kIOHIDProductIDKey));
    info->versionNum = (uint16_t)wkdi_getIntProp(device, CFSTR(kIOHIDVersionNumberKey));
    wkdi_getStringProp(device, CFSTR(kIOHIDManufacturerKey), info->vendorName, sizeof(info->vendorName));
    wkdi_getStringProp(device, CFSTR(kIOHIDProductKey), info->productName, sizeof(info->productName));
    wkdi_getStringProp(device, CFSTR(kIOHIDSerialNumberKey), info->serialNumber, sizeof(info->serialNumber));
    uint32_t locID = wkdi_getIntProp(device, CFSTR(kIOHIDLocationIDKey));
    snprintf(info->devicePath, sizeof(info->devicePath), "IOHIDDevice:0x%08x", locID);
    info->connectionType = wkdi_connType(device);
}

// Single enumeration function - returns count of devices found
static int wkdi_enum(WitnessdKbdDevInfo* devices, int maxDevices) {
    IOHIDManagerRef manager = IOHIDManagerCreate(kCFAllocatorDefault, kIOHIDOptionsTypeNone);
    if (!manager) return -1;

    CFMutableDictionaryRef matchDict = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );

    int usagePage = kHIDPage_GenericDesktop;
    int usage = kHIDUsage_GD_Keyboard;
    CFNumberRef pageNum = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &usagePage);
    CFNumberRef usageNum = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &usage);
    CFDictionarySetValue(matchDict, CFSTR(kIOHIDDeviceUsagePageKey), pageNum);
    CFDictionarySetValue(matchDict, CFSTR(kIOHIDDeviceUsageKey), usageNum);
    CFRelease(pageNum);
    CFRelease(usageNum);

    IOHIDManagerSetDeviceMatching(manager, matchDict);
    CFRelease(matchDict);

    CFSetRef deviceSet = IOHIDManagerCopyDevices(manager);
    int count = 0;

    if (deviceSet) {
        CFIndex setCount = CFSetGetCount(deviceSet);
        if (setCount > 0) {
            IOHIDDeviceRef* deviceArray = (IOHIDDeviceRef*)malloc(setCount * sizeof(IOHIDDeviceRef));
            CFSetGetValues(deviceSet, (const void**)deviceArray);
            for (CFIndex i = 0; i < setCount && count < maxDevices; i++) {
                wkdi_populate(deviceArray[i], &devices[count]);
                count++;
            }
            free(deviceArray);
        }
        CFRelease(deviceSet);
    }

    CFRelease(manager);
    return count;
}
*/
import "C"

import (
	"errors"
	"sync"
	"time"
)

// darwinDeviceAccessor implements DeviceAccessor for macOS.
type darwinDeviceAccessor struct {
	mu       sync.Mutex
	callback func(KeyboardDevice, DeviceEventType)
	watching bool
	stopCh   chan struct{}
}

// newPlatformDeviceAccessor creates a macOS device accessor.
func newPlatformDeviceAccessor() DeviceAccessor {
	return &darwinDeviceAccessor{}
}

// EnumerateKeyboards returns all connected keyboard devices.
func (d *darwinDeviceAccessor) EnumerateKeyboards() ([]KeyboardDevice, error) {
	const maxDevices = 32
	var cDevices [maxDevices]C.WitnessdKbdDevInfo

	count := C.wkdi_enum(&cDevices[0], C.int(maxDevices))
	if count < 0 {
		return nil, errors.New("failed to enumerate keyboards")
	}

	devices := make([]KeyboardDevice, 0, count)
	for i := 0; i < int(count); i++ {
		dev := cDeviceInfoToGo(&cDevices[i])
		devices = append(devices, dev)
	}

	return devices, nil
}

// cDeviceInfoToGo converts a C WitnessdKbdDevInfo to Go KeyboardDevice.
func cDeviceInfoToGo(cDev *C.WitnessdKbdDevInfo) KeyboardDevice {
	dev := KeyboardDevice{
		VendorID:       uint16(cDev.vendorID),
		ProductID:      uint16(cDev.productID),
		VersionNum:     uint16(cDev.versionNum),
		VendorName:     C.GoString(&cDev.vendorName[0]),
		ProductName:    C.GoString(&cDev.productName[0]),
		SerialNumber:   C.GoString(&cDev.serialNumber[0]),
		DevicePath:     C.GoString(&cDev.devicePath[0]),
		ConnectionType: ConnectionType(cDev.connectionType),
	}

	if dev.VendorName == "" {
		dev.VendorName = LookupVendorName(dev.VendorID)
	}

	return dev
}

// StartWatching begins watching for device changes using polling.
func (d *darwinDeviceAccessor) StartWatching(callback func(KeyboardDevice, DeviceEventType)) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.watching {
		return errors.New("already watching")
	}

	d.callback = callback
	d.stopCh = make(chan struct{})
	d.watching = true

	// Use polling approach for simplicity and to avoid CGO callback complexity
	go d.pollDevices()

	return nil
}

// pollDevices polls for device changes periodically.
func (d *darwinDeviceAccessor) pollDevices() {
	initialDevices, _ := d.EnumerateKeyboards()
	knownDevices := make(map[string]KeyboardDevice)
	for _, dev := range initialDevices {
		knownDevices[dev.DevicePath] = dev
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
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
}

// StopWatching stops watching for device changes.
func (d *darwinDeviceAccessor) StopWatching() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.watching {
		return nil
	}

	close(d.stopCh)
	d.watching = false
	d.callback = nil
	return nil
}
