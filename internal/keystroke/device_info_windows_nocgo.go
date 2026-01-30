//go:build windows && !cgo

package keystroke

import (
	"errors"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	setupapi = syscall.NewLazyDLL("setupapi.dll")
	hid      = syscall.NewLazyDLL("hid.dll")

	setupDiGetClassDevsW            = setupapi.NewProc("SetupDiGetClassDevsW")
	setupDiEnumDeviceInterfaces     = setupapi.NewProc("SetupDiEnumDeviceInterfaces")
	setupDiGetDeviceInterfaceDetailW = setupapi.NewProc("SetupDiGetDeviceInterfaceDetailW")
	setupDiDestroyDeviceInfoList    = setupapi.NewProc("SetupDiDestroyDeviceInfoList")

	hidDGetHidGuid              = hid.NewProc("HidD_GetHidGuid")
	hidDGetAttributes           = hid.NewProc("HidD_GetAttributes")
	hidDGetProductString        = hid.NewProc("HidD_GetProductString")
	hidDGetManufacturerString   = hid.NewProc("HidD_GetManufacturerString")
	hidDGetSerialNumberString   = hid.NewProc("HidD_GetSerialNumberString")
	hidDGetPreparsedData        = hid.NewProc("HidD_GetPreparsedData")
	hidDFreePreparsedData       = hid.NewProc("HidD_FreePreparsedData")
	hidPGetCaps                 = hid.NewProc("HidP_GetCaps")
)

const (
	DIGCF_PRESENT         = 0x2
	DIGCF_DEVICEINTERFACE = 0x10
	INVALID_HANDLE_VALUE  = ^uintptr(0)
)

// GUID structure
type guid struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

// SP_DEVICE_INTERFACE_DATA structure
type spDeviceInterfaceData struct {
	cbSize             uint32
	InterfaceClassGuid guid
	Flags              uint32
	Reserved           uintptr
}

// HIDD_ATTRIBUTES structure
type hiddAttributes struct {
	Size          uint32
	VendorID      uint16
	ProductID     uint16
	VersionNumber uint16
}

// HIDP_CAPS structure (partial)
type hidpCaps struct {
	Usage                     uint16
	UsagePage                 uint16
	InputReportByteLength     uint16
	OutputReportByteLength    uint16
	FeatureReportByteLength   uint16
	Reserved                  [17]uint16
	NumberLinkCollectionNodes uint16
	// ... more fields not needed
}

// windowsDeviceAccessorNoCgo implements DeviceAccessor for Windows without cgo.
type windowsDeviceAccessorNoCgo struct {
	mu       sync.Mutex
	callback func(KeyboardDevice, DeviceEventType)
	watching bool
	stopCh   chan struct{}
}

// newPlatformDeviceAccessor creates a Windows device accessor (no-cgo version).
func newPlatformDeviceAccessor() DeviceAccessor {
	return &windowsDeviceAccessorNoCgo{}
}

// EnumerateKeyboards returns all connected keyboard devices.
func (d *windowsDeviceAccessorNoCgo) EnumerateKeyboards() ([]KeyboardDevice, error) {
	devices := make([]KeyboardDevice, 0)

	// Get HID GUID
	var hidGuid guid
	hidDGetHidGuid.Call(uintptr(unsafe.Pointer(&hidGuid)))

	// Get device info set
	hDevInfo, _, _ := setupDiGetClassDevsW.Call(
		uintptr(unsafe.Pointer(&hidGuid)),
		0,
		0,
		DIGCF_PRESENT|DIGCF_DEVICEINTERFACE,
	)

	if hDevInfo == INVALID_HANDLE_VALUE {
		return nil, errors.New("failed to get device info set")
	}
	defer setupDiDestroyDeviceInfoList.Call(hDevInfo)

	// Enumerate devices
	var interfaceData spDeviceInterfaceData
	interfaceData.cbSize = uint32(unsafe.Sizeof(interfaceData))

	for i := uint32(0); ; i++ {
		ret, _, _ := setupDiEnumDeviceInterfaces.Call(
			hDevInfo,
			0,
			uintptr(unsafe.Pointer(&hidGuid)),
			uintptr(i),
			uintptr(unsafe.Pointer(&interfaceData)),
		)

		if ret == 0 {
			break
		}

		// Get required size for detail data
		var requiredSize uint32
		setupDiGetDeviceInterfaceDetailW.Call(
			hDevInfo,
			uintptr(unsafe.Pointer(&interfaceData)),
			0,
			0,
			uintptr(unsafe.Pointer(&requiredSize)),
			0,
		)

		if requiredSize == 0 {
			continue
		}

		// Allocate detail data
		detailData := make([]byte, requiredSize)
		// cbSize is at offset 0, set to 8 for 64-bit or 6 for 32-bit
		if unsafe.Sizeof(uintptr(0)) == 8 {
			*(*uint32)(unsafe.Pointer(&detailData[0])) = 8
		} else {
			*(*uint32)(unsafe.Pointer(&detailData[0])) = 6
		}

		ret, _, _ = setupDiGetDeviceInterfaceDetailW.Call(
			hDevInfo,
			uintptr(unsafe.Pointer(&interfaceData)),
			uintptr(unsafe.Pointer(&detailData[0])),
			uintptr(requiredSize),
			0,
			0,
		)

		if ret == 0 {
			continue
		}

		// Extract device path (starts at offset 4)
		devicePath := syscall.UTF16ToString((*[512]uint16)(unsafe.Pointer(&detailData[4]))[:])

		// Try to open the device
		pathPtr, _ := syscall.UTF16PtrFromString(devicePath)
		handle, err := syscall.CreateFile(
			pathPtr,
			0,
			syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
			nil,
			syscall.OPEN_EXISTING,
			0,
			0,
		)

		if err != nil {
			continue
		}

		// Check if it's a keyboard
		var preparsedData uintptr
		ret, _, _ = hidDGetPreparsedData.Call(
			uintptr(handle),
			uintptr(unsafe.Pointer(&preparsedData)),
		)

		if ret != 0 {
			var caps hidpCaps
			ret, _, _ = hidPGetCaps.Call(
				preparsedData,
				uintptr(unsafe.Pointer(&caps)),
			)

			// Usage Page 0x01 (Generic Desktop), Usage 0x06 (Keyboard)
			if caps.UsagePage == 0x01 && caps.Usage == 0x06 {
				dev := KeyboardDevice{
					DevicePath: devicePath,
				}

				// Get attributes
				var attrs hiddAttributes
				attrs.Size = uint32(unsafe.Sizeof(attrs))
				ret, _, _ = hidDGetAttributes.Call(
					uintptr(handle),
					uintptr(unsafe.Pointer(&attrs)),
				)
				if ret != 0 {
					dev.VendorID = attrs.VendorID
					dev.ProductID = attrs.ProductID
					dev.VersionNum = attrs.VersionNumber
				}

				// Get product string
				productBuf := make([]uint16, 256)
				hidDGetProductString.Call(
					uintptr(handle),
					uintptr(unsafe.Pointer(&productBuf[0])),
					uintptr(len(productBuf)*2),
				)
				dev.ProductName = syscall.UTF16ToString(productBuf)

				// Get manufacturer string
				mfrBuf := make([]uint16, 256)
				hidDGetManufacturerString.Call(
					uintptr(handle),
					uintptr(unsafe.Pointer(&mfrBuf[0])),
					uintptr(len(mfrBuf)*2),
				)
				dev.VendorName = syscall.UTF16ToString(mfrBuf)

				// Get serial number
				serialBuf := make([]uint16, 256)
				hidDGetSerialNumberString.Call(
					uintptr(handle),
					uintptr(unsafe.Pointer(&serialBuf[0])),
					uintptr(len(serialBuf)*2),
				)
				dev.SerialNumber = syscall.UTF16ToString(serialBuf)

				// Determine connection type from path
				dev.ConnectionType = determineConnectionTypeFromPath(devicePath)

				// Look up vendor name if not provided
				if dev.VendorName == "" {
					dev.VendorName = LookupVendorName(dev.VendorID)
				}

				devices = append(devices, dev)
			}

			hidDFreePreparsedData.Call(preparsedData)
		}

		syscall.CloseHandle(handle)
	}

	return devices, nil
}

// determineConnectionTypeFromPath determines connection type from device path.
func determineConnectionTypeFromPath(path string) ConnectionType {
	if len(path) == 0 {
		return ConnectionUnknown
	}

	// USB devices
	if contains(path, "USB") || contains(path, "HID#VID_") {
		return ConnectionUSB
	}

	// Bluetooth devices
	if contains(path, "BTHLE") || contains(path, "BTH") {
		return ConnectionBluetooth
	}

	// PS/2 devices
	if contains(path, "ACPI") || contains(path, "PS2") {
		return ConnectionPS2
	}

	// Virtual devices
	if contains(path, "VIRTUAL") || contains(path, "Root#RDP") {
		return ConnectionVirtual
	}

	return ConnectionUnknown
}

// contains is a simple case-insensitive contains check.
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			sc := s[i+j]
			tc := substr[j]
			// Simple uppercase conversion for ASCII
			if sc >= 'a' && sc <= 'z' {
				sc -= 32
			}
			if tc >= 'a' && tc <= 'z' {
				tc -= 32
			}
			if sc != tc {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// StartWatching begins watching for device changes.
func (d *windowsDeviceAccessorNoCgo) StartWatching(callback func(KeyboardDevice, DeviceEventType)) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.watching {
		return errors.New("already watching")
	}

	d.callback = callback
	d.stopCh = make(chan struct{})
	d.watching = true

	go d.pollDevices()

	return nil
}

// pollDevices polls for device changes periodically.
func (d *windowsDeviceAccessorNoCgo) pollDevices() {
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
func (d *windowsDeviceAccessorNoCgo) StopWatching() error {
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
