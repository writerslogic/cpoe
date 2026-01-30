//go:build linux

package keystroke

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// linuxDeviceAccessor implements DeviceAccessor for Linux.
type linuxDeviceAccessor struct {
	mu       sync.Mutex
	callback func(KeyboardDevice, DeviceEventType)
	watcher  *fsnotify.Watcher
	stopCh   chan struct{}
	watching bool
}

// newPlatformDeviceAccessor creates a Linux device accessor.
func newPlatformDeviceAccessor() DeviceAccessor {
	return &linuxDeviceAccessor{}
}

// EnumerateKeyboards returns all connected keyboard devices.
func (d *linuxDeviceAccessor) EnumerateKeyboards() ([]KeyboardDevice, error) {
	devices := make([]KeyboardDevice, 0)

	// Method 1: Parse /proc/bus/input/devices
	procDevices, err := parseInputDevices()
	if err == nil {
		devices = append(devices, procDevices...)
	}

	// Method 2: Scan sysfs for HID devices
	sysfsDevices, err := scanSysfsHID()
	if err == nil {
		// Merge without duplicates
		for _, dev := range sysfsDevices {
			found := false
			for _, existing := range devices {
				if existing.VendorID == dev.VendorID &&
					existing.ProductID == dev.ProductID &&
					existing.ProductName == dev.ProductName {
					found = true
					break
				}
			}
			if !found {
				devices = append(devices, dev)
			}
		}
	}

	return devices, nil
}

// parseInputDevices parses /proc/bus/input/devices to find keyboards.
func parseInputDevices() ([]KeyboardDevice, error) {
	f, err := os.Open("/proc/bus/input/devices")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	devices := make([]KeyboardDevice, 0)
	scanner := bufio.NewScanner(f)

	var current KeyboardDevice
	var isKeyboard bool
	var physPath string

	for scanner.Scan() {
		line := scanner.Text()

		// I: Bus=0003 Vendor=046d Product=c52b Version=0111
		if strings.HasPrefix(line, "I:") {
			current = KeyboardDevice{}
			isKeyboard = false
			physPath = ""

			// Parse Bus, Vendor, Product, Version
			parts := strings.Fields(line)
			for _, part := range parts {
				if strings.HasPrefix(part, "Vendor=") {
					if v, err := strconv.ParseUint(strings.TrimPrefix(part, "Vendor="), 16, 16); err == nil {
						current.VendorID = uint16(v)
					}
				} else if strings.HasPrefix(part, "Product=") {
					if v, err := strconv.ParseUint(strings.TrimPrefix(part, "Product="), 16, 16); err == nil {
						current.ProductID = uint16(v)
					}
				} else if strings.HasPrefix(part, "Version=") {
					if v, err := strconv.ParseUint(strings.TrimPrefix(part, "Version="), 16, 16); err == nil {
						current.VersionNum = uint16(v)
					}
				} else if strings.HasPrefix(part, "Bus=") {
					bus := strings.TrimPrefix(part, "Bus=")
					current.ConnectionType = busToConnectionType(bus)
				}
			}
		}

		// N: Name="Logitech USB Receiver"
		if strings.HasPrefix(line, "N:") {
			re := regexp.MustCompile(`Name="([^"]*)"`)
			if matches := re.FindStringSubmatch(line); len(matches) > 1 {
				current.ProductName = matches[1]
			}
		}

		// P: Phys=usb-0000:00:14.0-2/input0
		if strings.HasPrefix(line, "P:") {
			physPath = strings.TrimPrefix(line, "P: Phys=")
			current.DevicePath = physPath

			// Determine connection type from phys path
			if current.ConnectionType == ConnectionUnknown {
				current.ConnectionType = physToConnectionType(physPath)
			}
		}

		// S: Sysfs=/devices/pci0000:00/...
		if strings.HasPrefix(line, "S:") {
			sysfs := strings.TrimPrefix(line, "S: Sysfs=")
			if current.DevicePath == "" {
				current.DevicePath = sysfs
			}
		}

		// B: KEY=... (capability bitmap - large for keyboards)
		if strings.HasPrefix(line, "B: KEY=") {
			keyBits := strings.TrimPrefix(line, "B: KEY=")
			// Keyboards have many key bits set
			if len(keyBits) > 20 {
				isKeyboard = true
			}
		}

		// Empty line = end of device block
		if line == "" {
			if isKeyboard && current.ProductName != "" {
				current.VendorName = LookupVendorName(current.VendorID)
				devices = append(devices, current)
			}
		}
	}

	// Don't forget last device if file doesn't end with newline
	if isKeyboard && current.ProductName != "" {
		current.VendorName = LookupVendorName(current.VendorID)
		devices = append(devices, current)
	}

	return devices, scanner.Err()
}

// busToConnectionType converts Linux bus code to ConnectionType.
func busToConnectionType(bus string) ConnectionType {
	switch bus {
	case "0003": // BUS_USB
		return ConnectionUSB
	case "0005": // BUS_BLUETOOTH
		return ConnectionBluetooth
	case "0011": // BUS_I8042 (PS/2)
		return ConnectionPS2
	case "0019": // BUS_HOST
		return ConnectionInternal
	case "0006": // BUS_VIRTUAL
		return ConnectionVirtual
	case "001F": // BUS_RMI
		return ConnectionInternal
	default:
		return ConnectionUnknown
	}
}

// physToConnectionType determines connection from phys path.
func physToConnectionType(phys string) ConnectionType {
	phys = strings.ToLower(phys)

	if strings.HasPrefix(phys, "usb-") {
		return ConnectionUSB
	} else if strings.Contains(phys, "bluetooth") ||
		strings.HasPrefix(phys, "bt-") {
		return ConnectionBluetooth
	} else if strings.HasPrefix(phys, "isa") ||
		strings.Contains(phys, "i8042") ||
		strings.Contains(phys, "serio") {
		return ConnectionPS2
	} else if strings.HasPrefix(phys, "virtual") ||
		phys == "" {
		return ConnectionVirtual
	}

	return ConnectionUnknown
}

// scanSysfsHID scans /sys/bus/hid/devices for keyboard info.
func scanSysfsHID() ([]KeyboardDevice, error) {
	devices := make([]KeyboardDevice, 0)

	hidPath := "/sys/bus/hid/devices"
	entries, err := os.ReadDir(hidPath)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		devPath := filepath.Join(hidPath, entry.Name())

		// Read uevent for device info
		ueventPath := filepath.Join(devPath, "uevent")
		data, err := os.ReadFile(ueventPath)
		if err != nil {
			continue
		}

		// Check if it's a keyboard
		content := string(data)
		if !strings.Contains(strings.ToLower(content), "keyboard") {
			continue
		}

		dev := KeyboardDevice{
			DevicePath: entry.Name(),
		}

		// Parse uevent
		for _, line := range strings.Split(content, "\n") {
			if strings.HasPrefix(line, "HID_ID=") {
				// Format: HID_ID=0003:0000046D:0000C52B
				parts := strings.Split(strings.TrimPrefix(line, "HID_ID="), ":")
				if len(parts) >= 3 {
					if bus, err := strconv.ParseUint(parts[0], 16, 16); err == nil {
						dev.ConnectionType = busToConnectionType(strings.ToUpper(parts[0]))
						_ = bus
					}
					if vid, err := strconv.ParseUint(parts[1], 16, 16); err == nil {
						dev.VendorID = uint16(vid)
					}
					if pid, err := strconv.ParseUint(parts[2], 16, 16); err == nil {
						dev.ProductID = uint16(pid)
					}
				}
			} else if strings.HasPrefix(line, "HID_NAME=") {
				dev.ProductName = strings.TrimPrefix(line, "HID_NAME=")
			}
		}

		if dev.ProductName != "" {
			dev.VendorName = LookupVendorName(dev.VendorID)
			devices = append(devices, dev)
		}
	}

	return devices, nil
}

// StartWatching begins watching for device changes using udev/sysfs.
func (d *linuxDeviceAccessor) StartWatching(callback func(KeyboardDevice, DeviceEventType)) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.watching {
		return errors.New("already watching")
	}

	// Create fsnotify watcher for /dev/input
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		// Fall back to polling
		d.startPolling(callback)
		return nil
	}

	// Watch /dev/input for device changes
	if err := watcher.Add("/dev/input"); err != nil {
		watcher.Close()
		d.startPolling(callback)
		return nil
	}

	d.watcher = watcher
	d.callback = callback
	d.stopCh = make(chan struct{})
	d.watching = true

	// Get initial device list
	initialDevices, _ := d.EnumerateKeyboards()

	go d.watchLoop(initialDevices)

	return nil
}

// watchLoop monitors for device changes.
func (d *linuxDeviceAccessor) watchLoop(initialDevices []KeyboardDevice) {
	knownDevices := make(map[string]KeyboardDevice)
	for _, dev := range initialDevices {
		knownDevices[dev.DevicePath] = dev
	}

	for {
		select {
		case <-d.stopCh:
			return
		case event, ok := <-d.watcher.Events:
			if !ok {
				return
			}

			// Check for input device changes
			if strings.Contains(event.Name, "event") {
				// Re-enumerate and compare
				time.Sleep(100 * time.Millisecond) // Wait for device to settle
				newDevices, err := d.EnumerateKeyboards()
				if err != nil {
					continue
				}

				// Find new devices
				newKnown := make(map[string]KeyboardDevice)
				for _, dev := range newDevices {
					newKnown[dev.DevicePath] = dev
					if _, exists := knownDevices[dev.DevicePath]; !exists {
						if d.callback != nil {
							d.callback(dev, DeviceConnected)
						}
					}
				}

				// Find removed devices
				for path, dev := range knownDevices {
					if _, exists := newKnown[path]; !exists {
						if d.callback != nil {
							d.callback(dev, DeviceDisconnected)
						}
					}
				}

				knownDevices = newKnown
			}
		case _, ok := <-d.watcher.Errors:
			if !ok {
				return
			}
		}
	}
}

// startPolling starts a polling-based device watcher.
func (d *linuxDeviceAccessor) startPolling(callback func(KeyboardDevice, DeviceEventType)) {
	d.callback = callback
	d.stopCh = make(chan struct{})
	d.watching = true

	initialDevices, _ := d.EnumerateKeyboards()

	go func() {
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
						if d.callback != nil {
							d.callback(dev, DeviceConnected)
						}
					}
				}

				for path, dev := range knownDevices {
					if _, exists := newKnown[path]; !exists {
						if d.callback != nil {
							d.callback(dev, DeviceDisconnected)
						}
					}
				}

				knownDevices = newKnown
			}
		}
	}()
}

// StopWatching stops watching for device changes.
func (d *linuxDeviceAccessor) StopWatching() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.watching {
		return nil
	}

	close(d.stopCh)

	if d.watcher != nil {
		d.watcher.Close()
		d.watcher = nil
	}

	d.callback = nil
	d.watching = false
	return nil
}
