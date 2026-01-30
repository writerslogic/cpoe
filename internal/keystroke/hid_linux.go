//go:build linux

package keystroke

import (
	"bufio"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
)

// HIDMonitor provides direct hardware keyboard monitoring via Linux hidraw.
// This monitors at a layer that is harder to spoof than /dev/input/eventX.
//
// Architecture:
//
//   Physical Keyboard
//         │
//         ▼
//   USB/Bluetooth HID Driver (kernel)
//         │
//         ├──────────────────────────────┐
//         ▼                              ▼
//   ┌─────────────────────────────┐   ┌─────────────────────────────┐
//   │  hidraw Layer               │   │  input Layer                │
//   │  (/dev/hidrawX)             │   │  (/dev/input/eventX)        │
//   │  ◄── WE MONITOR HERE        │   │  ◄── Main counter uses this │
//   └─────────────────────────────┘   └─────────────────────────────┘
//
// Note: On Linux, both hidraw and input events come from the kernel driver,
// but hidraw provides the raw HID reports while input provides processed
// key codes. Synthetic event injection typically happens at the input layer
// via uinput/ydotool/xdotool, which doesn't affect hidraw.
type HIDMonitor struct {
	running atomic.Bool

	mu       sync.RWMutex
	count    int64
	devices  []string
	stopChan chan struct{}
	doneChan chan struct{}
}

// NewHIDMonitor creates a new HID monitor for Linux.
func NewHIDMonitor() *HIDMonitor {
	return &HIDMonitor{}
}

// findHidrawKeyboards finds /dev/hidraw devices that are keyboards.
func findHidrawKeyboards() ([]string, error) {
	var devices []string

	// Look for hidraw devices
	hidrawDevices, err := filepath.Glob("/dev/hidraw*")
	if err != nil {
		return nil, err
	}

	for _, dev := range hidrawDevices {
		// Try to identify if this is a keyboard by checking sysfs
		// The device number is the suffix after "hidraw"
		devName := filepath.Base(dev)
		sysPath := filepath.Join("/sys/class/hidraw", devName, "device/uevent")

		data, err := os.ReadFile(sysPath)
		if err != nil {
			continue
		}

		content := string(data)
		// Look for keyboard indicators in uevent
		// HID_NAME often contains "Keyboard" or we can check the modalias
		if strings.Contains(strings.ToLower(content), "keyboard") ||
			strings.Contains(content, "HID_MODALIAS=hid:b") {
			// Additional check: try to open and read HID descriptor
			f, err := os.OpenFile(dev, os.O_RDONLY, 0)
			if err == nil {
				f.Close()
				devices = append(devices, dev)
			}
		}
	}

	// Alternative: check /sys/class/input for keyboard devices and find their hidraw
	inputDevices, _ := filepath.Glob("/sys/class/input/event*")
	for _, inputDev := range inputDevices {
		// Check if it's a keyboard
		capsPath := filepath.Join(inputDev, "device/capabilities/key")
		caps, err := os.ReadFile(capsPath)
		if err != nil {
			continue
		}

		// A keyboard typically has many key capabilities
		// (the key capability bitmap is large for keyboards)
		if len(strings.TrimSpace(string(caps))) > 20 {
			// Look for associated hidraw
			hidrawLinks, _ := filepath.Glob(filepath.Join(inputDev, "device/device/hidraw/hidraw*"))
			for _, link := range hidrawLinks {
				devName := filepath.Base(link)
				devPath := "/dev/" + devName
				if _, err := os.Stat(devPath); err == nil {
					// Check if not already in list
					found := false
					for _, d := range devices {
						if d == devPath {
							found = true
							break
						}
					}
					if !found {
						devices = append(devices, devPath)
					}
				}
			}
		}
	}

	return devices, nil
}

// Start begins HID monitoring.
func (h *HIDMonitor) Start() error {
	if h.running.Load() {
		return errors.New("HID monitor already running")
	}

	devices, err := findHidrawKeyboards()
	if err != nil || len(devices) == 0 {
		// Try alternative approach: use evdev but check for hardware events
		return errors.New("no hidraw keyboard devices found (may need root or hidraw access)")
	}

	h.mu.Lock()
	h.devices = devices
	h.count = 0
	h.stopChan = make(chan struct{})
	h.doneChan = make(chan struct{})
	h.mu.Unlock()

	h.running.Store(true)

	go h.readLoop()

	return nil
}

// readLoop reads from hidraw devices and counts keystrokes.
func (h *HIDMonitor) readLoop() {
	defer func() {
		h.running.Store(false)
		close(h.doneChan)
	}()

	h.mu.RLock()
	devices := h.devices
	h.mu.RUnlock()

	// Open first available hidraw device
	var f *os.File
	var err error
	for _, dev := range devices {
		f, err = os.OpenFile(dev, os.O_RDONLY, 0)
		if err == nil {
			break
		}
	}
	if f == nil {
		return
	}
	defer f.Close()

	// Read HID reports
	// Keyboard HID reports are typically 8 bytes:
	// Byte 0: Modifier keys (Ctrl, Shift, Alt, GUI)
	// Byte 1: Reserved
	// Bytes 2-7: Key codes (up to 6 simultaneous keys)
	buf := make([]byte, 64) // Max HID report size

	// Track previous state to detect key press events
	var prevKeys [6]byte

	for {
		select {
		case <-h.stopChan:
			return
		default:
			n, err := f.Read(buf)
			if err != nil {
				continue
			}

			// Standard keyboard report is at least 8 bytes
			if n >= 8 {
				// Check for new key presses (keys in current report but not in previous)
				for i := 2; i < 8 && i < n; i++ {
					keyCode := buf[i]
					if keyCode == 0 {
						continue
					}

					// Check if this is a new key (not in previous state)
					isNew := true
					for j := 0; j < 6; j++ {
						if prevKeys[j] == keyCode {
							isNew = false
							break
						}
					}

					if isNew {
						h.mu.Lock()
						h.count++
						h.mu.Unlock()
					}
				}

				// Update previous state
				for i := 0; i < 6 && i+2 < n; i++ {
					prevKeys[i] = buf[i+2]
				}
			}
		}
	}
}

// Stop stops HID monitoring.
func (h *HIDMonitor) Stop() {
	if !h.running.Load() {
		return
	}

	close(h.stopChan)
	<-h.doneChan
}

// Count returns the number of hardware keystrokes detected.
func (h *HIDMonitor) Count() int64 {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.count
}

// Reset resets the HID keystroke count.
func (h *HIDMonitor) Reset() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.count = 0
}

// IsRunning returns whether HID monitoring is active.
func (h *HIDMonitor) IsRunning() bool {
	return h.running.Load()
}

// Alternative approach: Use /dev/input/eventX with EVIOCGRAB
// to get exclusive access and check device flags for hardware vs synthetic.

// HIDInputMonitor uses evdev with additional checks for synthetic events.
// This is an alternative when hidraw access isn't available.
type HIDInputMonitor struct {
	running atomic.Bool

	mu       sync.RWMutex
	count    int64
	device   string
	stopChan chan struct{}
	doneChan chan struct{}
}

// inputEvent matches the Linux input_event struct.
type hidInputEvent struct {
	TimeSec  int64  // __kernel_time_t
	TimeUsec int64  // __kernel_suseconds_t
	Type     uint16
	Code     uint16
	Value    int32
}

const (
	evKeyConst     = 1
	keyPressConst  = 1
	synReportConst = 0
)

// NewHIDInputMonitor creates a monitor using evdev with hardware verification.
func NewHIDInputMonitor() *HIDInputMonitor {
	return &HIDInputMonitor{}
}

// findPhysicalKeyboard finds a keyboard that appears to be physical hardware.
func findPhysicalKeyboard() (string, error) {
	// Read /proc/bus/input/devices to find keyboards
	f, err := os.Open("/proc/bus/input/devices")
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var currentHandler string
	var currentPhys string
	isKeyboard := false

	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "H: Handlers=") {
			parts := strings.Fields(line)
			for _, part := range parts {
				if strings.HasPrefix(part, "event") {
					currentHandler = "/dev/input/" + part
				}
			}
		}

		if strings.HasPrefix(line, "P: Phys=") {
			currentPhys = strings.TrimPrefix(line, "P: Phys=")
		}

		if strings.HasPrefix(line, "B: KEY=") {
			if len(line) > 10 {
				isKeyboard = true
			}
		}

		if line == "" {
			// End of device block
			if isKeyboard && currentHandler != "" {
				// Check if it looks like physical hardware
				// Physical devices typically have phys paths like usb-xxx or bluetooth-xxx
				// Virtual devices often have empty phys or phys starting with virtual
				if currentPhys != "" && !strings.HasPrefix(strings.ToLower(currentPhys), "virtual") {
					return currentHandler, nil
				}
			}
			currentHandler = ""
			currentPhys = ""
			isKeyboard = false
		}
	}

	return "", errors.New("no physical keyboard found")
}

// Start begins input monitoring with hardware verification.
func (h *HIDInputMonitor) Start() error {
	if h.running.Load() {
		return errors.New("HID input monitor already running")
	}

	device, err := findPhysicalKeyboard()
	if err != nil {
		return err
	}

	h.mu.Lock()
	h.device = device
	h.count = 0
	h.stopChan = make(chan struct{})
	h.doneChan = make(chan struct{})
	h.mu.Unlock()

	h.running.Store(true)

	go h.readInputLoop()

	return nil
}

// readInputLoop reads from evdev device.
func (h *HIDInputMonitor) readInputLoop() {
	defer func() {
		h.running.Store(false)
		close(h.doneChan)
	}()

	h.mu.RLock()
	device := h.device
	h.mu.RUnlock()

	f, err := os.OpenFile(device, os.O_RDONLY, 0)
	if err != nil {
		return
	}
	defer f.Close()

	eventSize := binary.Size(hidInputEvent{})
	buf := make([]byte, eventSize)

	for {
		select {
		case <-h.stopChan:
			return
		default:
			n, err := f.Read(buf)
			if err != nil {
				continue
			}
			if n < eventSize {
				continue
			}

			// Parse event
			var ev hidInputEvent
			ev.Type = binary.LittleEndian.Uint16(buf[16:18])
			ev.Value = int32(binary.LittleEndian.Uint32(buf[20:24]))

			// Count key press events
			if ev.Type == evKeyConst && ev.Value == keyPressConst {
				h.mu.Lock()
				h.count++
				h.mu.Unlock()
			}
		}
	}
}

// Stop stops the input monitor.
func (h *HIDInputMonitor) Stop() {
	if !h.running.Load() {
		return
	}

	close(h.stopChan)
	<-h.doneChan
}

// Count returns the keystroke count.
func (h *HIDInputMonitor) Count() int64 {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.count
}

// Reset resets the count.
func (h *HIDInputMonitor) Reset() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.count = 0
}

// IsRunning returns running state.
func (h *HIDInputMonitor) IsRunning() bool {
	return h.running.Load()
}
