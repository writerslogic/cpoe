// +build linux

package keystroke

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// LinuxCounter uses /dev/input for keyboard counting on Linux.
type LinuxCounter struct {
	BaseCounter
	ctx      context.Context
	cancel   context.CancelFunc
	done     chan struct{}
	devices  []string
}

func newPlatformCounter() Counter {
	return &LinuxCounter{}
}

// Available checks if we can read input devices.
func (l *LinuxCounter) Available() (bool, string) {
	devices, err := findKeyboardDevices()
	if err != nil {
		return false, fmt.Sprintf("cannot find keyboard devices: %v", err)
	}
	if len(devices) == 0 {
		return false, "no keyboard devices found"
	}

	// Check if we can read at least one device
	for _, dev := range devices {
		f, err := os.OpenFile(dev, os.O_RDONLY, 0)
		if err == nil {
			f.Close()
			return true, fmt.Sprintf("found keyboard device: %s", dev)
		}
	}

	return false, "cannot read keyboard devices (need to be in 'input' group or run as root)"
}

// findKeyboardDevices finds /dev/input devices that are keyboards.
func findKeyboardDevices() ([]string, error) {
	var devices []string

	// Read /proc/bus/input/devices to find keyboards
	f, err := os.Open("/proc/bus/input/devices")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var currentHandler string
	isKeyboard := false

	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "H: Handlers=") {
			// Extract event handler
			parts := strings.Fields(line)
			for _, part := range parts {
				if strings.HasPrefix(part, "event") {
					currentHandler = "/dev/input/" + part
				}
			}
		}

		if strings.HasPrefix(line, "B: KEY=") {
			// If it has key capabilities, it's likely a keyboard
			if len(line) > 10 {
				isKeyboard = true
			}
		}

		if line == "" {
			// End of device block
			if isKeyboard && currentHandler != "" {
				devices = append(devices, currentHandler)
			}
			currentHandler = ""
			isKeyboard = false
		}
	}

	// Also check by name pattern
	matches, _ := filepath.Glob("/dev/input/by-id/*-kbd")
	devices = append(devices, matches...)

	return devices, nil
}

// Start begins counting keyboard events.
func (l *LinuxCounter) Start(ctx context.Context) error {
	if l.IsRunning() {
		return ErrAlreadyRunning
	}

	devices, err := findKeyboardDevices()
	if err != nil || len(devices) == 0 {
		return ErrNotAvailable
	}

	l.devices = devices
	l.ctx, l.cancel = context.WithCancel(ctx)
	l.done = make(chan struct{})
	l.SetRunning(true)

	// Start reading from keyboard devices
	go l.readLoop()

	return nil
}

// inputEvent matches the Linux input_event struct.
type inputEvent struct {
	Time  syscall.Timeval
	Type  uint16
	Code  uint16
	Value int32
}

const (
	evKey     = 1
	keyPress  = 1
)

func (l *LinuxCounter) readLoop() {
	defer close(l.done)

	// Open first available keyboard device
	var f *os.File
	var err error
	for _, dev := range l.devices {
		f, err = os.OpenFile(dev, os.O_RDONLY, 0)
		if err == nil {
			break
		}
	}
	if f == nil {
		return
	}
	defer f.Close()

	// Read events
	eventSize := binary.Size(inputEvent{})
	buf := make([]byte, eventSize)

	for {
		select {
		case <-l.ctx.Done():
			return
		default:
			// Set read deadline so we can check context
			n, err := f.Read(buf)
			if err != nil {
				continue
			}
			if n < eventSize {
				continue
			}

			// Parse event - we only care that a key was pressed,
			// NOT which key (privacy)
			var ev inputEvent
			ev.Type = binary.LittleEndian.Uint16(buf[16:18])
			ev.Value = int32(binary.LittleEndian.Uint32(buf[20:24]))

			// Count key press events (not releases)
			if ev.Type == evKey && ev.Value == keyPress {
				l.Increment()
			}
		}
	}
}

// Stop stops counting.
func (l *LinuxCounter) Stop() error {
	if !l.IsRunning() {
		return nil
	}

	if l.cancel != nil {
		l.cancel()
	}

	if l.done != nil {
		<-l.done
	}

	l.SetRunning(false)
	l.CloseListeners()

	return nil
}

// FocusedWindow returns the currently focused window name (optional).
// This can be used to limit tracking to specific applications.
func FocusedWindow() (string, error) {
	// Would need X11 or Wayland integration
	return "", errors.New("not implemented")
}
