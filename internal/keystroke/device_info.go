//go:build darwin || linux || windows

package keystroke

import (
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"time"
)

// KeyboardDevice represents a physical keyboard device with identification info.
type KeyboardDevice struct {
	// Hardware identifiers
	VendorID    uint16 `json:"vendor_id"`
	ProductID   uint16 `json:"product_id"`
	VersionNum  uint16 `json:"version_num,omitempty"`

	// Human-readable info
	VendorName  string `json:"vendor_name,omitempty"`
	ProductName string `json:"product_name"`

	// Unique identifier
	SerialNumber string `json:"serial_number,omitempty"`
	DevicePath   string `json:"device_path"`

	// Connection type
	ConnectionType ConnectionType `json:"connection_type"`

	// Device fingerprint (hash of identifiers)
	Fingerprint [32]byte `json:"fingerprint"`
}

// ConnectionType indicates how the keyboard is connected.
type ConnectionType int

const (
	ConnectionUnknown   ConnectionType = iota
	ConnectionUSB                      // USB wired
	ConnectionBluetooth               // Bluetooth wireless
	ConnectionPS2                     // PS/2 (older systems)
	ConnectionInternal                // Built-in laptop keyboard
	ConnectionVirtual                 // Virtual/software keyboard
)

// String returns the connection type as a string.
func (ct ConnectionType) String() string {
	switch ct {
	case ConnectionUSB:
		return "USB"
	case ConnectionBluetooth:
		return "Bluetooth"
	case ConnectionPS2:
		return "PS/2"
	case ConnectionInternal:
		return "Internal"
	case ConnectionVirtual:
		return "Virtual"
	default:
		return "Unknown"
	}
}

// IsPhysical returns true if this is a physical (hardware) connection.
func (ct ConnectionType) IsPhysical() bool {
	switch ct {
	case ConnectionUSB, ConnectionBluetooth, ConnectionPS2, ConnectionInternal:
		return true
	default:
		return false
	}
}

// ComputeFingerprint generates a device fingerprint from identifiers.
func (kd *KeyboardDevice) ComputeFingerprint() [32]byte {
	h := sha256.New()
	h.Write([]byte("witnessd-device-v1"))
	binary.Write(h, binary.BigEndian, kd.VendorID)
	binary.Write(h, binary.BigEndian, kd.ProductID)
	binary.Write(h, binary.BigEndian, kd.VersionNum)
	h.Write([]byte(kd.ProductName))
	h.Write([]byte(kd.SerialNumber))

	var fp [32]byte
	copy(fp[:], h.Sum(nil))
	kd.Fingerprint = fp
	return fp
}

// DeviceChangeEvent records when a device is connected/disconnected.
type DeviceChangeEvent struct {
	Timestamp  time.Time
	Device     KeyboardDevice
	EventType  DeviceEventType
	SessionSeq uint64 // Event sequence in session
}

// DeviceEventType indicates what happened to the device.
type DeviceEventType int

const (
	DeviceConnected    DeviceEventType = iota
	DeviceDisconnected
	DeviceFirstSeen    // First time seeing this device
	DeviceReturned     // Returning device seen before
)

// DeviceTracker monitors connected keyboard devices and tracks changes.
type DeviceTracker struct {
	mu sync.RWMutex

	// Currently connected devices
	devices map[string]*KeyboardDevice // keyed by device path

	// Session info
	primaryDevice   *KeyboardDevice // Main device used in session
	sessionStart    time.Time
	sessionSeq      uint64

	// Device history
	seenDevices     map[[32]byte]time.Time // fingerprint -> first seen time
	deviceChanges   []DeviceChangeEvent

	// Alerts
	alerts          []DeviceAlert

	// Platform-specific accessor
	accessor DeviceAccessor
}

// DeviceAlert indicates a suspicious device event.
type DeviceAlert struct {
	Timestamp   time.Time
	AlertType   DeviceAlertType
	Description string
	Severity    float64 // 0-1, higher = more suspicious
	Device      *KeyboardDevice
}

// DeviceAlertType categorizes device-related alerts.
type DeviceAlertType int

const (
	AlertDeviceSwitchMidSession  DeviceAlertType = iota // Changed keyboard during session
	AlertVirtualDeviceDetected                         // Virtual/software keyboard detected
	AlertUnknownDeviceType                             // Couldn't identify device type
	AlertMultipleDevicesActive                         // Multiple keyboards in use simultaneously
	AlertDeviceRapidReconnect                          // Device disconnected/reconnected quickly
)

// DeviceAccessor is the platform-specific interface for enumerating devices.
type DeviceAccessor interface {
	// EnumerateKeyboards returns all connected keyboard devices.
	EnumerateKeyboards() ([]KeyboardDevice, error)

	// StartWatching begins watching for device changes.
	StartWatching(callback func(KeyboardDevice, DeviceEventType)) error

	// StopWatching stops watching for device changes.
	StopWatching() error
}

// NewDeviceTracker creates a new device tracker.
func NewDeviceTracker() *DeviceTracker {
	dt := &DeviceTracker{
		devices:       make(map[string]*KeyboardDevice),
		seenDevices:   make(map[[32]byte]time.Time),
		deviceChanges: make([]DeviceChangeEvent, 0, 100),
		alerts:        make([]DeviceAlert, 0, 50),
		sessionStart:  time.Now(),
	}

	// Initialize platform-specific accessor
	dt.accessor = newPlatformDeviceAccessor()

	return dt
}

// Start begins device tracking and enumeration.
func (dt *DeviceTracker) Start() error {
	dt.mu.Lock()
	defer dt.mu.Unlock()

	// Initial enumeration
	devices, err := dt.accessor.EnumerateKeyboards()
	if err != nil {
		return err
	}

	// Track all discovered devices
	for i := range devices {
		dev := &devices[i]
		dev.ComputeFingerprint()
		dt.devices[dev.DevicePath] = dev

		// Record as seen
		if _, seen := dt.seenDevices[dev.Fingerprint]; !seen {
			dt.seenDevices[dev.Fingerprint] = time.Now()
			dt.recordChange(*dev, DeviceFirstSeen)
		}

		// First device becomes primary
		if dt.primaryDevice == nil {
			dt.primaryDevice = dev
		}

		// Check for virtual devices
		if dev.ConnectionType == ConnectionVirtual {
			dt.addAlert(AlertVirtualDeviceDetected,
				"Virtual keyboard detected: "+dev.ProductName,
				0.7, dev)
		}
	}

	// Start watching for changes
	if err := dt.accessor.StartWatching(dt.handleDeviceChange); err != nil {
		// Non-fatal, we can still enumerate manually
	}

	return nil
}

// Stop stops device tracking.
func (dt *DeviceTracker) Stop() {
	dt.accessor.StopWatching()
}

// handleDeviceChange processes a device connect/disconnect event.
func (dt *DeviceTracker) handleDeviceChange(device KeyboardDevice, eventType DeviceEventType) {
	dt.mu.Lock()
	defer dt.mu.Unlock()

	device.ComputeFingerprint()

	switch eventType {
	case DeviceConnected:
		dt.devices[device.DevicePath] = &device

		// Check if we've seen this device before
		if _, seen := dt.seenDevices[device.Fingerprint]; seen {
			dt.recordChange(device, DeviceReturned)
		} else {
			dt.seenDevices[device.Fingerprint] = time.Now()
			dt.recordChange(device, DeviceFirstSeen)
		}

		// Check for suspicious patterns
		if dt.primaryDevice != nil && device.Fingerprint != dt.primaryDevice.Fingerprint {
			dt.addAlert(AlertMultipleDevicesActive,
				"New keyboard connected during session",
				0.5, &device)
		}

		if device.ConnectionType == ConnectionVirtual {
			dt.addAlert(AlertVirtualDeviceDetected,
				"Virtual keyboard connected: "+device.ProductName,
				0.8, &device)
		}

	case DeviceDisconnected:
		delete(dt.devices, device.DevicePath)
		dt.recordChange(device, DeviceDisconnected)
	}
}

// recordChange records a device change event.
func (dt *DeviceTracker) recordChange(device KeyboardDevice, eventType DeviceEventType) {
	dt.sessionSeq++
	event := DeviceChangeEvent{
		Timestamp:  time.Now(),
		Device:     device,
		EventType:  eventType,
		SessionSeq: dt.sessionSeq,
	}

	dt.deviceChanges = append(dt.deviceChanges, event)

	// Limit history
	if len(dt.deviceChanges) > 100 {
		dt.deviceChanges = dt.deviceChanges[50:]
	}
}

// addAlert adds a device alert.
func (dt *DeviceTracker) addAlert(alertType DeviceAlertType, desc string, severity float64, device *KeyboardDevice) {
	alert := DeviceAlert{
		Timestamp:   time.Now(),
		AlertType:   alertType,
		Description: desc,
		Severity:    severity,
		Device:      device,
	}

	dt.alerts = append(dt.alerts, alert)

	// Limit alerts
	if len(dt.alerts) > 50 {
		dt.alerts = dt.alerts[25:]
	}
}

// GetDevices returns currently connected keyboard devices.
func (dt *DeviceTracker) GetDevices() []KeyboardDevice {
	dt.mu.RLock()
	defer dt.mu.RUnlock()

	result := make([]KeyboardDevice, 0, len(dt.devices))
	for _, dev := range dt.devices {
		result = append(result, *dev)
	}
	return result
}

// GetPrimaryDevice returns the primary (first) keyboard device.
func (dt *DeviceTracker) GetPrimaryDevice() *KeyboardDevice {
	dt.mu.RLock()
	defer dt.mu.RUnlock()
	return dt.primaryDevice
}

// GetAlerts returns device-related alerts.
func (dt *DeviceTracker) GetAlerts() []DeviceAlert {
	dt.mu.RLock()
	defer dt.mu.RUnlock()

	result := make([]DeviceAlert, len(dt.alerts))
	copy(result, dt.alerts)
	return result
}

// GetChanges returns device change history.
func (dt *DeviceTracker) GetChanges() []DeviceChangeEvent {
	dt.mu.RLock()
	defer dt.mu.RUnlock()

	result := make([]DeviceChangeEvent, len(dt.deviceChanges))
	copy(result, dt.deviceChanges)
	return result
}

// VerifyDeviceConsistency checks if the same device(s) are being used throughout.
func (dt *DeviceTracker) VerifyDeviceConsistency() (score float64, issues []string) {
	dt.mu.RLock()
	defer dt.mu.RUnlock()

	score = 1.0
	issues = make([]string, 0)

	// Check for device switches
	deviceSwitches := 0
	for _, change := range dt.deviceChanges {
		if change.EventType == DeviceFirstSeen && dt.sessionSeq > 1 {
			deviceSwitches++
		}
	}
	if deviceSwitches > 0 {
		score -= 0.1 * float64(deviceSwitches)
		issues = append(issues, "keyboard switched during session")
	}

	// Check for virtual devices
	for _, dev := range dt.devices {
		if dev.ConnectionType == ConnectionVirtual {
			score -= 0.3
			issues = append(issues, "virtual keyboard detected: "+dev.ProductName)
		}
	}

	// Check alerts
	for _, alert := range dt.alerts {
		score -= alert.Severity * 0.1
	}

	if score < 0 {
		score = 0
	}

	return score, issues
}

// DeviceHash creates a hash representing the current device state.
func (dt *DeviceTracker) DeviceHash() [32]byte {
	dt.mu.RLock()
	defer dt.mu.RUnlock()

	h := sha256.New()
	h.Write([]byte("witnessd-devices-v1"))

	// Hash all device fingerprints
	for _, dev := range dt.devices {
		h.Write(dev.Fingerprint[:])
	}

	// Include session info
	binary.Write(h, binary.BigEndian, dt.sessionStart.UnixNano())
	binary.Write(h, binary.BigEndian, dt.sessionSeq)

	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// SessionDeviceReport generates a report of device activity during the session.
type SessionDeviceReport struct {
	SessionStart      time.Time                  `json:"session_start"`
	PrimaryDevice     *KeyboardDevice            `json:"primary_device,omitempty"`
	CurrentDevices    []KeyboardDevice           `json:"current_devices"`
	UniqueDevicesSeen int                        `json:"unique_devices_seen"`
	DeviceChanges     int                        `json:"device_changes"`
	Alerts            []DeviceAlert              `json:"alerts"`
	ConsistencyScore  float64                    `json:"consistency_score"`
	Issues            []string                   `json:"issues,omitempty"`
	DeviceHash        [32]byte                   `json:"device_hash"`
}

// GenerateReport creates a session device report.
func (dt *DeviceTracker) GenerateReport() SessionDeviceReport {
	dt.mu.RLock()
	defer dt.mu.RUnlock()

	score, issues := dt.VerifyDeviceConsistency()

	return SessionDeviceReport{
		SessionStart:      dt.sessionStart,
		PrimaryDevice:     dt.primaryDevice,
		CurrentDevices:    dt.GetDevices(),
		UniqueDevicesSeen: len(dt.seenDevices),
		DeviceChanges:     len(dt.deviceChanges),
		Alerts:            dt.alerts,
		ConsistencyScore:  score,
		Issues:            issues,
		DeviceHash:        dt.DeviceHash(),
	}
}

// Well-known vendor IDs for common keyboard manufacturers.
var WellKnownVendors = map[uint16]string{
	0x045E: "Microsoft",
	0x046D: "Logitech",
	0x04D9: "Holtek (generic)",
	0x05AC: "Apple",
	0x0609: "Primax",
	0x0951: "Kingston (HyperX)",
	0x0A5C: "Broadcom",
	0x1038: "SteelSeries",
	0x1050: "Yubico",
	0x1532: "Razer",
	0x17EF: "Lenovo",
	0x1B1C: "Corsair",
	0x1D50: "OpenMoko",
	0x258A: "SINO WEALTH (generic)",
	0x3297: "ZSA (Moonlander/Ergodox)",
	0x4653: "Keychron",
	0x8087: "Intel",
	0xFEED: "Custom/QMK",
}

// LookupVendorName returns a human-readable vendor name.
func LookupVendorName(vendorID uint16) string {
	if name, ok := WellKnownVendors[vendorID]; ok {
		return name
	}
	return ""
}
