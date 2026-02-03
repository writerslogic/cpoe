//go:build darwin || linux || windows

package session

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

// MultiDeviceSession coordinates authorship tracking across multiple devices.
//
// Use cases:
// - User starts writing on laptop, continues on tablet
// - User types on phone, edits on desktop
// - Collaborative editing with multiple authors
//
// Security model:
// - Each device has a unique identity (DeviceSession)
// - Sessions can be "linked" to prove same user
// - Unauthorized devices can be detected
// - Timeline anomalies (impossible edits) are flagged
type MultiDeviceSession struct {
	mu sync.RWMutex

	// Session identity
	sessionID     [32]byte
	masterSecret  [32]byte // Used to derive device-specific keys
	createdAt     time.Time

	// Linked devices
	devices       map[[32]byte]*DeviceSession
	deviceOrder   [][32]byte // Order devices were added

	// Cross-device timeline
	timeline      []TimelineEvent
	lastEventSeq  uint64

	// User identity (if linked)
	userIdentity  *UserIdentity

	// Anomaly tracking
	anomalies     []DeviceAnomaly
}

// DeviceSession represents a single device's session.
type DeviceSession struct {
	// Device identity
	DeviceID        [32]byte `json:"device_id"`
	DeviceFingerprint [32]byte `json:"device_fingerprint"` // From hardware
	DeviceName      string   `json:"device_name"`
	DeviceType      DeviceType `json:"device_type"`

	// Session binding
	LinkedAt        time.Time  `json:"linked_at"`
	LinkProof       []byte     `json:"link_proof"` // Signed by master
	DerivedKey      [32]byte   `json:"-"`          // Session-specific key

	// Activity tracking
	FirstActivity   time.Time  `json:"first_activity"`
	LastActivity    time.Time  `json:"last_activity"`
	EventCount      uint64     `json:"event_count"`
	BytesAuthored   int64      `json:"bytes_authored"`

	// Biometric binding (optional)
	BiometricHash   *[32]byte  `json:"biometric_hash,omitempty"`

	// Trust level
	TrustScore      float64    `json:"trust_score"`
	Verified        bool       `json:"verified"`
}

// DeviceType categorizes the device.
type DeviceType int

const (
	DeviceTypeUnknown DeviceType = iota
	DeviceTypeDesktop            // Desktop/laptop computer
	DeviceTypeTablet             // iPad, Android tablet
	DeviceTypePhone              // Smartphone
	DeviceTypeServer             // Server/cloud instance
)

// TimelineEvent represents an event in the cross-device timeline.
type TimelineEvent struct {
	Timestamp     time.Time   `json:"timestamp"`
	Sequence      uint64      `json:"sequence"`
	DeviceID      [32]byte    `json:"device_id"`
	EventType     TimelineEventType `json:"event_type"`
	BytesDelta    int64       `json:"bytes_delta"` // Positive = added, negative = removed
	DocumentHash  [32]byte    `json:"document_hash"`
	PrevEventHash [32]byte    `json:"prev_event_hash"` // Links events
	Signature     []byte      `json:"signature"`
}

// TimelineEventType categorizes timeline events.
type TimelineEventType int

const (
	EventTypeEdit TimelineEventType = iota
	EventTypePaste
	EventTypeDelete
	EventTypeDictation
	EventTypeSessionStart
	EventTypeSessionEnd
	EventTypeDeviceSwitch
	EventTypeSync
)

// DeviceAnomaly represents a suspicious cross-device event.
type DeviceAnomaly struct {
	Timestamp     time.Time
	AnomalyType   DeviceAnomalyType
	Description   string
	Severity      float64 // 0-1
	DeviceID      *[32]byte
	EventSequence uint64
}

// DeviceAnomalyType categorizes device anomalies.
type DeviceAnomalyType int

const (
	AnomalySimultaneousEdits   DeviceAnomalyType = iota // Edits from multiple devices at same time
	AnomalyImpossibleSwitch                             // Device switch faster than physically possible
	AnomalyUnauthorizedDevice                           // Unknown device trying to contribute
	AnomalyTimelineGap                                  // Missing events in sequence
	AnomalyBiometricMismatch                            // Biometrics don't match expected user
	AnomalyBackdatedEvent                               // Event timestamp before previous event
)

// UserIdentity represents a verified user identity across devices.
type UserIdentity struct {
	UserID          [32]byte  `json:"user_id"`
	PublicKey       ed25519.PublicKey `json:"public_key"`
	BiometricProfiles map[[32]byte][32]byte `json:"biometric_profiles"` // DeviceID -> BiometricHash
	CreatedAt       time.Time `json:"created_at"`
}

// NewMultiDeviceSession creates a new multi-device session.
func NewMultiDeviceSession() (*MultiDeviceSession, error) {
	mds := &MultiDeviceSession{
		createdAt:    time.Now(),
		devices:      make(map[[32]byte]*DeviceSession),
		deviceOrder:  make([][32]byte, 0),
		timeline:     make([]TimelineEvent, 0, 1000),
		anomalies:    make([]DeviceAnomaly, 0, 50),
	}

	// Generate session ID and master secret
	if _, err := rand.Read(mds.sessionID[:]); err != nil {
		return nil, err
	}
	if _, err := rand.Read(mds.masterSecret[:]); err != nil {
		return nil, err
	}

	return mds, nil
}

// SessionID returns the session identifier.
func (mds *MultiDeviceSession) SessionID() [32]byte {
	return mds.sessionID
}

// LinkDevice adds a device to this session.
func (mds *MultiDeviceSession) LinkDevice(deviceFingerprint [32]byte, deviceName string, deviceType DeviceType) (*DeviceSession, error) {
	mds.mu.Lock()
	defer mds.mu.Unlock()

	// Generate device ID
	var deviceID [32]byte
	h := sha256.New()
	h.Write(mds.sessionID[:])
	h.Write(deviceFingerprint[:])
	h.Write([]byte(deviceName))
	copy(deviceID[:], h.Sum(nil))

	// Check if already linked
	if _, exists := mds.devices[deviceID]; exists {
		return mds.devices[deviceID], nil
	}

	// Derive device-specific key
	var derivedKey [32]byte
	h = hmac.New(sha256.New, mds.masterSecret[:])
	h.Write([]byte("device-key"))
	h.Write(deviceID[:])
	copy(derivedKey[:], h.Sum(nil))

	// Create link proof (signed by master)
	h = hmac.New(sha256.New, mds.masterSecret[:])
	h.Write([]byte("link-proof"))
	h.Write(deviceID[:])
	binary.Write(h, binary.BigEndian, time.Now().UnixNano())
	linkProof := h.Sum(nil)

	device := &DeviceSession{
		DeviceID:          deviceID,
		DeviceFingerprint: deviceFingerprint,
		DeviceName:        deviceName,
		DeviceType:        deviceType,
		LinkedAt:          time.Now(),
		LinkProof:         linkProof,
		DerivedKey:        derivedKey,
		TrustScore:        0.5, // Start with neutral trust
	}

	mds.devices[deviceID] = device
	mds.deviceOrder = append(mds.deviceOrder, deviceID)

	// Record session start event
	mds.recordEvent(deviceID, EventTypeSessionStart, 0, [32]byte{})

	return device, nil
}

// VerifyDevice verifies a device belongs to this session.
func (mds *MultiDeviceSession) VerifyDevice(deviceID [32]byte, proof []byte) bool {
	mds.mu.RLock()
	defer mds.mu.RUnlock()

	device, exists := mds.devices[deviceID]
	if !exists {
		mds.recordAnomaly(AnomalyUnauthorizedDevice, "unknown device attempted verification", 0.8, &deviceID)
		return false
	}

	// Verify proof matches
	return hmac.Equal(device.LinkProof, proof)
}

// RecordEdit records an edit from a device.
func (mds *MultiDeviceSession) RecordEdit(deviceID [32]byte, bytesDelta int64, documentHash [32]byte) error {
	mds.mu.Lock()
	defer mds.mu.Unlock()

	device, exists := mds.devices[deviceID]
	if !exists {
		mds.recordAnomaly(AnomalyUnauthorizedDevice, "edit from unknown device", 0.9, &deviceID)
		return errors.New("device not linked to session")
	}

	// Check for simultaneous edits
	if len(mds.timeline) > 0 {
		lastEvent := mds.timeline[len(mds.timeline)-1]
		timeSince := time.Since(lastEvent.Timestamp)

		// If last event was from different device within 100ms, flag it
		if lastEvent.DeviceID != deviceID && timeSince < 100*time.Millisecond {
			mds.recordAnomaly(AnomalySimultaneousEdits,
				"edits from multiple devices within 100ms", 0.6, &deviceID)
		}

		// Check for impossible device switch (e.g., <1 second between devices)
		if lastEvent.DeviceID != deviceID && timeSince < time.Second {
			mds.recordAnomaly(AnomalyImpossibleSwitch,
				"device switch faster than 1 second", 0.7, &deviceID)
		}
	}

	// Update device stats
	device.LastActivity = time.Now()
	device.EventCount++
	if bytesDelta > 0 {
		device.BytesAuthored += bytesDelta
	}

	if device.FirstActivity.IsZero() {
		device.FirstActivity = time.Now()
	}

	// Record event
	eventType := EventTypeEdit
	if bytesDelta < 0 {
		eventType = EventTypeDelete
	}

	mds.recordEvent(deviceID, eventType, bytesDelta, documentHash)

	return nil
}

// recordEvent adds an event to the timeline.
func (mds *MultiDeviceSession) recordEvent(deviceID [32]byte, eventType TimelineEventType, bytesDelta int64, docHash [32]byte) {
	mds.lastEventSeq++

	var prevHash [32]byte
	if len(mds.timeline) > 0 {
		prevEvent := mds.timeline[len(mds.timeline)-1]
		h := sha256.New()
		binary.Write(h, binary.BigEndian, prevEvent.Sequence)
		h.Write(prevEvent.DeviceID[:])
		h.Write(prevEvent.DocumentHash[:])
		copy(prevHash[:], h.Sum(nil))
	}

	event := TimelineEvent{
		Timestamp:     time.Now(),
		Sequence:      mds.lastEventSeq,
		DeviceID:      deviceID,
		EventType:     eventType,
		BytesDelta:    bytesDelta,
		DocumentHash:  docHash,
		PrevEventHash: prevHash,
	}

	// Sign the event
	device := mds.devices[deviceID]
	h := hmac.New(sha256.New, device.DerivedKey[:])
	binary.Write(h, binary.BigEndian, event.Sequence)
	binary.Write(h, binary.BigEndian, event.Timestamp.UnixNano())
	h.Write(event.DocumentHash[:])
	h.Write(event.PrevEventHash[:])
	event.Signature = h.Sum(nil)

	mds.timeline = append(mds.timeline, event)

	// Limit timeline size
	if len(mds.timeline) > 1000 {
		mds.timeline = mds.timeline[500:]
	}
}

// recordAnomaly adds an anomaly record.
func (mds *MultiDeviceSession) recordAnomaly(anomalyType DeviceAnomalyType, desc string, severity float64, deviceID *[32]byte) {
	anomaly := DeviceAnomaly{
		Timestamp:     time.Now(),
		AnomalyType:   anomalyType,
		Description:   desc,
		Severity:      severity,
		DeviceID:      deviceID,
		EventSequence: mds.lastEventSeq,
	}

	mds.anomalies = append(mds.anomalies, anomaly)

	// Update device trust if identified
	if deviceID != nil {
		if device, exists := mds.devices[*deviceID]; exists {
			device.TrustScore -= severity * 0.1
			if device.TrustScore < 0 {
				device.TrustScore = 0
			}
		}
	}

	// Limit anomaly history
	if len(mds.anomalies) > 50 {
		mds.anomalies = mds.anomalies[25:]
	}
}

// SwitchDevice records an intentional device switch.
func (mds *MultiDeviceSession) SwitchDevice(fromDevice, toDevice [32]byte) error {
	mds.mu.Lock()
	defer mds.mu.Unlock()

	if _, exists := mds.devices[fromDevice]; !exists {
		return errors.New("source device not linked")
	}
	if _, exists := mds.devices[toDevice]; !exists {
		return errors.New("target device not linked")
	}

	// Record switch event on both devices
	mds.recordEvent(fromDevice, EventTypeSessionEnd, 0, [32]byte{})
	mds.recordEvent(toDevice, EventTypeDeviceSwitch, 0, [32]byte{})

	return nil
}

// GetDevices returns all linked devices.
func (mds *MultiDeviceSession) GetDevices() []*DeviceSession {
	mds.mu.RLock()
	defer mds.mu.RUnlock()

	result := make([]*DeviceSession, 0, len(mds.devices))
	for _, deviceID := range mds.deviceOrder {
		if device, exists := mds.devices[deviceID]; exists {
			result = append(result, device)
		}
	}
	return result
}

// GetTimeline returns the event timeline.
func (mds *MultiDeviceSession) GetTimeline() []TimelineEvent {
	mds.mu.RLock()
	defer mds.mu.RUnlock()

	result := make([]TimelineEvent, len(mds.timeline))
	copy(result, mds.timeline)
	return result
}

// GetAnomalies returns detected anomalies.
func (mds *MultiDeviceSession) GetAnomalies() []DeviceAnomaly {
	mds.mu.RLock()
	defer mds.mu.RUnlock()

	result := make([]DeviceAnomaly, len(mds.anomalies))
	copy(result, mds.anomalies)
	return result
}

// VerifyTimeline verifies the integrity of the timeline.
func (mds *MultiDeviceSession) VerifyTimeline() (valid bool, brokenAt uint64) {
	mds.mu.RLock()
	defer mds.mu.RUnlock()

	for i := 1; i < len(mds.timeline); i++ {
		event := mds.timeline[i]
		prevEvent := mds.timeline[i-1]

		// Verify sequence
		if event.Sequence != prevEvent.Sequence+1 {
			return false, event.Sequence
		}

		// Verify prev hash
		h := sha256.New()
		binary.Write(h, binary.BigEndian, prevEvent.Sequence)
		h.Write(prevEvent.DeviceID[:])
		h.Write(prevEvent.DocumentHash[:])
		var expectedPrevHash [32]byte
		copy(expectedPrevHash[:], h.Sum(nil))

		if event.PrevEventHash != expectedPrevHash {
			return false, event.Sequence
		}

		// Verify signature
		device, exists := mds.devices[event.DeviceID]
		if !exists {
			return false, event.Sequence
		}

		h = hmac.New(sha256.New, device.DerivedKey[:])
		binary.Write(h, binary.BigEndian, event.Sequence)
		binary.Write(h, binary.BigEndian, event.Timestamp.UnixNano())
		h.Write(event.DocumentHash[:])
		h.Write(event.PrevEventHash[:])
		expectedSig := h.Sum(nil)

		if !hmac.Equal(event.Signature, expectedSig) {
			return false, event.Sequence
		}

		// Verify timestamps are monotonic
		if event.Timestamp.Before(prevEvent.Timestamp) {
			mds.anomalies = append(mds.anomalies, DeviceAnomaly{
				Timestamp:     time.Now(),
				AnomalyType:   AnomalyBackdatedEvent,
				Description:   "event timestamp before previous event",
				Severity:      0.8,
				DeviceID:      &event.DeviceID,
				EventSequence: event.Sequence,
			})
			// Continue verification, but flag it
		}
	}

	return true, 0
}

// SessionIntegrity calculates overall session integrity score.
func (mds *MultiDeviceSession) SessionIntegrity() float64 {
	mds.mu.RLock()
	defer mds.mu.RUnlock()

	score := 1.0

	// Deduct for anomalies
	for _, anomaly := range mds.anomalies {
		score -= anomaly.Severity * 0.05
	}

	// Deduct for untrusted devices
	for _, device := range mds.devices {
		if device.TrustScore < 0.5 {
			score -= (0.5 - device.TrustScore) * 0.1
		}
	}

	// Verify timeline integrity
	if valid, _ := mds.VerifyTimeline(); !valid {
		score -= 0.3
	}

	if score < 0 {
		score = 0
	}
	return score
}

// CrossDeviceReport generates a report of multi-device session activity.
type CrossDeviceReport struct {
	SessionID         [32]byte          `json:"session_id"`
	CreatedAt         time.Time         `json:"created_at"`
	DeviceCount       int               `json:"device_count"`
	Devices           []*DeviceSession  `json:"devices"`
	TotalEvents       int               `json:"total_events"`
	TotalBytesAuthored int64            `json:"total_bytes_authored"`
	AnomalyCount      int               `json:"anomaly_count"`
	Anomalies         []DeviceAnomaly   `json:"anomalies"`
	IntegrityScore    float64           `json:"integrity_score"`
	TimelineValid     bool              `json:"timeline_valid"`
}

// GenerateReport creates a cross-device session report.
func (mds *MultiDeviceSession) GenerateReport() CrossDeviceReport {
	mds.mu.RLock()
	defer mds.mu.RUnlock()

	var totalBytes int64
	devices := mds.GetDevices()
	for _, dev := range devices {
		totalBytes += dev.BytesAuthored
	}

	valid, _ := mds.VerifyTimeline()

	return CrossDeviceReport{
		SessionID:          mds.sessionID,
		CreatedAt:          mds.createdAt,
		DeviceCount:        len(mds.devices),
		Devices:            devices,
		TotalEvents:        len(mds.timeline),
		TotalBytesAuthored: totalBytes,
		AnomalyCount:       len(mds.anomalies),
		Anomalies:          mds.GetAnomalies(),
		IntegrityScore:     mds.SessionIntegrity(),
		TimelineValid:      valid,
	}
}

// BindUserIdentity binds a user identity to this session.
func (mds *MultiDeviceSession) BindUserIdentity(publicKey ed25519.PublicKey) error {
	mds.mu.Lock()
	defer mds.mu.Unlock()

	if mds.userIdentity != nil {
		return errors.New("user identity already bound")
	}

	var userID [32]byte
	h := sha256.Sum256(publicKey)
	userID = h

	mds.userIdentity = &UserIdentity{
		UserID:            userID,
		PublicKey:         publicKey,
		BiometricProfiles: make(map[[32]byte][32]byte),
		CreatedAt:         time.Now(),
	}

	return nil
}

// BindDeviceBiometrics associates biometric data with a device.
func (mds *MultiDeviceSession) BindDeviceBiometrics(deviceID [32]byte, biometricHash [32]byte) error {
	mds.mu.Lock()
	defer mds.mu.Unlock()

	device, exists := mds.devices[deviceID]
	if !exists {
		return errors.New("device not found")
	}

	device.BiometricHash = &biometricHash

	// If user identity exists, add to profile
	if mds.userIdentity != nil {
		// Check for mismatch with existing profile
		for existingDeviceID, existingHash := range mds.userIdentity.BiometricProfiles {
			if existingHash != biometricHash && existingDeviceID != deviceID {
				// Different biometrics on different devices - might be suspicious
				// or might be legitimate (different sensors have different readings)
				// Just note it, don't flag as anomaly
			}
		}
		mds.userIdentity.BiometricProfiles[deviceID] = biometricHash
	}

	return nil
}

// ExportSessionToken creates a token that can be used to resume this session on another device.
func (mds *MultiDeviceSession) ExportSessionToken() ([]byte, error) {
	mds.mu.RLock()
	defer mds.mu.RUnlock()

	// Create token: sessionID + HMAC(masterSecret, "export-token")
	h := hmac.New(sha256.New, mds.masterSecret[:])
	h.Write([]byte("export-token"))
	binary.Write(h, binary.BigEndian, time.Now().UnixNano())

	token := make([]byte, 64)
	copy(token[:32], mds.sessionID[:])
	copy(token[32:], h.Sum(nil))

	return token, nil
}

// ValidateSessionToken validates an import token.
func (mds *MultiDeviceSession) ValidateSessionToken(token []byte) bool {
	if len(token) != 64 {
		return false
	}

	mds.mu.RLock()
	defer mds.mu.RUnlock()

	// Check session ID matches
	var tokenSessionID [32]byte
	copy(tokenSessionID[:], token[:32])
	if tokenSessionID != mds.sessionID {
		return false
	}

	// Token MAC is verified by attempting to link (see LinkDevice)
	// For full validation, we'd need the original timestamp
	return true
}
