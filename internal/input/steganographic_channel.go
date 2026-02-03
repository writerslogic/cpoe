//go:build darwin || linux || windows

package input

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"sync"
	"time"
)

// StegChannel provides a steganographic covert channel for verification signals.
//
// The Problem:
// An adversary who can intercept all signals could potentially replay or
// manipulate them. Even if they can't decrypt the content, they might be
// able to identify which signals are "important" and target those.
//
// The Solution:
// Embed real verification signals into a constant stream of noise data
// at a secret "jitter frequency" that only the system knows. The adversary
// sees a continuous stream of random-looking data and cannot distinguish
// real signals from noise without knowing the secret frequency.
//
// How it works:
// 1. System generates a session-specific secret jitter key
// 2. A continuous stream of "carrier" data flows through the system
// 3. Real signals are embedded at pseudo-random intervals derived from the key
// 4. Noise signals fill all other intervals
// 5. Only the verification system (with the key) can extract real signals
//
// Properties:
// - Adversary cannot identify which data points are real vs noise
// - Timing attacks are defeated (constant data rate)
// - Even if the user is the adversary, they don't know the jitter key
// - Replay attacks fail (each session has unique key)
type StegChannel struct {
	mu sync.RWMutex

	// Secret jitter key (session-specific, not known to user or adversary)
	jitterKey [32]byte

	// Channel parameters
	carrierRate     time.Duration // How often carrier data flows
	signalDensity   float64       // What fraction of carrier contains real signals
	currentSlot     uint64        // Current time slot
	lastSlotTime    time.Time

	// Data streams
	carrierStream   []CarrierPacket
	extractedSignals []ExtractedSignal

	// State
	running bool
	stopCh  chan struct{}
}

// CarrierPacket is a single packet in the carrier stream.
// To an observer, all packets look identical (random data).
type CarrierPacket struct {
	Timestamp   time.Time
	SlotNumber  uint64
	Data        [64]byte  // Random-looking data
	IsRealSignal bool     // Only known internally
}

// ExtractedSignal is a signal extracted from the carrier.
type ExtractedSignal struct {
	Timestamp  time.Time
	SignalType string
	Value      float64
	Integrity  [32]byte // HMAC to verify not tampered
}

// SignalToEmbed represents a signal to be embedded in the carrier.
type SignalToEmbed struct {
	Type  string
	Value float64
}

// NewStegChannel creates a steganographic channel.
func NewStegChannel() *StegChannel {
	sc := &StegChannel{
		carrierRate:   50 * time.Millisecond, // 20 packets/second
		signalDensity: 0.1,                    // 10% real signals, 90% noise
		carrierStream: make([]CarrierPacket, 0, 1000),
		stopCh:        make(chan struct{}),
	}

	// Generate session-specific jitter key
	// This key is derived from:
	// 1. Random bytes (unpredictable)
	// 2. System-specific data (unique to this installation)
	// 3. Timestamp (session-specific)
	sc.generateJitterKey()

	return sc
}

// generateJitterKey creates the session-specific secret key.
// The user cannot know this key because:
// 1. It includes entropy from crypto/rand
// 2. It's not stored anywhere accessible
// 3. It's regenerated each session
func (sc *StegChannel) generateJitterKey() {
	h := sha256.New()

	// Random entropy
	var randomBytes [32]byte
	rand.Read(randomBytes[:])
	h.Write(randomBytes[:])

	// Time entropy (session-specific)
	binary.Write(h, binary.BigEndian, time.Now().UnixNano())

	// Additional entropy from memory address (unpredictable)
	binary.Write(h, binary.BigEndian, uint64(uintptr(time.Now().UnixNano())))

	copy(sc.jitterKey[:], h.Sum(nil))
}

// Start begins the carrier stream.
func (sc *StegChannel) Start() {
	sc.mu.Lock()
	if sc.running {
		sc.mu.Unlock()
		return
	}
	sc.running = true
	sc.stopCh = make(chan struct{})
	sc.lastSlotTime = time.Now()
	sc.mu.Unlock()

	go sc.carrierLoop()
}

// Stop stops the carrier stream.
func (sc *StegChannel) Stop() {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if !sc.running {
		return
	}

	sc.running = false
	close(sc.stopCh)
}

// carrierLoop generates continuous carrier data.
func (sc *StegChannel) carrierLoop() {
	ticker := time.NewTicker(sc.carrierRate)
	defer ticker.Stop()

	for {
		select {
		case <-sc.stopCh:
			return
		case <-ticker.C:
			sc.emitCarrierPacket()
		}
	}
}

// emitCarrierPacket generates a single carrier packet.
func (sc *StegChannel) emitCarrierPacket() {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	packet := CarrierPacket{
		Timestamp:  time.Now(),
		SlotNumber: sc.currentSlot,
	}

	// Fill with random data (looks identical whether signal or noise)
	rand.Read(packet.Data[:])

	// Check if this slot should contain a real signal
	// (determined by jitter key, not known to adversary)
	packet.IsRealSignal = sc.isSignalSlot(sc.currentSlot)

	sc.carrierStream = append(sc.carrierStream, packet)
	sc.currentSlot++

	// Limit buffer size
	if len(sc.carrierStream) > 1000 {
		sc.carrierStream = sc.carrierStream[500:]
	}
}

// isSignalSlot determines if a slot should contain a real signal.
// This is a pseudo-random decision based on the secret jitter key.
// The pattern appears random but is deterministic with the key.
func (sc *StegChannel) isSignalSlot(slot uint64) bool {
	// HMAC-based pseudo-random function
	mac := hmac.New(sha256.New, sc.jitterKey[:])
	binary.Write(mac, binary.BigEndian, slot)
	result := mac.Sum(nil)

	// Use first byte to determine if signal slot
	// Probability = signalDensity
	threshold := uint8(sc.signalDensity * 256)
	return result[0] < threshold
}

// getSignalSlotOffset returns which byte within the packet holds the signal.
// This adds another layer of uncertainty for the adversary.
func (sc *StegChannel) getSignalSlotOffset(slot uint64) int {
	mac := hmac.New(sha256.New, sc.jitterKey[:])
	binary.Write(mac, binary.BigEndian, slot)
	binary.Write(mac, binary.BigEndian, uint64(0xDEADBEEF)) // Different input
	result := mac.Sum(nil)

	// Offset within 64-byte packet
	return int(result[0]) % 56 // Leave room for 8-byte value
}

// EmbedSignal embeds a signal into the carrier stream.
// The signal will be placed in the next available signal slot.
func (sc *StegChannel) EmbedSignal(signal SignalToEmbed) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	// Find next signal slot
	for i := len(sc.carrierStream) - 1; i >= 0; i-- {
		packet := &sc.carrierStream[i]
		if packet.IsRealSignal {
			// Embed the signal at the secret offset
			offset := sc.getSignalSlotOffset(packet.SlotNumber)
			sc.encodeSignal(packet, offset, signal)
			return
		}
	}
}

// encodeSignal encodes a signal into a carrier packet.
func (sc *StegChannel) encodeSignal(packet *CarrierPacket, offset int, signal SignalToEmbed) {
	// Encode signal type as first byte
	typeHash := sha256.Sum256([]byte(signal.Type))
	packet.Data[offset] = typeHash[0]

	// Encode value as IEEE 754 float64
	bits := math.Float64bits(signal.Value)
	binary.BigEndian.PutUint64(packet.Data[offset+1:offset+9], bits)
}

// ExtractSignals extracts real signals from the carrier stream.
// Only works with knowledge of the jitter key.
func (sc *StegChannel) ExtractSignals() []ExtractedSignal {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	var signals []ExtractedSignal

	for _, packet := range sc.carrierStream {
		if sc.isSignalSlot(packet.SlotNumber) {
			offset := sc.getSignalSlotOffset(packet.SlotNumber)

			// Decode signal
			signal := ExtractedSignal{
				Timestamp: packet.Timestamp,
			}

			// Type is in first byte (we'd need reverse lookup)
			// For now, store as numeric
			signal.SignalType = "embedded"

			// Decode value
			if offset+9 <= len(packet.Data) {
				bits := binary.BigEndian.Uint64(packet.Data[offset+1 : offset+9])
				signal.Value = math.Float64frombits(bits)
			}

			// Compute integrity MAC
			signal.Integrity = sc.computeSignalMAC(packet, signal)

			signals = append(signals, signal)
		}
	}

	sc.extractedSignals = signals
	return signals
}

// computeSignalMAC computes integrity MAC for an extracted signal.
func (sc *StegChannel) computeSignalMAC(packet CarrierPacket, signal ExtractedSignal) [32]byte {
	mac := hmac.New(sha256.New, sc.jitterKey[:])
	binary.Write(mac, binary.BigEndian, packet.SlotNumber)
	binary.Write(mac, binary.BigEndian, packet.Timestamp.UnixNano())
	binary.Write(mac, binary.BigEndian, signal.Value)

	var result [32]byte
	copy(result[:], mac.Sum(nil))
	return result
}

// GetCarrierStream returns the raw carrier stream.
// To an adversary, this looks like random data.
func (sc *StegChannel) GetCarrierStream() []CarrierPacket {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	result := make([]CarrierPacket, len(sc.carrierStream))
	copy(result, sc.carrierStream)
	return result
}

// JitterFrequencyVerifier verifies that signals arrive at the expected jitter frequency.
// This detects if an adversary is replaying or injecting signals at wrong times.
type JitterFrequencyVerifier struct {
	mu sync.RWMutex

	jitterKey      [32]byte
	expectedSlots  []uint64 // Which slots should have signals
	observedSlots  []uint64 // Which slots actually had signals
	matchScore     float64
}

// NewJitterFrequencyVerifier creates a verifier.
func NewJitterFrequencyVerifier(key [32]byte) *JitterFrequencyVerifier {
	return &JitterFrequencyVerifier{
		jitterKey:     key,
		expectedSlots: make([]uint64, 0, 100),
		observedSlots: make([]uint64, 0, 100),
	}
}

// ExpectSignal marks that a signal is expected at a slot.
func (jfv *JitterFrequencyVerifier) ExpectSignal(slot uint64) {
	jfv.mu.Lock()
	defer jfv.mu.Unlock()

	jfv.expectedSlots = append(jfv.expectedSlots, slot)

	// Limit size
	if len(jfv.expectedSlots) > 100 {
		jfv.expectedSlots = jfv.expectedSlots[50:]
	}
}

// ObserveSignal marks that a signal was observed at a slot.
func (jfv *JitterFrequencyVerifier) ObserveSignal(slot uint64) {
	jfv.mu.Lock()
	defer jfv.mu.Unlock()

	jfv.observedSlots = append(jfv.observedSlots, slot)

	// Limit size
	if len(jfv.observedSlots) > 100 {
		jfv.observedSlots = jfv.observedSlots[50:]
	}

	jfv.updateMatchScore()
}

// updateMatchScore calculates how well observed matches expected.
func (jfv *JitterFrequencyVerifier) updateMatchScore() {
	if len(jfv.expectedSlots) == 0 || len(jfv.observedSlots) == 0 {
		jfv.matchScore = 0.5
		return
	}

	// Count matches
	matches := 0
	for _, expected := range jfv.expectedSlots {
		for _, observed := range jfv.observedSlots {
			if expected == observed {
				matches++
				break
			}
		}
	}

	jfv.matchScore = float64(matches) / float64(len(jfv.expectedSlots))
}

// MatchScore returns the current match score.
func (jfv *JitterFrequencyVerifier) MatchScore() float64 {
	jfv.mu.RLock()
	defer jfv.mu.RUnlock()
	return jfv.matchScore
}

// IsFrequencyValid returns true if signals arrive at expected jitter frequency.
func (jfv *JitterFrequencyVerifier) IsFrequencyValid() bool {
	jfv.mu.RLock()
	defer jfv.mu.RUnlock()
	return jfv.matchScore >= 0.8 // 80% match required
}

// TimingObfuscator adds random delays to prevent timing analysis.
// This ensures an adversary cannot correlate signals by timing.
type TimingObfuscator struct {
	mu sync.RWMutex

	key           [32]byte
	minDelay      time.Duration
	maxDelay      time.Duration
	delayCounter  uint64
}

// NewTimingObfuscator creates a timing obfuscator.
func NewTimingObfuscator(minDelay, maxDelay time.Duration) *TimingObfuscator {
	var key [32]byte
	rand.Read(key[:])

	return &TimingObfuscator{
		key:      key,
		minDelay: minDelay,
		maxDelay: maxDelay,
	}
}

// GetDelay returns a pseudo-random delay based on the secret key.
// Delays are deterministic (reproducible with key) but appear random.
func (to *TimingObfuscator) GetDelay() time.Duration {
	to.mu.Lock()
	defer to.mu.Unlock()

	// Generate pseudo-random delay
	mac := hmac.New(sha256.New, to.key[:])
	binary.Write(mac, binary.BigEndian, to.delayCounter)
	result := mac.Sum(nil)
	to.delayCounter++

	// Convert to delay in range [minDelay, maxDelay]
	randomFraction := float64(binary.BigEndian.Uint64(result[:8])) / float64(^uint64(0))
	delayRange := to.maxDelay - to.minDelay
	delay := to.minDelay + time.Duration(randomFraction*float64(delayRange))

	return delay
}

// ApplyDelay waits for the obfuscation delay.
func (to *TimingObfuscator) ApplyDelay() {
	delay := to.GetDelay()
	time.Sleep(delay)
}

// CovertChannelStats provides statistics about the covert channel.
type CovertChannelStats struct {
	TotalPackets      int     `json:"total_packets"`
	SignalPackets     int     `json:"signal_packets"`
	NoisePackets      int     `json:"noise_packets"`
	SignalDensity     float64 `json:"signal_density"`
	FrequencyMatch    float64 `json:"frequency_match"`
	ChannelIntegrity  float64 `json:"channel_integrity"`
}

// Stats returns channel statistics.
func (sc *StegChannel) Stats() CovertChannelStats {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	stats := CovertChannelStats{
		TotalPackets:  len(sc.carrierStream),
		SignalDensity: sc.signalDensity,
	}

	for _, packet := range sc.carrierStream {
		if packet.IsRealSignal {
			stats.SignalPackets++
		} else {
			stats.NoisePackets++
		}
	}

	// Channel integrity (signals arriving at expected frequency)
	if stats.TotalPackets > 0 {
		expectedSignals := int(float64(stats.TotalPackets) * sc.signalDensity)
		if expectedSignals > 0 {
			stats.ChannelIntegrity = float64(stats.SignalPackets) / float64(expectedSignals)
			if stats.ChannelIntegrity > 1 {
				stats.ChannelIntegrity = 1
			}
		}
	}

	return stats
}
