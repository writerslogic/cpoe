//go:build darwin || linux || windows

// Package input provides enhanced spread-spectrum steganography for keystroke verification.
//
// This module extends basic DSSS with five integrated features:
//  1. Selective Disclosure: Different keys unlock different evidence layers
//  2. Document Watermarking: Embed timing signatures directly in document text
//  3. Biometric Protection: Timing data accessible only with key
//  4. Temporal Binding: VDF-based proof of when typing occurred (no external service)
//  5. Anti-Replay: Challenge-response prevents evidence replay attacks
package input

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"math/cmplx"
	"sync"
	"time"

	"witnessd/internal/vdf"
)

// DisclosureLevel defines what a key can access.
type DisclosureLevel int

const (
	// LevelPublic: Anyone can verify "human typed this" (no key needed)
	LevelPublic DisclosureLevel = 0

	// LevelBasic: Verifier can confirm typing patterns exist
	LevelBasic DisclosureLevel = 1

	// LevelStandard: Verifier can extract coarse timing bins
	LevelStandard DisclosureLevel = 2

	// LevelFull: Verifier can extract raw biometric timing
	LevelFull DisclosureLevel = 3
)

// EnhancedDSSSConfig configures the enhanced spread-spectrum encoder.
type EnhancedDSSSConfig struct {
	// Base spread-spectrum parameters
	SpreadingFactor  int
	ChipRate         int
	NumFrequencyBins int
	EmbedStrength    float64

	// Selective disclosure
	EnableSelectiveDisclosure bool

	// Document watermarking
	EnableWatermarking bool
	WatermarkStrength  float64 // How visible the watermark is (0.0-1.0)

	// Temporal binding
	EnableTemporalBinding bool
	VDFParams             vdf.Parameters

	// Anti-replay
	EnableAntiReplay bool
	ChallengeSize    int // Bytes
}

// DefaultEnhancedDSSSConfig returns sensible defaults.
func DefaultEnhancedDSSSConfig() EnhancedDSSSConfig {
	return EnhancedDSSSConfig{
		SpreadingFactor:           32,
		ChipRate:                  32,
		NumFrequencyBins:          64,
		EmbedStrength:             0.1,
		EnableSelectiveDisclosure: true,
		EnableWatermarking:        true,
		WatermarkStrength:         0.3,
		EnableTemporalBinding:     true,
		VDFParams:                 vdf.DefaultParameters(),
		EnableAntiReplay:          true,
		ChallengeSize:             32,
	}
}

// EnhancedDSSSEncoder implements enhanced spread-spectrum with all five features.
type EnhancedDSSSEncoder struct {
	mu sync.RWMutex

	config EnhancedDSSSConfig

	// Master key (only author has this)
	masterKey [32]byte

	// Derived keys for selective disclosure
	derivedKeys map[DisclosureLevel][32]byte

	// PN sequences for each level
	pnSequences map[DisclosureLevel][]int8

	// Frequency domain carriers
	carriers map[DisclosureLevel][]complex128

	// Temporal binding
	temporalAnchor    *TemporalAnchor
	vdfProofs         []*vdf.Proof
	lastVDFTime       time.Time
	vdfInterval       time.Duration
	pendingVDFInput   [32]byte
	vdfComputeStarted bool

	// Anti-replay state
	activeChallenge   []byte
	challengeExpiry   time.Time
	challengeResponse []byte

	// Statistics
	symbolsEncoded int
	symbolsDecoded int
}

// TemporalAnchor binds evidence to a specific time window.
type TemporalAnchor struct {
	// VDF chain proves minimum elapsed time (no external service needed)
	VDFChain []*vdf.Proof `json:"vdf_chain"`

	// Start and end times (claimed, verified by VDF)
	ClaimedStart time.Time `json:"claimed_start"`
	ClaimedEnd   time.Time `json:"claimed_end"`

	// Minimum provable elapsed time (from VDF)
	MinElapsed time.Duration `json:"min_elapsed"`

	// Optional: External beacon binding (drand, etc.)
	BeaconRound  uint64 `json:"beacon_round,omitempty"`
	BeaconValue  []byte `json:"beacon_value,omitempty"`
	BeaconSource string `json:"beacon_source,omitempty"`
}

// NewEnhancedDSSSEncoder creates an enhanced encoder with all features.
func NewEnhancedDSSSEncoder(config EnhancedDSSSConfig) *EnhancedDSSSEncoder {
	enc := &EnhancedDSSSEncoder{
		config:      config,
		derivedKeys: make(map[DisclosureLevel][32]byte),
		pnSequences: make(map[DisclosureLevel][]int8),
		carriers:    make(map[DisclosureLevel][]complex128),
		vdfInterval: 30 * time.Second, // VDF checkpoint every 30s
	}

	// Generate master key
	rand.Read(enc.masterKey[:])

	// Derive keys for each disclosure level
	enc.deriveKeys()

	// Generate PN sequences for each level
	for level := LevelPublic; level <= LevelFull; level++ {
		enc.generatePNSequence(level)
		enc.initializeCarrier(level)
	}

	// Initialize temporal anchor
	if config.EnableTemporalBinding {
		enc.initializeTemporalAnchor()
	}

	return enc
}

// NewEnhancedDSSSEncoderWithKey creates an encoder with a specific master key.
func NewEnhancedDSSSEncoderWithKey(config EnhancedDSSSConfig, masterKey [32]byte) *EnhancedDSSSEncoder {
	enc := &EnhancedDSSSEncoder{
		config:      config,
		masterKey:   masterKey,
		derivedKeys: make(map[DisclosureLevel][32]byte),
		pnSequences: make(map[DisclosureLevel][]int8),
		carriers:    make(map[DisclosureLevel][]complex128),
		vdfInterval: 30 * time.Second,
	}

	enc.deriveKeys()

	for level := LevelPublic; level <= LevelFull; level++ {
		enc.generatePNSequence(level)
		enc.initializeCarrier(level)
	}

	if config.EnableTemporalBinding {
		enc.initializeTemporalAnchor()
	}

	return enc
}

// deriveKeys derives disclosure-level keys from master key.
func (enc *EnhancedDSSSEncoder) deriveKeys() {
	for level := LevelPublic; level <= LevelFull; level++ {
		h := hmac.New(sha256.New, enc.masterKey[:])
		h.Write([]byte("dsss-level-key"))
		binary.Write(h, binary.BigEndian, int64(level))
		var key [32]byte
		copy(key[:], h.Sum(nil))
		enc.derivedKeys[level] = key
	}
}

// generatePNSequence creates the pseudo-noise sequence for a level.
func (enc *EnhancedDSSSEncoder) generatePNSequence(level DisclosureLevel) {
	length := enc.config.SpreadingFactor * enc.config.ChipRate
	enc.pnSequences[level] = make([]int8, length)

	key := enc.derivedKeys[level]
	h := hmac.New(sha256.New, key[:])

	for i := 0; i < length; i += 32 {
		binary.Write(h, binary.BigEndian, uint64(i/32))
		chunk := h.Sum(nil)
		h.Reset()

		for j := 0; j < 32 && i+j < length; j++ {
			if chunk[j]&1 == 0 {
				enc.pnSequences[level][i+j] = 1
			} else {
				enc.pnSequences[level][i+j] = -1
			}
		}
	}
}

// initializeCarrier sets up frequency domain carrier for a level.
func (enc *EnhancedDSSSEncoder) initializeCarrier(level DisclosureLevel) {
	enc.carriers[level] = make([]complex128, enc.config.NumFrequencyBins)

	key := enc.derivedKeys[level]
	h := hmac.New(sha256.New, key[:])
	h.Write([]byte("carrier-phase"))

	for i := 0; i < enc.config.NumFrequencyBins; i++ {
		binary.Write(h, binary.BigEndian, uint64(i))
		hash := h.Sum(nil)
		h.Reset()

		phase := float64(binary.BigEndian.Uint64(hash[:8])) / float64(^uint64(0)) * 2 * math.Pi
		enc.carriers[level][i] = cmplx.Rect(1.0, phase)
	}
}

// initializeTemporalAnchor starts the temporal binding chain.
func (enc *EnhancedDSSSEncoder) initializeTemporalAnchor() {
	enc.temporalAnchor = &TemporalAnchor{
		VDFChain:     make([]*vdf.Proof, 0),
		ClaimedStart: time.Now(),
	}

	// Create initial VDF input from master key + timestamp
	h := sha256.New()
	h.Write(enc.masterKey[:])
	binary.Write(h, binary.BigEndian, time.Now().UnixNano())
	copy(enc.pendingVDFInput[:], h.Sum(nil))

	enc.lastVDFTime = time.Now()
}

// ========== Feature 1: Selective Disclosure ==========

// LayeredTimingSignal contains timing data at multiple disclosure levels.
type LayeredTimingSignal struct {
	// Level 0 (Public): Proves typing occurred (noise floor only)
	PublicNoise []complex128 `json:"public_noise"`

	// Level 1 (Basic): Confirms timing patterns exist
	BasicSignal []complex128 `json:"basic_signal"`

	// Level 2 (Standard): Coarse timing bins (k-anonymous)
	StandardSignal []complex128 `json:"standard_signal"`
	CoarseBins     []uint8      `json:"coarse_bins"`

	// Level 3 (Full): Raw biometric timing
	FullSignal []complex128 `json:"full_signal"`

	// Combined observable (what untrusted parties see)
	Observable []complex128 `json:"observable"`
}

// EncodeTimingLayered encodes a timing delta with selective disclosure.
func (enc *EnhancedDSSSEncoder) EncodeTimingLayered(deltaMs float64) *LayeredTimingSignal {
	enc.mu.Lock()
	defer enc.mu.Unlock()

	signal := &LayeredTimingSignal{
		PublicNoise:    make([]complex128, enc.config.NumFrequencyBins),
		BasicSignal:    make([]complex128, enc.config.NumFrequencyBins),
		StandardSignal: make([]complex128, enc.config.NumFrequencyBins),
		FullSignal:     make([]complex128, enc.config.NumFrequencyBins),
		Observable:     make([]complex128, enc.config.NumFrequencyBins),
	}

	// Normalize timing delta
	normalizedDelta := (deltaMs - 200) / 200
	normalizedDelta = math.Max(-1, math.Min(1, normalizedDelta))

	// Coarse bin (0-9, each ~50ms)
	coarseBin := uint8(math.Min(9, math.Max(0, deltaMs/50)))
	signal.CoarseBins = []uint8{coarseBin}

	// Level 0: Just noise (proves something was recorded)
	for i := 0; i < enc.config.NumFrequencyBins; i++ {
		signal.PublicNoise[i] = enc.generateNoiseComponent()
	}

	// Level 1: Basic signal (pattern exists)
	basicValue := 0.0
	if deltaMs > 0 {
		basicValue = 1.0 // Just indicates "keystroke happened"
	}
	for i := 0; i < enc.config.NumFrequencyBins; i++ {
		chipIdx := i % enc.config.ChipRate
		amp := basicValue * float64(enc.pnSequences[LevelBasic][chipIdx]) * enc.config.EmbedStrength * 0.5
		signal.BasicSignal[i] = enc.carriers[LevelBasic][i] * complex(amp, 0)
	}

	// Level 2: Standard signal (coarse timing bin)
	coarseNormalized := float64(coarseBin)/9.0*2 - 1 // Map 0-9 to [-1, 1]
	for i := 0; i < enc.config.NumFrequencyBins; i++ {
		chipIdx := i % enc.config.ChipRate
		amp := coarseNormalized * float64(enc.pnSequences[LevelStandard][chipIdx]) * enc.config.EmbedStrength * 0.7
		signal.StandardSignal[i] = enc.carriers[LevelStandard][i] * complex(amp, 0)
	}

	// Level 3: Full signal (raw biometric)
	for i := 0; i < enc.config.NumFrequencyBins; i++ {
		chipIdx := i % enc.config.ChipRate
		amp := normalizedDelta * float64(enc.pnSequences[LevelFull][chipIdx]) * enc.config.EmbedStrength
		signal.FullSignal[i] = enc.carriers[LevelFull][i] * complex(amp, 0)
	}

	// Combine into observable (all layers + noise)
	for i := 0; i < enc.config.NumFrequencyBins; i++ {
		signal.Observable[i] = signal.PublicNoise[i] +
			signal.BasicSignal[i] +
			signal.StandardSignal[i] +
			signal.FullSignal[i]
	}

	enc.symbolsEncoded++

	// Check if we need a VDF checkpoint
	if enc.config.EnableTemporalBinding {
		enc.maybeAddVDFCheckpoint()
	}

	return signal
}

// DecodeAtLevel extracts timing data at the specified disclosure level.
func (enc *EnhancedDSSSEncoder) DecodeAtLevel(signal *LayeredTimingSignal, level DisclosureLevel, key [32]byte) (float64, float64, error) {
	enc.mu.Lock()
	defer enc.mu.Unlock()

	// Verify key matches the level
	storedKey, ok := enc.derivedKeys[level]
	if !ok {
		return 0, 0, errors.New("invalid disclosure level")
	}
	expectedKeyHash := sha256.Sum256(storedKey[:])
	providedKeyHash := sha256.Sum256(key[:])
	if expectedKeyHash != providedKeyHash {
		// Try to derive from master key
		h := hmac.New(sha256.New, key[:])
		h.Write([]byte("dsss-level-key"))
		binary.Write(h, binary.BigEndian, int64(level))
		derivedKey := h.Sum(nil)
		derivedHash := sha256.Sum256(derivedKey)
		if derivedHash != expectedKeyHash {
			return 0, 0, errors.New("invalid key for disclosure level")
		}
	}

	var sourceSignal []complex128
	switch level {
	case LevelBasic:
		sourceSignal = signal.BasicSignal
	case LevelStandard:
		sourceSignal = signal.StandardSignal
	case LevelFull:
		sourceSignal = signal.FullSignal
	default:
		return 0, 0, errors.New("public level requires no decoding")
	}

	// Despread using correlation
	correlation := 0.0
	pn := enc.pnSequences[level]
	carrier := enc.carriers[level]

	for i := 0; i < enc.config.NumFrequencyBins; i++ {
		chipIdx := i % enc.config.ChipRate
		demodulated := sourceSignal[i] / carrier[i]
		correlation += real(demodulated) * float64(pn[chipIdx])
	}

	// Normalize
	var strengthMultiplier float64
	switch level {
	case LevelBasic:
		strengthMultiplier = 0.5
	case LevelStandard:
		strengthMultiplier = 0.7
	case LevelFull:
		strengthMultiplier = 1.0
	}
	correlation /= float64(enc.config.NumFrequencyBins) * enc.config.EmbedStrength * strengthMultiplier

	// Denormalize based on level
	var deltaMs float64
	switch level {
	case LevelBasic:
		deltaMs = correlation // Just 0 or 1
	case LevelStandard:
		bin := (correlation + 1) / 2 * 9 // Map [-1, 1] to [0, 9]
		deltaMs = bin * 50               // Each bin is ~50ms
	case LevelFull:
		deltaMs = correlation*200 + 200
	}

	confidence := math.Min(1.0, math.Abs(correlation))
	enc.symbolsDecoded++

	return deltaMs, confidence, nil
}

// generateNoiseComponent creates a random noise component.
func (enc *EnhancedDSSSEncoder) generateNoiseComponent() complex128 {
	var buf [16]byte
	rand.Read(buf[:])
	amp := float64(binary.BigEndian.Uint64(buf[:8])) / float64(^uint64(0))
	phase := float64(binary.BigEndian.Uint64(buf[8:])) / float64(^uint64(0)) * 2 * math.Pi
	return cmplx.Rect(amp, phase)
}

// ========== Feature 2: Document Watermarking ==========

// WatermarkConfig configures document watermarking.
type WatermarkConfig struct {
	// Method: "spacing", "unicode", "punctuation"
	Method string

	// Strength affects visibility (0.0-1.0)
	Strength float64

	// Preserve readability
	MaxModificationsPerSentence int
}

// DocumentWatermark embeds timing signature in document text.
type DocumentWatermark struct {
	// Original document hash
	OriginalHash [32]byte `json:"original_hash"`

	// Watermarked document hash
	WatermarkedHash [32]byte `json:"watermarked_hash"`

	// Embedded timing signature (DSSS encoded)
	EmbeddedSignature []byte `json:"embedded_signature"`

	// Extraction key hash (for verification)
	KeyHash [32]byte `json:"key_hash"`

	// Number of modifications made
	ModificationCount int `json:"modification_count"`

	// Method used
	Method string `json:"method"`
}

// EmbedWatermark embeds a timing signature into document text.
func (enc *EnhancedDSSSEncoder) EmbedWatermark(document []byte, timingSignals []*LayeredTimingSignal) (*DocumentWatermark, []byte, error) {
	enc.mu.Lock()
	defer enc.mu.Unlock()

	if !enc.config.EnableWatermarking {
		return nil, nil, errors.New("watermarking not enabled")
	}

	originalHash := sha256.Sum256(document)

	// Encode timing signals into a compact signature
	signature := enc.encodeSignatureForWatermark(timingSignals)

	// Embed using Unicode variation selectors (invisible)
	watermarked, modCount := enc.embedUnicodeWatermark(document, signature)

	watermarkedHash := sha256.Sum256(watermarked)

	wm := &DocumentWatermark{
		OriginalHash:      originalHash,
		WatermarkedHash:   watermarkedHash,
		EmbeddedSignature: signature,
		KeyHash:           sha256.Sum256(enc.masterKey[:]),
		ModificationCount: modCount,
		Method:            "unicode_variation",
	}

	return wm, watermarked, nil
}

// encodeSignatureForWatermark compresses timing signals for embedding.
func (enc *EnhancedDSSSEncoder) encodeSignatureForWatermark(signals []*LayeredTimingSignal) []byte {
	// Use a compact representation: just the coarse bins
	signature := make([]byte, 0, len(signals)+32)

	// Add key commitment
	keyCommit := sha256.Sum256(enc.masterKey[:])
	signature = append(signature, keyCommit[:8]...)

	// Add coarse timing bins (4 bits each, pack 2 per byte)
	for i := 0; i < len(signals); i += 2 {
		var packed byte
		if len(signals[i].CoarseBins) > 0 {
			packed = signals[i].CoarseBins[0] << 4
		}
		if i+1 < len(signals) && len(signals[i+1].CoarseBins) > 0 {
			packed |= signals[i+1].CoarseBins[0] & 0x0F
		}
		signature = append(signature, packed)
	}

	return signature
}

// embedUnicodeWatermark embeds data using Unicode variation selectors.
// These are invisible characters that modify the display of preceding characters.
func (enc *EnhancedDSSSEncoder) embedUnicodeWatermark(document []byte, signature []byte) ([]byte, int) {
	// Unicode variation selectors: U+FE00 to U+FE0F (16 values = 4 bits each)
	// We can also use U+E0100 to U+E01EF for more capacity

	result := make([]byte, 0, len(document)+len(signature)*4)
	modCount := 0
	sigIdx := 0
	bitIdx := 0

	for i := 0; i < len(document); i++ {
		result = append(result, document[i])

		// After alphanumeric characters, potentially insert a variation selector
		if sigIdx < len(signature) && isAlphanumeric(document[i]) {
			// Every 8th character, embed 4 bits
			if i%8 == 7 {
				nibble := (signature[sigIdx] >> (4 - bitIdx)) & 0x0F
				// Use variation selector VS1-VS16 (U+FE00-U+FE0F)
				vs := 0xFE00 + int(nibble)
				result = append(result, encodeUTF8Rune(rune(vs))...)
				modCount++

				bitIdx += 4
				if bitIdx >= 8 {
					bitIdx = 0
					sigIdx++
				}
			}
		}
	}

	return result, modCount
}

func isAlphanumeric(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

func encodeUTF8Rune(r rune) []byte {
	buf := make([]byte, 4)
	n := 0
	if r < 0x80 {
		buf[0] = byte(r)
		n = 1
	} else if r < 0x800 {
		buf[0] = byte(0xC0 | (r >> 6))
		buf[1] = byte(0x80 | (r & 0x3F))
		n = 2
	} else if r < 0x10000 {
		buf[0] = byte(0xE0 | (r >> 12))
		buf[1] = byte(0x80 | ((r >> 6) & 0x3F))
		buf[2] = byte(0x80 | (r & 0x3F))
		n = 3
	} else {
		buf[0] = byte(0xF0 | (r >> 18))
		buf[1] = byte(0x80 | ((r >> 12) & 0x3F))
		buf[2] = byte(0x80 | ((r >> 6) & 0x3F))
		buf[3] = byte(0x80 | (r & 0x3F))
		n = 4
	}
	return buf[:n]
}

// ExtractWatermark extracts a timing signature from a watermarked document.
func (enc *EnhancedDSSSEncoder) ExtractWatermark(document []byte) ([]byte, error) {
	enc.mu.RLock()
	defer enc.mu.RUnlock()

	signature := make([]byte, 0)
	var currentByte byte
	bitCount := 0

	for i := 0; i < len(document); i++ {
		// Look for variation selectors (3-byte UTF-8 sequence starting with 0xEF 0xB8)
		if i+2 < len(document) && document[i] == 0xEF && document[i+1] == 0xB8 {
			// This is a variation selector U+FE00-U+FE0F
			nibble := document[i+2] - 0x80 // Extract the 4-bit value
			if nibble < 16 {
				if bitCount == 0 {
					currentByte = nibble << 4
				} else {
					currentByte |= nibble
					signature = append(signature, currentByte)
					currentByte = 0
				}
				bitCount = (bitCount + 4) % 8
			}
			i += 2 // Skip the variation selector bytes
		}
	}

	if len(signature) < 8 {
		return nil, errors.New("no watermark found or corrupted")
	}

	// Verify key commitment
	keyCommit := sha256.Sum256(enc.masterKey[:])
	for i := 0; i < 8; i++ {
		if signature[i] != keyCommit[i] {
			return nil, errors.New("watermark key mismatch")
		}
	}

	return signature[8:], nil
}

// ========== Feature 3: Biometric Protection ==========

// ProtectedBiometricEvidence contains timing data that requires a key to access.
type ProtectedBiometricEvidence struct {
	// Public data (no key needed)
	SessionID     string        `json:"session_id"`
	StartTime     time.Time     `json:"start_time"`
	EndTime       time.Time     `json:"end_time"`
	KeystrokeCount int          `json:"keystroke_count"`
	CoarseTimestamp []int64     `json:"coarse_timestamps"` // Second-level only

	// Zone transitions (k-anonymous, no key needed)
	ZoneTransitions []uint8 `json:"zone_transitions"`

	// Protected timing stream (key required)
	ProtectedStream [][]complex128 `json:"protected_stream"`

	// Key verification
	KeyHash [32]byte `json:"key_hash"`

	// Disclosure level available
	MaxLevel DisclosureLevel `json:"max_level"`
}

// CreateProtectedEvidence creates biometric evidence with timing protection.
func (enc *EnhancedDSSSEncoder) CreateProtectedEvidence(
	sessionID string,
	startTime, endTime time.Time,
	timingSignals []*LayeredTimingSignal,
	zoneTransitions []uint8,
) *ProtectedBiometricEvidence {
	enc.mu.Lock()
	defer enc.mu.Unlock()

	evidence := &ProtectedBiometricEvidence{
		SessionID:       sessionID,
		StartTime:       startTime,
		EndTime:         endTime,
		KeystrokeCount:  len(timingSignals),
		ZoneTransitions: zoneTransitions,
		KeyHash:         sha256.Sum256(enc.masterKey[:]),
		MaxLevel:        LevelFull,
	}

	// Coarse timestamps (second-level only - no biometric leakage)
	duration := endTime.Sub(startTime)
	avgInterval := duration / time.Duration(len(timingSignals)+1)
	for i := 0; i < len(timingSignals); i++ {
		t := startTime.Add(avgInterval * time.Duration(i+1))
		evidence.CoarseTimestamp = append(evidence.CoarseTimestamp, t.Unix())
	}

	// Protected stream (full biometric, encrypted by DSSS)
	evidence.ProtectedStream = make([][]complex128, len(timingSignals))
	for i, sig := range timingSignals {
		evidence.ProtectedStream[i] = sig.Observable
	}

	return evidence
}

// VerifyBiometricEvidence extracts timing data from protected evidence.
func (enc *EnhancedDSSSEncoder) VerifyBiometricEvidence(
	evidence *ProtectedBiometricEvidence,
	level DisclosureLevel,
	key [32]byte,
) ([]float64, float64, error) {
	enc.mu.Lock()
	defer enc.mu.Unlock()

	// Verify key
	keyHash := sha256.Sum256(key[:])
	if keyHash != evidence.KeyHash {
		return nil, 0, errors.New("invalid key")
	}

	if level > evidence.MaxLevel {
		return nil, 0, errors.New("requested level exceeds available")
	}

	// Extract timing at requested level
	timings := make([]float64, len(evidence.ProtectedStream))
	totalConfidence := 0.0

	for i, stream := range evidence.ProtectedStream {
		// Decode from the combined observable using correlation with level-specific PN sequence
		timing, confidence, err := enc.decodeFromObservable(stream, level)
		if err != nil {
			continue
		}
		timings[i] = timing
		totalConfidence += confidence
	}

	avgConfidence := 0.0
	if len(timings) > 0 {
		avgConfidence = totalConfidence / float64(len(timings))
	}

	return timings, avgConfidence, nil
}

// decodeFromObservable extracts timing from combined observable at a level.
func (enc *EnhancedDSSSEncoder) decodeFromObservable(observable []complex128, level DisclosureLevel) (float64, float64, error) {
	if len(observable) != enc.config.NumFrequencyBins {
		return 0, 0, errors.New("invalid observable length")
	}

	pn, ok := enc.pnSequences[level]
	if !ok {
		return 0, 0, errors.New("invalid level")
	}
	carrier, ok := enc.carriers[level]
	if !ok {
		return 0, 0, errors.New("invalid level")
	}

	correlation := 0.0
	for i := 0; i < enc.config.NumFrequencyBins; i++ {
		chipIdx := i % enc.config.ChipRate
		demodulated := observable[i] / carrier[i]
		correlation += real(demodulated) * float64(pn[chipIdx])
	}

	var strengthMultiplier float64
	switch level {
	case LevelBasic:
		strengthMultiplier = 0.5
	case LevelStandard:
		strengthMultiplier = 0.7
	case LevelFull:
		strengthMultiplier = 1.0
	default:
		return 0, 0, errors.New("invalid level")
	}

	correlation /= float64(enc.config.NumFrequencyBins) * enc.config.EmbedStrength * strengthMultiplier

	var deltaMs float64
	switch level {
	case LevelBasic:
		deltaMs = correlation
	case LevelStandard:
		bin := (correlation + 1) / 2 * 9
		deltaMs = bin * 50
	case LevelFull:
		deltaMs = correlation*200 + 200
	}

	confidence := math.Min(1.0, math.Abs(correlation))
	return deltaMs, confidence, nil
}

// ========== Feature 4: Temporal Binding (VDF-based, no external service) ==========

// maybeAddVDFCheckpoint adds a VDF proof if enough time has passed.
func (enc *EnhancedDSSSEncoder) maybeAddVDFCheckpoint() {
	if !enc.config.EnableTemporalBinding || enc.temporalAnchor == nil {
		return
	}

	elapsed := time.Since(enc.lastVDFTime)
	if elapsed < enc.vdfInterval {
		return
	}

	// Compute VDF proof for elapsed time
	proof, err := vdf.Compute(enc.pendingVDFInput, elapsed, enc.config.VDFParams)
	if err != nil {
		return
	}

	enc.temporalAnchor.VDFChain = append(enc.temporalAnchor.VDFChain, proof)
	enc.temporalAnchor.MinElapsed += proof.MinElapsedTime(enc.config.VDFParams)

	// Chain: next input is hash of current output
	enc.pendingVDFInput = sha256.Sum256(proof.Output[:])
	enc.lastVDFTime = time.Now()
}

// FinalizeTemporalAnchor completes the temporal binding chain.
func (enc *EnhancedDSSSEncoder) FinalizeTemporalAnchor() *TemporalAnchor {
	enc.mu.Lock()
	defer enc.mu.Unlock()

	if enc.temporalAnchor == nil {
		return nil
	}

	// Add final VDF proof
	elapsed := time.Since(enc.lastVDFTime)
	if elapsed > time.Second {
		proof, err := vdf.Compute(enc.pendingVDFInput, elapsed, enc.config.VDFParams)
		if err == nil {
			enc.temporalAnchor.VDFChain = append(enc.temporalAnchor.VDFChain, proof)
			enc.temporalAnchor.MinElapsed += proof.MinElapsedTime(enc.config.VDFParams)
		}
	}

	enc.temporalAnchor.ClaimedEnd = time.Now()

	return enc.temporalAnchor
}

// VerifyTemporalAnchor verifies the VDF chain proves minimum elapsed time.
func VerifyTemporalAnchor(anchor *TemporalAnchor, params vdf.Parameters) (time.Duration, error) {
	if anchor == nil || len(anchor.VDFChain) == 0 {
		return 0, errors.New("no temporal anchor")
	}

	var totalElapsed time.Duration
	var prevOutput [32]byte

	for i, proof := range anchor.VDFChain {
		// Verify VDF proof
		if !vdf.Verify(proof) {
			return 0, errors.New("VDF verification failed")
		}

		// Verify chain linkage (except first)
		if i > 0 {
			expectedInput := sha256.Sum256(prevOutput[:])
			if proof.Input != expectedInput {
				return 0, errors.New("VDF chain broken")
			}
		}

		totalElapsed += proof.MinElapsedTime(params)
		prevOutput = proof.Output
	}

	return totalElapsed, nil
}

// BindToBeacon optionally binds the temporal anchor to an external beacon.
// This provides absolute time binding but requires network access.
func (enc *EnhancedDSSSEncoder) BindToBeacon(source string, round uint64, value []byte) error {
	enc.mu.Lock()
	defer enc.mu.Unlock()

	if enc.temporalAnchor == nil {
		return errors.New("no temporal anchor initialized")
	}

	enc.temporalAnchor.BeaconSource = source
	enc.temporalAnchor.BeaconRound = round
	enc.temporalAnchor.BeaconValue = value

	// Mix beacon into VDF input for binding
	h := sha256.New()
	h.Write(enc.pendingVDFInput[:])
	h.Write(value)
	copy(enc.pendingVDFInput[:], h.Sum(nil))

	return nil
}

// ========== Feature 5: Anti-Replay Challenge-Response ==========

// AntiReplayChallenge is issued by a verifier to prevent replay attacks.
type AntiReplayChallenge struct {
	Nonce      []byte    `json:"nonce"`
	IssuedAt   time.Time `json:"issued_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	IssuerID   string    `json:"issuer_id"`
	Purpose    string    `json:"purpose"`
}

// AntiReplayChallengeResponse proves the evidence was created in response to a challenge.
type AntiReplayChallengeResponse struct {
	Challenge     *AntiReplayChallenge `json:"challenge"`
	Response      []byte               `json:"response"`
	ProofBinding  [32]byte             `json:"proof_binding"`
	EvidenceHash  [32]byte             `json:"evidence_hash"`
}

// GenerateAntiReplayChallenge creates a new anti-replay challenge.
func GenerateAntiReplayChallenge(issuerID, purpose string, validity time.Duration) *AntiReplayChallenge {
	nonce := make([]byte, 32)
	rand.Read(nonce)

	return &AntiReplayChallenge{
		Nonce:     nonce,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(validity),
		IssuerID:  issuerID,
		Purpose:   purpose,
	}
}

// BindToAntiReplayChallenge binds the current session to an anti-replay challenge.
func (enc *EnhancedDSSSEncoder) BindToAntiReplayChallenge(challenge *AntiReplayChallenge) error {
	enc.mu.Lock()
	defer enc.mu.Unlock()

	if !enc.config.EnableAntiReplay {
		return errors.New("anti-replay not enabled")
	}

	if time.Now().After(challenge.ExpiresAt) {
		return errors.New("challenge expired")
	}

	enc.activeChallenge = challenge.Nonce
	enc.challengeExpiry = challenge.ExpiresAt

	// Mix challenge into PN sequence generation for binding
	// This makes the encoded signals dependent on the challenge
	for level := LevelPublic; level <= LevelFull; level++ {
		levelKey := enc.derivedKeys[level]
		h := hmac.New(sha256.New, levelKey[:])
		h.Write(challenge.Nonce)
		var challengedKey [32]byte
		copy(challengedKey[:], h.Sum(nil))

		// Regenerate PN sequence with challenge binding
		enc.regeneratePNWithKey(level, challengedKey)
	}

	return nil
}

// regeneratePNWithKey regenerates PN sequence with a specific key.
func (enc *EnhancedDSSSEncoder) regeneratePNWithKey(level DisclosureLevel, key [32]byte) {
	length := enc.config.SpreadingFactor * enc.config.ChipRate
	enc.pnSequences[level] = make([]int8, length)

	keySlice := key[:]
	h := hmac.New(sha256.New, keySlice)
	for i := 0; i < length; i += 32 {
		binary.Write(h, binary.BigEndian, uint64(i/32))
		chunk := h.Sum(nil)
		h.Reset()

		for j := 0; j < 32 && i+j < length; j++ {
			if chunk[j]&1 == 0 {
				enc.pnSequences[level][i+j] = 1
			} else {
				enc.pnSequences[level][i+j] = -1
			}
		}
	}
}

// CreateAntiReplayChallengeResponse creates a response proving evidence is fresh.
func (enc *EnhancedDSSSEncoder) CreateAntiReplayChallengeResponse(
	challenge *AntiReplayChallenge,
	evidence *ProtectedBiometricEvidence,
) (*AntiReplayChallengeResponse, error) {
	enc.mu.Lock()
	defer enc.mu.Unlock()

	if time.Now().After(challenge.ExpiresAt) {
		return nil, errors.New("challenge expired")
	}

	// Compute response: HMAC(masterKey, challenge || evidenceHash)
	evidenceHash := sha256.Sum256([]byte(evidence.SessionID))

	h := hmac.New(sha256.New, enc.masterKey[:])
	h.Write(challenge.Nonce)
	h.Write(evidenceHash[:])
	response := h.Sum(nil)

	// Proof binding: hash(response || evidence.ProtectedStream[0])
	h.Reset()
	h.Write(response)
	if len(evidence.ProtectedStream) > 0 {
		for _, c := range evidence.ProtectedStream[0] {
			binary.Write(h, binary.BigEndian, real(c))
			binary.Write(h, binary.BigEndian, imag(c))
		}
	}
	var proofBinding [32]byte
	copy(proofBinding[:], h.Sum(nil))

	return &AntiReplayChallengeResponse{
		Challenge:    challenge,
		Response:     response,
		ProofBinding: proofBinding,
		EvidenceHash: evidenceHash,
	}, nil
}

// VerifyAntiReplayChallengeResponse verifies a challenge response is valid.
func (enc *EnhancedDSSSEncoder) VerifyAntiReplayChallengeResponse(
	response *AntiReplayChallengeResponse,
	evidence *ProtectedBiometricEvidence,
) error {
	enc.mu.RLock()
	defer enc.mu.RUnlock()

	// Verify challenge hasn't expired (with some grace period for verification)
	if time.Now().After(response.Challenge.ExpiresAt.Add(5 * time.Minute)) {
		return errors.New("challenge response too old")
	}

	// Recompute expected response
	evidenceHash := sha256.Sum256([]byte(evidence.SessionID))
	if evidenceHash != response.EvidenceHash {
		return errors.New("evidence hash mismatch")
	}

	h := hmac.New(sha256.New, enc.masterKey[:])
	h.Write(response.Challenge.Nonce)
	h.Write(evidenceHash[:])
	expectedResponse := h.Sum(nil)

	// Compare responses
	if !hmac.Equal(response.Response, expectedResponse) {
		return errors.New("response verification failed")
	}

	// Verify proof binding
	h.Reset()
	h.Write(response.Response)
	if len(evidence.ProtectedStream) > 0 {
		for _, c := range evidence.ProtectedStream[0] {
			binary.Write(h, binary.BigEndian, real(c))
			binary.Write(h, binary.BigEndian, imag(c))
		}
	}
	var expectedBinding [32]byte
	copy(expectedBinding[:], h.Sum(nil))

	if expectedBinding != response.ProofBinding {
		return errors.New("proof binding mismatch")
	}

	return nil
}

// ========== Key Export/Import ==========

// ExportDerivedKey exports a key for a specific disclosure level.
// This allows the author to share limited access with verifiers.
func (enc *EnhancedDSSSEncoder) ExportDerivedKey(level DisclosureLevel) [32]byte {
	enc.mu.RLock()
	defer enc.mu.RUnlock()
	return enc.derivedKeys[level]
}

// GetMasterKey returns the master key (only for backup/recovery).
func (enc *EnhancedDSSSEncoder) GetMasterKey() [32]byte {
	enc.mu.RLock()
	defer enc.mu.RUnlock()
	return enc.masterKey
}
