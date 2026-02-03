//go:build darwin || linux || windows

// Package input provides spread-spectrum steganography for keystroke timing verification.
//
// Spread-spectrum steganography spreads a narrow-band signal across a much wider
// frequency band using a pseudo-noise (PN) sequence. The result appears as
// low-level noise distributed uniformly across all frequencies, making it
// undetectable without knowledge of the spreading code.
//
// For keystroke verification, we spread timing delta information across multiple
// "frequency bins" in the time-frequency domain. An adversary observing the
// system cannot identify which components carry real timing information.
package input

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"math/cmplx"
	"sync"
)

// SpreadSpectrumConfig configures the spread-spectrum encoder.
type SpreadSpectrumConfig struct {
	// SpreadingFactor determines how much the signal is spread.
	// Higher values = more resilient to interference but lower capacity.
	// Typical values: 8, 16, 32, 64
	SpreadingFactor int

	// ChipRate is the number of chips per symbol.
	// Should match SpreadingFactor for direct-sequence spread spectrum.
	ChipRate int

	// NumFrequencyBins is the number of frequency bins for embedding.
	// More bins = better concealment but more computation.
	NumFrequencyBins int

	// EmbedStrength controls signal amplitude (0.0-1.0).
	// Lower = more stealthy but harder to extract.
	EmbedStrength float64
}

// DefaultSpreadSpectrumConfig returns sensible defaults.
func DefaultSpreadSpectrumConfig() SpreadSpectrumConfig {
	return SpreadSpectrumConfig{
		SpreadingFactor:  32,
		ChipRate:         32,
		NumFrequencyBins: 64,
		EmbedStrength:    0.1, // 10% of noise floor
	}
}

// SpreadSpectrumEncoder implements direct-sequence spread-spectrum (DSSS) steganography.
//
// Architecture:
// 1. Input signal (keystroke timing deltas) is converted to symbols
// 2. Each symbol is spread by XOR with a PN sequence (spreading)
// 3. Spread signal is modulated onto carrier (frequency domain embedding)
// 4. Result appears as wideband noise
//
// Extraction (despreading):
// 1. Correlate received signal with known PN sequence
// 2. PN sequence acts as matched filter, recovering original signal
// 3. Without PN sequence, correlation yields noise
type SpreadSpectrumEncoder struct {
	mu sync.RWMutex

	config SpreadSpectrumConfig

	// Secret key for PN sequence generation
	secretKey [32]byte

	// PN sequence (pseudo-noise spreading code)
	pnSequence []int8 // +1 or -1 values

	// Frequency domain carrier
	carrier []complex128

	// Embedded data buffer
	embedBuffer []float64

	// Statistics
	symbolsEncoded   int
	symbolsDecoded   int
	correlationPeaks []float64
}

// NewSpreadSpectrumEncoder creates a spread-spectrum encoder with the given config.
func NewSpreadSpectrumEncoder(config SpreadSpectrumConfig) *SpreadSpectrumEncoder {
	sse := &SpreadSpectrumEncoder{
		config:      config,
		embedBuffer: make([]float64, config.NumFrequencyBins),
		carrier:     make([]complex128, config.NumFrequencyBins),
	}

	// Generate secret key
	rand.Read(sse.secretKey[:])

	// Generate PN sequence from key
	sse.generatePNSequence()

	// Initialize carrier with random phase
	sse.initializeCarrier()

	return sse
}

// NewSpreadSpectrumEncoderWithKey creates an encoder with a specific key (for verification).
func NewSpreadSpectrumEncoderWithKey(config SpreadSpectrumConfig, key [32]byte) *SpreadSpectrumEncoder {
	sse := &SpreadSpectrumEncoder{
		config:      config,
		secretKey:   key,
		embedBuffer: make([]float64, config.NumFrequencyBins),
		carrier:     make([]complex128, config.NumFrequencyBins),
	}

	sse.generatePNSequence()
	sse.initializeCarrier()

	return sse
}

// generatePNSequence creates the pseudo-noise spreading sequence.
// Uses a Gold code generator for good cross-correlation properties.
func (sse *SpreadSpectrumEncoder) generatePNSequence() {
	length := sse.config.SpreadingFactor * sse.config.ChipRate
	sse.pnSequence = make([]int8, length)

	// Generate PN sequence using HMAC-based DRBG
	h := hmac.New(sha256.New, sse.secretKey[:])

	for i := 0; i < length; i += 32 {
		// Generate 32 bytes at a time
		binary.Write(h, binary.BigEndian, uint64(i/32))
		chunk := h.Sum(nil)
		h.Reset()

		for j := 0; j < 32 && i+j < length; j++ {
			// Convert byte to +1 or -1
			if chunk[j]&1 == 0 {
				sse.pnSequence[i+j] = 1
			} else {
				sse.pnSequence[i+j] = -1
			}
		}
	}
}

// initializeCarrier sets up the frequency domain carrier.
func (sse *SpreadSpectrumEncoder) initializeCarrier() {
	h := hmac.New(sha256.New, sse.secretKey[:])
	h.Write([]byte("carrier-phase"))

	for i := 0; i < sse.config.NumFrequencyBins; i++ {
		binary.Write(h, binary.BigEndian, uint64(i))
		hash := h.Sum(nil)
		h.Reset()

		// Random phase for each frequency bin
		phase := float64(binary.BigEndian.Uint64(hash[:8])) / float64(^uint64(0)) * 2 * math.Pi
		sse.carrier[i] = cmplx.Rect(1.0, phase)
	}
}

// SpreadSymbol spreads a single data symbol across multiple chips.
// Returns the spread signal ready for embedding.
func (sse *SpreadSpectrumEncoder) SpreadSymbol(symbol float64) []float64 {
	sse.mu.Lock()
	defer sse.mu.Unlock()

	spread := make([]float64, sse.config.ChipRate)

	// Direct-sequence spreading: multiply symbol by PN sequence
	for i := 0; i < sse.config.ChipRate; i++ {
		spread[i] = symbol * float64(sse.pnSequence[i%len(sse.pnSequence)])
	}

	sse.symbolsEncoded++
	return spread
}

// EncodeTimingDelta encodes a keystroke timing delta using spread-spectrum.
// The timing delta is normalized and spread across frequency bins.
func (sse *SpreadSpectrumEncoder) EncodeTimingDelta(deltaMs float64) *SpreadSignal {
	sse.mu.Lock()
	defer sse.mu.Unlock()

	// Normalize timing delta to [-1, 1] range
	// Typical keystroke deltas are 50-500ms
	normalizedDelta := (deltaMs - 200) / 200 // Center around 200ms
	if normalizedDelta > 1 {
		normalizedDelta = 1
	}
	if normalizedDelta < -1 {
		normalizedDelta = -1
	}

	// Create spread signal
	signal := &SpreadSignal{
		OriginalValue:  deltaMs,
		NormalizedValue: normalizedDelta,
		FrequencyBins:  make([]complex128, sse.config.NumFrequencyBins),
		Chips:          make([]float64, sse.config.ChipRate),
	}

	// Spread the normalized value
	for i := 0; i < sse.config.ChipRate; i++ {
		signal.Chips[i] = normalizedDelta * float64(sse.pnSequence[i])
	}

	// Embed into frequency domain
	for i := 0; i < sse.config.NumFrequencyBins; i++ {
		// Select which chips contribute to this bin
		chipIndex := i % sse.config.ChipRate
		amplitude := signal.Chips[chipIndex] * sse.config.EmbedStrength

		// Modulate onto carrier
		signal.FrequencyBins[i] = sse.carrier[i] * complex(amplitude, 0)
	}

	// Add noise floor to mask the signal
	signal.NoiseFloor = sse.generateNoiseFloor()

	sse.symbolsEncoded++
	return signal
}

// generateNoiseFloor creates random noise that masks the embedded signal.
func (sse *SpreadSpectrumEncoder) generateNoiseFloor() []complex128 {
	noise := make([]complex128, sse.config.NumFrequencyBins)

	var randomBytes [16]byte
	rand.Read(randomBytes[:])

	h := hmac.New(sha256.New, randomBytes[:])

	for i := 0; i < sse.config.NumFrequencyBins; i++ {
		binary.Write(h, binary.BigEndian, uint64(i))
		hash := h.Sum(nil)
		h.Reset()

		// Random amplitude and phase
		amp := float64(binary.BigEndian.Uint64(hash[:8])) / float64(^uint64(0))
		phase := float64(binary.BigEndian.Uint64(hash[8:16])) / float64(^uint64(0)) * 2 * math.Pi

		noise[i] = cmplx.Rect(amp, phase)
	}

	return noise
}

// SpreadSignal represents a spread-spectrum encoded signal.
type SpreadSignal struct {
	OriginalValue   float64      // Original timing delta (ms)
	NormalizedValue float64      // Normalized to [-1, 1]
	Chips           []float64    // Spread chips
	FrequencyBins   []complex128 // Frequency domain representation
	NoiseFloor      []complex128 // Added noise for concealment
}

// GetCombinedSignal returns the signal plus noise floor (what an observer sees).
func (ss *SpreadSignal) GetCombinedSignal() []complex128 {
	combined := make([]complex128, len(ss.FrequencyBins))
	for i := range combined {
		combined[i] = ss.FrequencyBins[i] + ss.NoiseFloor[i]
	}
	return combined
}

// DecodeTimingDelta extracts a timing delta from a spread-spectrum signal.
// Requires the same secret key used for encoding.
func (sse *SpreadSpectrumEncoder) DecodeTimingDelta(signal *SpreadSignal) (float64, float64) {
	sse.mu.Lock()
	defer sse.mu.Unlock()

	// Despread by correlating with PN sequence
	correlation := 0.0

	for i := 0; i < sse.config.NumFrequencyBins; i++ {
		chipIndex := i % sse.config.ChipRate

		// Demodulate from carrier
		demodulated := signal.FrequencyBins[i] / sse.carrier[i]

		// Correlate with PN sequence
		correlation += real(demodulated) * float64(sse.pnSequence[chipIndex])
	}

	// Normalize correlation
	correlation /= float64(sse.config.NumFrequencyBins) * sse.config.EmbedStrength

	// Denormalize back to timing delta
	deltaMs := correlation*200 + 200

	// Compute correlation strength (confidence)
	confidence := math.Abs(correlation)
	if confidence > 1 {
		confidence = 1
	}

	sse.correlationPeaks = append(sse.correlationPeaks, confidence)
	sse.symbolsDecoded++

	return deltaMs, confidence
}

// DecodeFromCombined decodes from a combined signal (signal + noise).
// This is what an adversary would have to work with.
func (sse *SpreadSpectrumEncoder) DecodeFromCombined(combined []complex128) (float64, float64) {
	sse.mu.Lock()
	defer sse.mu.Unlock()

	if len(combined) != sse.config.NumFrequencyBins {
		return 0, 0
	}

	// Despread using correlation
	correlation := 0.0
	noiseEstimate := 0.0

	for i := 0; i < sse.config.NumFrequencyBins; i++ {
		chipIndex := i % sse.config.ChipRate

		// Demodulate from carrier
		demodulated := combined[i] / sse.carrier[i]

		// Correlate with PN sequence (this is the matched filter)
		correlation += real(demodulated) * float64(sse.pnSequence[chipIndex])

		// Estimate noise (orthogonal correlation)
		noiseEstimate += math.Abs(imag(demodulated))
	}

	// Normalize
	correlation /= float64(sse.config.NumFrequencyBins) * sse.config.EmbedStrength
	noiseEstimate /= float64(sse.config.NumFrequencyBins)

	// Denormalize to timing delta
	deltaMs := correlation*200 + 200

	// Signal-to-noise ratio as confidence
	signalPower := math.Abs(correlation)
	if noiseEstimate > 0 {
		snr := signalPower / noiseEstimate
		confidence := math.Min(1.0, snr/10.0) // SNR of 10 = confidence 1.0
		return deltaMs, confidence
	}

	return deltaMs, signalPower
}

// SpreadSpectrumSession manages spread-spectrum encoding for a verification session.
type SpreadSpectrumSession struct {
	mu sync.RWMutex

	encoder *SpreadSpectrumEncoder

	// Encoded timing deltas
	encodedSignals []*SpreadSignal

	// Session statistics
	totalDeltas     int
	avgCorrelation  float64
	peakCorrelation float64
}

// NewSpreadSpectrumSession creates a new spread-spectrum session.
func NewSpreadSpectrumSession() *SpreadSpectrumSession {
	return &SpreadSpectrumSession{
		encoder:        NewSpreadSpectrumEncoder(DefaultSpreadSpectrumConfig()),
		encodedSignals: make([]*SpreadSignal, 0, 1000),
	}
}

// RecordTimingDelta encodes and stores a timing delta.
func (sss *SpreadSpectrumSession) RecordTimingDelta(deltaMs float64) {
	sss.mu.Lock()
	defer sss.mu.Unlock()

	signal := sss.encoder.EncodeTimingDelta(deltaMs)
	sss.encodedSignals = append(sss.encodedSignals, signal)
	sss.totalDeltas++

	// Limit buffer
	if len(sss.encodedSignals) > 10000 {
		sss.encodedSignals = sss.encodedSignals[5000:]
	}
}

// GetObservableStream returns what an adversary would see (signal + noise).
func (sss *SpreadSpectrumSession) GetObservableStream() [][]complex128 {
	sss.mu.RLock()
	defer sss.mu.RUnlock()

	stream := make([][]complex128, len(sss.encodedSignals))
	for i, signal := range sss.encodedSignals {
		stream[i] = signal.GetCombinedSignal()
	}
	return stream
}

// ExtractTimingDeltas recovers original timing deltas from the encoded signals.
// Only works with knowledge of the secret key.
func (sss *SpreadSpectrumSession) ExtractTimingDeltas() []TimingExtraction {
	sss.mu.RLock()
	defer sss.mu.RUnlock()

	results := make([]TimingExtraction, len(sss.encodedSignals))
	totalCorrelation := 0.0

	for i, signal := range sss.encodedSignals {
		deltaMs, confidence := sss.encoder.DecodeTimingDelta(signal)
		results[i] = TimingExtraction{
			Index:       i,
			ExtractedMs: deltaMs,
			OriginalMs:  signal.OriginalValue,
			Confidence:  confidence,
			Error:       math.Abs(deltaMs - signal.OriginalValue),
		}
		totalCorrelation += confidence

		if confidence > sss.peakCorrelation {
			sss.peakCorrelation = confidence
		}
	}

	if len(results) > 0 {
		sss.avgCorrelation = totalCorrelation / float64(len(results))
	}

	return results
}

// TimingExtraction holds the result of extracting a timing delta.
type TimingExtraction struct {
	Index       int     // Position in stream
	ExtractedMs float64 // Recovered timing delta
	OriginalMs  float64 // Original timing delta (for verification)
	Confidence  float64 // Extraction confidence (correlation strength)
	Error       float64 // Absolute error (ms)
}

// GetSecretKey returns the session's secret key (for trusted verification).
func (sss *SpreadSpectrumSession) GetSecretKey() [32]byte {
	sss.mu.RLock()
	defer sss.mu.RUnlock()
	return sss.encoder.secretKey
}

// SpreadSpectrumEvidence is the evidence package for spread-spectrum verification.
type SpreadSpectrumEvidence struct {
	// Combined observable stream (what adversary sees)
	ObservableStream [][]complex128 `json:"observable_stream"`

	// Number of timing deltas encoded
	NumDeltas int `json:"num_deltas"`

	// Configuration used
	Config SpreadSpectrumConfig `json:"config"`

	// Session statistics
	AvgCorrelation  float64 `json:"avg_correlation"`
	PeakCorrelation float64 `json:"peak_correlation"`

	// Key hash (for verifier to confirm they have correct key)
	KeyHash [32]byte `json:"key_hash"`
}

// Export creates evidence from the session.
func (sss *SpreadSpectrumSession) Export() *SpreadSpectrumEvidence {
	sss.mu.RLock()
	defer sss.mu.RUnlock()

	evidence := &SpreadSpectrumEvidence{
		ObservableStream: sss.GetObservableStream(),
		NumDeltas:        sss.totalDeltas,
		Config:           sss.encoder.config,
		AvgCorrelation:   sss.avgCorrelation,
		PeakCorrelation:  sss.peakCorrelation,
	}

	// Hash of key (not the key itself)
	evidence.KeyHash = sha256.Sum256(sss.encoder.secretKey[:])

	return evidence
}

// VerifyWithKey attempts to extract timing deltas using a provided key.
// Returns true if extraction succeeds with good correlation.
func (evidence *SpreadSpectrumEvidence) VerifyWithKey(key [32]byte) ([]TimingExtraction, bool) {
	// Verify key hash matches
	keyHash := sha256.Sum256(key[:])
	if keyHash != evidence.KeyHash {
		return nil, false
	}

	// Create decoder with the key
	decoder := NewSpreadSpectrumEncoderWithKey(evidence.Config, key)

	// Attempt to decode
	results := make([]TimingExtraction, len(evidence.ObservableStream))
	totalConfidence := 0.0

	for i, combined := range evidence.ObservableStream {
		deltaMs, confidence := decoder.DecodeFromCombined(combined)
		results[i] = TimingExtraction{
			Index:       i,
			ExtractedMs: deltaMs,
			Confidence:  confidence,
		}
		totalConfidence += confidence
	}

	// Check if overall extraction was successful
	avgConfidence := 0.0
	if len(results) > 0 {
		avgConfidence = totalConfidence / float64(len(results))
	}

	// Require minimum 50% average confidence
	return results, avgConfidence >= 0.5
}

// AttackResistanceTest simulates an adversary trying to extract without the key.
// Returns the correlation they would achieve (should be ~0 for random).
func (sss *SpreadSpectrumSession) AttackResistanceTest() float64 {
	sss.mu.RLock()
	defer sss.mu.RUnlock()

	// Create attacker with wrong key
	var wrongKey [32]byte
	rand.Read(wrongKey[:])
	attacker := NewSpreadSpectrumEncoderWithKey(sss.encoder.config, wrongKey)

	// Try to decode with wrong key
	totalCorrelation := 0.0
	for _, signal := range sss.encodedSignals {
		combined := signal.GetCombinedSignal()
		_, confidence := attacker.DecodeFromCombined(combined)
		totalCorrelation += confidence
	}

	if len(sss.encodedSignals) == 0 {
		return 0
	}

	return totalCorrelation / float64(len(sss.encodedSignals))
}
