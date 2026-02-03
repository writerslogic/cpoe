//go:build darwin || linux || windows

// Package input provides drand beacon integration for temporal binding.
//
// drand (https://drand.love) is a distributed randomness beacon operated by
// the League of Entropy. It provides publicly verifiable randomness every 30
// seconds, which can be used to prove that evidence was created after a
// specific point in time.
//
// This integration is OPTIONAL. The system works fully offline using VDF-based
// temporal binding. drand adds absolute time anchoring when network is available.
package input

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// DrandConfig configures the drand beacon client.
type DrandConfig struct {
	// URLs of drand HTTP endpoints (multiple for redundancy)
	// Default: League of Entropy mainnet endpoints
	Endpoints []string

	// ChainHash identifies the drand network
	// Default: League of Entropy mainnet (fastnet)
	ChainHash string

	// Timeout for HTTP requests
	Timeout time.Duration

	// CacheSize: number of recent beacons to cache
	CacheSize int
}

// DefaultDrandConfig returns configuration for League of Entropy mainnet.
func DefaultDrandConfig() DrandConfig {
	return DrandConfig{
		Endpoints: []string{
			"https://api.drand.sh",
			"https://drand.cloudflare.com",
			"https://api2.drand.sh",
			"https://api3.drand.sh",
		},
		// League of Entropy mainnet (fastnet) - 3 second rounds
		ChainHash: "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
		Timeout:   10 * time.Second,
		CacheSize: 100,
	}
}

// QuicknetDrandConfig returns configuration for the quicknet chain (faster).
func QuicknetDrandConfig() DrandConfig {
	return DrandConfig{
		Endpoints: []string{
			"https://api.drand.sh",
			"https://drand.cloudflare.com",
		},
		// Quicknet chain - optimized for speed
		ChainHash: "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c",
		Timeout:   10 * time.Second,
		CacheSize: 100,
	}
}

// DrandBeacon represents a single drand randomness beacon.
type DrandBeacon struct {
	// Round number (increments every period)
	Round uint64 `json:"round"`

	// Randomness is the output of the beacon (32 bytes, hex encoded in JSON)
	Randomness []byte `json:"randomness"`

	// Signature is the BLS signature proving the beacon is authentic
	Signature []byte `json:"signature"`

	// PreviousSignature for chained randomness (optional in unchained mode)
	PreviousSignature []byte `json:"previous_signature,omitempty"`

	// Genesis time and period for computing expected times
	GenesisTime int64         `json:"-"`
	Period      time.Duration `json:"-"`
}

// drandJSONBeacon is the JSON representation from the API.
type drandJSONBeacon struct {
	Round             uint64 `json:"round"`
	Randomness        string `json:"randomness"`
	Signature         string `json:"signature"`
	PreviousSignature string `json:"previous_signature,omitempty"`
}

// drandChainInfo contains network metadata.
type drandChainInfo struct {
	PublicKey   string `json:"public_key"`
	Period      int    `json:"period"`
	GenesisTime int64  `json:"genesis_time"`
	Hash        string `json:"hash"`
	SchemeID    string `json:"schemeID"`
}

// ExpectedTime returns the time this beacon should have been produced.
func (b *DrandBeacon) ExpectedTime() time.Time {
	if b.GenesisTime == 0 || b.Period == 0 {
		return time.Time{}
	}
	return time.Unix(b.GenesisTime, 0).Add(time.Duration(b.Round) * b.Period)
}

// DrandClient fetches randomness from the drand network.
type DrandClient struct {
	mu sync.RWMutex

	config    DrandConfig
	client    *http.Client
	chainInfo *drandChainInfo

	// Cache of recent beacons
	cache     map[uint64]*DrandBeacon
	cacheList []uint64 // For LRU eviction

	// Last successful fetch
	lastBeacon *DrandBeacon
	lastFetch  time.Time
}

// NewDrandClient creates a new drand client.
func NewDrandClient(config DrandConfig) *DrandClient {
	return &DrandClient{
		config: config,
		client: &http.Client{
			Timeout: config.Timeout,
		},
		cache: make(map[uint64]*DrandBeacon),
	}
}

// Initialize fetches chain info and validates connectivity.
func (dc *DrandClient) Initialize(ctx context.Context) error {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	// Try each endpoint until one works
	var lastErr error
	for _, endpoint := range dc.config.Endpoints {
		info, err := dc.fetchChainInfo(ctx, endpoint)
		if err != nil {
			lastErr = err
			continue
		}

		// Verify chain hash matches
		if info.Hash != dc.config.ChainHash {
			lastErr = fmt.Errorf("chain hash mismatch: got %s, want %s", info.Hash, dc.config.ChainHash)
			continue
		}

		dc.chainInfo = info
		return nil
	}

	return fmt.Errorf("failed to connect to any drand endpoint: %w", lastErr)
}

// fetchChainInfo retrieves chain metadata from an endpoint.
func (dc *DrandClient) fetchChainInfo(ctx context.Context, endpoint string) (*drandChainInfo, error) {
	url := fmt.Sprintf("%s/%s/info", endpoint, dc.config.ChainHash)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := dc.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var info drandChainInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, err
	}

	return &info, nil
}

// GetLatest fetches the most recent beacon.
func (dc *DrandClient) GetLatest(ctx context.Context) (*DrandBeacon, error) {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	// Check cache freshness (beacons are produced every period)
	if dc.lastBeacon != nil && dc.chainInfo != nil {
		expectedRound := dc.currentRound()
		if dc.lastBeacon.Round >= expectedRound {
			return dc.lastBeacon, nil
		}
	}

	// Fetch latest
	beacon, err := dc.fetchBeacon(ctx, 0) // 0 = latest
	if err != nil {
		return nil, err
	}

	dc.cacheBeacon(beacon)
	dc.lastBeacon = beacon
	dc.lastFetch = time.Now()

	return beacon, nil
}

// GetRound fetches a specific round's beacon.
func (dc *DrandClient) GetRound(ctx context.Context, round uint64) (*DrandBeacon, error) {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	// Check cache
	if beacon, ok := dc.cache[round]; ok {
		return beacon, nil
	}

	// Fetch specific round
	beacon, err := dc.fetchBeacon(ctx, round)
	if err != nil {
		return nil, err
	}

	dc.cacheBeacon(beacon)
	return beacon, nil
}

// currentRound calculates the expected current round number.
func (dc *DrandClient) currentRound() uint64 {
	if dc.chainInfo == nil {
		return 0
	}
	elapsed := time.Since(time.Unix(dc.chainInfo.GenesisTime, 0))
	periodDuration := time.Duration(dc.chainInfo.Period) * time.Second
	return uint64(elapsed / periodDuration)
}

// fetchBeacon retrieves a beacon from the network.
func (dc *DrandClient) fetchBeacon(ctx context.Context, round uint64) (*DrandBeacon, error) {
	var lastErr error

	for _, endpoint := range dc.config.Endpoints {
		var url string
		if round == 0 {
			url = fmt.Sprintf("%s/%s/public/latest", endpoint, dc.config.ChainHash)
		} else {
			url = fmt.Sprintf("%s/%s/public/%d", endpoint, dc.config.ChainHash, round)
		}

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			lastErr = err
			continue
		}

		resp, err := dc.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
			continue
		}

		var jb drandJSONBeacon
		if err := json.Unmarshal(body, &jb); err != nil {
			lastErr = err
			continue
		}

		// Decode hex fields
		randomness, err := hex.DecodeString(jb.Randomness)
		if err != nil {
			lastErr = err
			continue
		}

		signature, err := hex.DecodeString(jb.Signature)
		if err != nil {
			lastErr = err
			continue
		}

		beacon := &DrandBeacon{
			Round:      jb.Round,
			Randomness: randomness,
			Signature:  signature,
		}

		if jb.PreviousSignature != "" {
			beacon.PreviousSignature, _ = hex.DecodeString(jb.PreviousSignature)
		}

		if dc.chainInfo != nil {
			beacon.GenesisTime = dc.chainInfo.GenesisTime
			beacon.Period = time.Duration(dc.chainInfo.Period) * time.Second
		}

		return beacon, nil
	}

	return nil, fmt.Errorf("failed to fetch beacon from any endpoint: %w", lastErr)
}

// cacheBeacon adds a beacon to the cache with LRU eviction.
func (dc *DrandClient) cacheBeacon(beacon *DrandBeacon) {
	if _, exists := dc.cache[beacon.Round]; exists {
		return
	}

	dc.cache[beacon.Round] = beacon
	dc.cacheList = append(dc.cacheList, beacon.Round)

	// Evict oldest if over capacity
	for len(dc.cacheList) > dc.config.CacheSize {
		oldest := dc.cacheList[0]
		dc.cacheList = dc.cacheList[1:]
		delete(dc.cache, oldest)
	}
}

// ========== Integration with Enhanced DSSS ==========

// BeaconBinding represents a binding to a drand beacon.
type BeaconBinding struct {
	// Source identifies the beacon network
	Source string `json:"source"`

	// ChainHash of the drand network
	ChainHash string `json:"chain_hash"`

	// Round number
	Round uint64 `json:"round"`

	// Randomness value (32 bytes)
	Randomness []byte `json:"randomness"`

	// Signature for verification
	Signature []byte `json:"signature"`

	// ExpectedTime when this beacon was produced
	ExpectedTime time.Time `json:"expected_time"`

	// Binding commitment: hash(masterKey || randomness)
	BindingCommitment [32]byte `json:"binding_commitment"`
}

// BindToDrandBeacon creates a binding between the DSSS session and a drand beacon.
func (enc *EnhancedDSSSEncoder) BindToDrandBeacon(beacon *DrandBeacon, chainHash string) (*BeaconBinding, error) {
	enc.mu.Lock()
	defer enc.mu.Unlock()

	if beacon == nil || len(beacon.Randomness) == 0 {
		return nil, errors.New("invalid beacon")
	}

	// Create binding commitment
	h := sha256.New()
	h.Write(enc.masterKey[:])
	h.Write(beacon.Randomness)
	var commitment [32]byte
	copy(commitment[:], h.Sum(nil))

	binding := &BeaconBinding{
		Source:            "drand",
		ChainHash:         chainHash,
		Round:             beacon.Round,
		Randomness:        beacon.Randomness,
		Signature:         beacon.Signature,
		ExpectedTime:      beacon.ExpectedTime(),
		BindingCommitment: commitment,
	}

	// Also bind to the temporal anchor
	if enc.temporalAnchor != nil {
		enc.temporalAnchor.BeaconSource = "drand"
		enc.temporalAnchor.BeaconRound = beacon.Round
		enc.temporalAnchor.BeaconValue = beacon.Randomness
	}

	// Mix beacon into VDF input
	h.Reset()
	h.Write(enc.pendingVDFInput[:])
	h.Write(beacon.Randomness)
	copy(enc.pendingVDFInput[:], h.Sum(nil))

	return binding, nil
}

// VerifyBeaconBinding verifies a beacon binding is valid.
func VerifyBeaconBinding(binding *BeaconBinding, masterKey [32]byte) error {
	if binding == nil {
		return errors.New("nil binding")
	}

	// Verify commitment
	h := sha256.New()
	h.Write(masterKey[:])
	h.Write(binding.Randomness)
	var expectedCommitment [32]byte
	copy(expectedCommitment[:], h.Sum(nil))

	if expectedCommitment != binding.BindingCommitment {
		return errors.New("binding commitment mismatch")
	}

	// Note: Full BLS signature verification requires the drand public key
	// which can be fetched from chain info. For simplicity, we trust the
	// randomness value here. Production systems should verify the signature.

	return nil
}

// ========== Alternative Beacon Sources ==========

// LocalEntropyBeacon creates a beacon from local entropy sources.
// This is a fallback when no network beacons are available.
// It provides no absolute time proof but does provide unpredictability.
type LocalEntropyBeacon struct {
	// Timestamp when entropy was collected
	Timestamp time.Time `json:"timestamp"`

	// Sources of entropy used
	Sources []string `json:"sources"`

	// Combined entropy value
	Entropy []byte `json:"entropy"`

	// Hash of entropy (for binding)
	EntropyHash [32]byte `json:"entropy_hash"`
}

// CollectLocalEntropy gathers entropy from available local sources.
func CollectLocalEntropy() (*LocalEntropyBeacon, error) {
	var sources []string
	h := sha256.New()

	// Source 1: Cryptographic random
	var cryptoRand [32]byte
	if _, err := io.ReadFull(cryptoRandomReader{}, cryptoRand[:]); err == nil {
		h.Write(cryptoRand[:])
		sources = append(sources, "crypto/rand")
	}

	// Source 2: High-resolution time
	h.Write([]byte(time.Now().Format(time.RFC3339Nano)))
	sources = append(sources, "time.Now")

	// Source 3: Process-specific entropy
	var procEntropy [8]byte
	binary.BigEndian.PutUint64(procEntropy[:], uint64(time.Now().UnixNano()))
	h.Write(procEntropy[:])
	sources = append(sources, "process")

	entropy := h.Sum(nil)
	entropyHash := sha256.Sum256(entropy)

	return &LocalEntropyBeacon{
		Timestamp:   time.Now(),
		Sources:     sources,
		Entropy:     entropy,
		EntropyHash: entropyHash,
	}, nil
}

// cryptoRandomReader wraps crypto/rand for io.Reader interface.
type cryptoRandomReader struct{}

func (cryptoRandomReader) Read(b []byte) (int, error) {
	return io.ReadFull(cryptoRandReader, b)
}

// cryptoRandReader is the actual crypto/rand source.
var cryptoRandReader io.Reader

func init() {
	// Use crypto/rand as the source
	cryptoRandReader = cryptoRandReaderImpl{}
}

type cryptoRandReaderImpl struct{}

func (cryptoRandReaderImpl) Read(b []byte) (int, error) {
	return rand.Read(b)
}

// BindToLocalEntropy binds the DSSS session to local entropy.
func (enc *EnhancedDSSSEncoder) BindToLocalEntropy(entropy *LocalEntropyBeacon) error {
	enc.mu.Lock()
	defer enc.mu.Unlock()

	if entropy == nil || len(entropy.Entropy) == 0 {
		return errors.New("invalid entropy")
	}

	// Bind to temporal anchor
	if enc.temporalAnchor != nil {
		enc.temporalAnchor.BeaconSource = "local"
		enc.temporalAnchor.BeaconRound = uint64(entropy.Timestamp.Unix())
		enc.temporalAnchor.BeaconValue = entropy.Entropy
	}

	// Mix into VDF input
	h := sha256.New()
	h.Write(enc.pendingVDFInput[:])
	h.Write(entropy.Entropy)
	copy(enc.pendingVDFInput[:], h.Sum(nil))

	return nil
}
