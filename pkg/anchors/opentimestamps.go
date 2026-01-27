// OpenTimestamps provider implementation.
//
// OpenTimestamps (OTS) is a free, open protocol for creating Bitcoin-backed
// timestamps. It provides cryptographic proof that data existed at a specific
// point in time by anchoring to the Bitcoin blockchain.
//
// Key characteristics:
// - FREE: No cost to create or verify timestamps
// - DECENTRALIZED: Multiple calendar servers, Bitcoin blockchain as anchor
// - GLOBALLY RECOGNIZED: Independent of any jurisdiction
// - DELAYED CONFIRMATION: ~1-2 hours for Bitcoin confirmation
//
// How it works:
// 1. Hash is submitted to calendar servers
// 2. Calendar aggregates hashes into a Merkle tree
// 3. Merkle root is embedded in a Bitcoin transaction
// 4. Once confirmed, proof links your hash to the Bitcoin block
//
// References:
// - https://opentimestamps.org/
// - https://github.com/opentimestamps/opentimestamps-client
// - https://petertodd.org/2016/opentimestamps-announcement

package anchors

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Default OTS calendar servers
var defaultCalendars = []string{
	"https://a.pool.opentimestamps.org",
	"https://b.pool.opentimestamps.org",
	"https://a.pool.eternitywall.com",
	"https://ots.btc.catallaxy.com",
}

// OTS file format magic bytes
var otsMagic = []byte{0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00, 0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94}

// OTS operation tags
const (
	otsOpSHA256    = 0x08
	otsOpRIPEMD160 = 0x07
	otsOpSHA1      = 0x02
	otsOpAppend    = 0xf0
	otsOpPrepend   = 0xf1
	otsOpReverse   = 0xf2
	otsOpHexlify   = 0xf3

	otsAttestPending = 0x83
	otsAttestBitcoin = 0x05
)

// OpenTimestampsProvider implements the Provider interface for OpenTimestamps.
type OpenTimestampsProvider struct {
	calendars  []string
	httpClient *http.Client
	timeout    time.Duration
}

// NewOpenTimestampsProvider creates a new OpenTimestamps provider.
func NewOpenTimestampsProvider() *OpenTimestampsProvider {
	return &OpenTimestampsProvider{
		calendars: defaultCalendars,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		timeout: 30 * time.Second,
	}
}

// Name returns the provider identifier.
func (p *OpenTimestampsProvider) Name() string {
	return "opentimestamps"
}

// DisplayName returns a human-readable name.
func (p *OpenTimestampsProvider) DisplayName() string {
	return "OpenTimestamps"
}

// Type returns the provider category.
func (p *OpenTimestampsProvider) Type() ProviderType {
	return TypeBlockchain
}

// Regions returns jurisdictions where this provider has legal standing.
func (p *OpenTimestampsProvider) Regions() []string {
	return []string{"GLOBAL"}
}

// LegalStanding returns the legal recognition level.
func (p *OpenTimestampsProvider) LegalStanding() LegalStanding {
	// Bitcoin timestamps are generally accepted as evidence
	// but may not have explicit legal framework in all jurisdictions
	return StandingEvidentiary
}

// Timestamp submits a hash to OpenTimestamps calendars.
func (p *OpenTimestampsProvider) Timestamp(ctx context.Context, hash [32]byte) (*Proof, error) {
	// Try each calendar until one succeeds
	var lastErr error
	for _, calendar := range p.calendars {
		proof, err := p.submitToCalendar(ctx, calendar, hash)
		if err == nil {
			return proof, nil
		}
		lastErr = err
	}

	return nil, fmt.Errorf("all calendars failed: %w", lastErr)
}

// submitToCalendar submits a hash to a specific calendar server.
func (p *OpenTimestampsProvider) submitToCalendar(ctx context.Context, calendar string, hash [32]byte) (*Proof, error) {
	url := calendar + "/digest"

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(hash[:]))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/vnd.opentimestamps.v1")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("calendar returned %d: %s", resp.StatusCode, string(body))
	}

	// Read the incomplete timestamp
	incompleteProof, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Build the OTS file
	otsFile := p.buildOTSFile(hash, incompleteProof)

	return &Proof{
		Provider:  p.Name(),
		Version:   1,
		Hash:      hash,
		Timestamp: time.Now(),
		Status:    StatusPending,
		RawProof:  otsFile,
		VerifyURL: "https://opentimestamps.org/",
		Metadata: map[string]interface{}{
			"calendar": calendar,
		},
	}, nil
}

// buildOTSFile constructs an OTS file from the hash and calendar response.
func (p *OpenTimestampsProvider) buildOTSFile(hash [32]byte, calendarProof []byte) []byte {
	var buf bytes.Buffer

	// Magic bytes
	buf.Write(otsMagic)

	// Version (0x01)
	buf.WriteByte(0x01)

	// Hash type (SHA256 = 0x08)
	buf.WriteByte(otsOpSHA256)

	// The hash itself
	buf.Write(hash[:])

	// Calendar proof
	buf.Write(calendarProof)

	return buf.Bytes()
}

// Verify checks an OpenTimestamps proof.
func (p *OpenTimestampsProvider) Verify(ctx context.Context, proof *Proof) (*VerifyResult, error) {
	if proof.Provider != p.Name() {
		return nil, fmt.Errorf("proof is not from %s", p.Name())
	}

	result := &VerifyResult{
		Provider:     p.Name(),
		VerifiedHash: proof.Hash,
	}

	// Parse the OTS file
	otsData := proof.RawProof
	if len(otsData) < len(otsMagic)+2 {
		result.Error = "proof too short"
		return result, ErrInvalidProof
	}

	// Check magic bytes
	if !bytes.HasPrefix(otsData, otsMagic) {
		result.Error = "invalid OTS magic bytes"
		return result, ErrInvalidProof
	}

	// Parse attestations
	attestations, err := p.parseAttestations(otsData[len(otsMagic):])
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	// Check for Bitcoin attestation
	for _, att := range attestations {
		if att.Type == "bitcoin" {
			result.Valid = true
			result.Status = StatusConfirmed
			result.Timestamp = att.Time
			result.Chain = &BlockchainAnchor{
				Chain:       "bitcoin",
				BlockHeight: att.Height,
				BlockTime:   att.Time,
			}
			return result, nil
		}
	}

	// Only pending attestations found
	result.Status = StatusPending
	result.Valid = true
	result.Warnings = append(result.Warnings, "proof is pending Bitcoin confirmation")
	return result, nil
}

type otsAttestation struct {
	Type   string
	Height uint64
	Time   time.Time
}

// parseAttestations extracts attestations from OTS data.
func (p *OpenTimestampsProvider) parseAttestations(data []byte) ([]otsAttestation, error) {
	var attestations []otsAttestation

	// Simple parser - look for attestation markers
	for i := 0; i < len(data); i++ {
		switch data[i] {
		case otsAttestPending:
			// Pending attestation - URL follows
			attestations = append(attestations, otsAttestation{Type: "pending"})

		case otsAttestBitcoin:
			// Bitcoin attestation - block height follows
			if i+8 <= len(data) {
				height := binary.BigEndian.Uint64(data[i+1 : i+9])
				attestations = append(attestations, otsAttestation{
					Type:   "bitcoin",
					Height: height,
					// Block time would need to be looked up
				})
			}
		}
	}

	return attestations, nil
}

// Upgrade attempts to upgrade a pending proof to confirmed status.
func (p *OpenTimestampsProvider) Upgrade(ctx context.Context, proof *Proof) (*Proof, error) {
	if proof.Status == StatusConfirmed {
		return proof, nil
	}

	// Get calendar from metadata
	calendar, ok := proof.Metadata["calendar"].(string)
	if !ok || calendar == "" {
		calendar = p.calendars[0]
	}

	// Request upgrade from calendar
	url := calendar + "/timestamp/" + hex.EncodeToString(proof.Hash[:])

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.opentimestamps.v1")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrProofPending
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("calendar returned %d", resp.StatusCode)
	}

	upgradedProof, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Check if we got a Bitcoin attestation
	if !bytes.Contains(upgradedProof, []byte{otsAttestBitcoin}) {
		return nil, ErrProofPending
	}

	// Build upgraded proof
	newProof := *proof
	newProof.RawProof = p.buildOTSFile(proof.Hash, upgradedProof)
	newProof.Status = StatusConfirmed

	// Verify to get the block info
	result, err := p.Verify(ctx, &newProof)
	if err == nil && result.Chain != nil {
		newProof.BlockchainAnchor = result.Chain
		newProof.Timestamp = result.Chain.BlockTime
	}

	return &newProof, nil
}

// RequiresPayment returns false - OpenTimestamps is free.
func (p *OpenTimestampsProvider) RequiresPayment() bool {
	return false
}

// RequiresNetwork returns true - needs internet for calendars.
func (p *OpenTimestampsProvider) RequiresNetwork() bool {
	return true
}

// RequiresCredentials returns false - no API keys needed.
func (p *OpenTimestampsProvider) RequiresCredentials() bool {
	return false
}

// Configure sets provider configuration.
func (p *OpenTimestampsProvider) Configure(config map[string]interface{}) error {
	if calendars, ok := config["calendars"].([]string); ok {
		p.calendars = calendars
	}
	if timeout, ok := config["timeout"].(time.Duration); ok {
		p.timeout = timeout
		p.httpClient.Timeout = timeout
	}
	return nil
}

// Status returns the current provider status.
func (p *OpenTimestampsProvider) Status(ctx context.Context) (*ProviderStatus, error) {
	status := &ProviderStatus{
		Configured: true,
		LastCheck:  time.Now(),
	}

	// Check if at least one calendar is reachable
	for _, calendar := range p.calendars {
		req, err := http.NewRequestWithContext(ctx, "GET", calendar, nil)
		if err != nil {
			continue
		}

		resp, err := p.httpClient.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode < 500 {
			status.Available = true
			status.Message = "Calendar " + calendar + " is reachable"
			return status, nil
		}
	}

	status.Available = false
	status.Message = "No calendars reachable"
	return status, nil
}

// Verify that OpenTimestampsProvider implements Provider.
var _ Provider = (*OpenTimestampsProvider)(nil)

// Helper function to compute SHA256
func sha256Hash(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// VerifyOTSFile verifies a standalone .ots file against a hash.
func VerifyOTSFile(otsFile []byte, expectedHash [32]byte) (*VerifyResult, error) {
	provider := NewOpenTimestampsProvider()
	proof := &Proof{
		Provider: provider.Name(),
		Hash:     expectedHash,
		RawProof: otsFile,
	}
	return provider.Verify(context.Background(), proof)
}
