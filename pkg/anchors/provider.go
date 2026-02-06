// Package anchors provides pluggable external timestamp anchoring services.
//
// External anchors provide independent, third-party proof that a hash existed
// at a specific point in time. This is crucial for legal standing in many
// jurisdictions where self-asserted timestamps are insufficient.
//
// # Supported Providers
//
// Fully implemented:
//   - OpenTimestamps: Free, Bitcoin-backed, globally recognized
//   - RFC 3161: Generic client for any RFC 3161 compliant TSA
//
// Scaffolded (community contributions welcome):
//   - eIDAS QTSPs: EU Qualified Trust Service Providers
//   - Keybase: Decentralized identity and timestamping
//   - CFCA: China Financial Certification Authority
//   - ICP-Brasil: Brazilian PKI infrastructure
//   - JNSA: Japanese Network Security Association
//   - KISA: Korean Internet Security Agency
//   - CCA: Indian Controller of Certifying Authorities
//   - GOST: Russian cryptographic standards
//   - ZertES: Swiss electronic signatures
//   - ESIGN/UETA: US electronic signature frameworks
//
// # Usage
//
//	registry := anchors.NewRegistry()
//	registry.Enable("opentimestamps", nil)
//
//	proof, err := registry.Timestamp(ctx, hash)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// # Contributing Regional Providers
//
// See EXTENDING.md for guidance on implementing providers for your region.
package anchors

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// Common errors
var (
	ErrNotImplemented    = errors.New("provider not implemented")
	ErrProviderDisabled  = errors.New("provider is disabled")
	ErrNetworkRequired   = errors.New("network access required but unavailable")
	ErrPaymentRequired   = errors.New("provider requires payment credentials")
	ErrInvalidProof      = errors.New("proof is invalid or malformed")
	ErrProofPending      = errors.New("proof is pending confirmation")
	ErrVerificationFailed = errors.New("proof verification failed")
)

// ProviderType categorizes timestamp providers by their trust model.
type ProviderType string

const (
	// TypeBlockchain anchors proofs to a public blockchain (Bitcoin, Ethereum, etc.)
	TypeBlockchain ProviderType = "blockchain"

	// TypeRFC3161 uses standard RFC 3161 timestamp protocol
	TypeRFC3161 ProviderType = "rfc3161"

	// TypeQualified indicates EU eIDAS Qualified Trust Service Provider
	TypeQualified ProviderType = "qualified"

	// TypeGovernment indicates a government-operated or mandated service
	TypeGovernment ProviderType = "government"

	// TypeDecentralized indicates a decentralized/distributed system
	TypeDecentralized ProviderType = "decentralized"
)

// LegalStanding describes the legal recognition level of a provider.
type LegalStanding string

const (
	// StandingNone - no specific legal recognition
	StandingNone LegalStanding = "none"

	// StandingEvidentiary - accepted as evidence in courts
	StandingEvidentiary LegalStanding = "evidentiary"

	// StandingLegal - legally equivalent to traditional timestamps
	StandingLegal LegalStanding = "legal"

	// StandingQualified - highest level (EU eIDAS Qualified)
	StandingQualified LegalStanding = "qualified"
)

// Provider defines the interface for external timestamp services.
//
// Implementations for region-specific providers (CFCA, ICP-Brasil, KISA, etc.)
// are welcome as community contributions. See EXTENDING.md for guidance.
type Provider interface {
	// Name returns a unique identifier for this provider.
	// Examples: "opentimestamps", "rfc3161", "eidas-digicert"
	Name() string

	// DisplayName returns a human-readable name.
	// Examples: "OpenTimestamps", "DigiCert Qualified TSA"
	DisplayName() string

	// Type returns the provider category.
	Type() ProviderType

	// Regions returns jurisdiction codes where this provider has legal standing.
	// Uses ISO 3166-1 alpha-2 codes plus special values:
	//   - "GLOBAL" for worldwide recognition
	//   - "EU" for European Union
	//   - Individual country codes (US, CN, JP, etc.)
	Regions() []string

	// LegalStanding returns the legal recognition level.
	LegalStanding() LegalStanding

	// Timestamp submits a hash and returns a proof.
	// The proof may be in "pending" status for blockchain-based providers.
	Timestamp(ctx context.Context, hash [32]byte) (*Proof, error)

	// Verify checks a proof against the provider.
	Verify(ctx context.Context, proof *Proof) (*VerifyResult, error)

	// Upgrade attempts to upgrade a pending proof to confirmed status.
	// For blockchain providers, this fetches the confirmation.
	// Returns ErrProofPending if still not confirmed.
	Upgrade(ctx context.Context, proof *Proof) (*Proof, error)

	// RequiresPayment indicates if this provider charges fees.
	RequiresPayment() bool

	// RequiresNetwork indicates if this provider needs internet access.
	RequiresNetwork() bool

	// RequiresCredentials indicates if API keys/certificates are needed.
	RequiresCredentials() bool

	// Configure sets provider-specific configuration.
	// Returns an error if required configuration is missing.
	Configure(config map[string]interface{}) error

	// Status returns the current provider status.
	Status(ctx context.Context) (*ProviderStatus, error)
}

// Proof is the provider-agnostic proof structure.
type Proof struct {
	// Provider identifier (e.g., "opentimestamps", "rfc3161")
	Provider string `json:"provider"`

	// Version of the proof format
	Version int `json:"version"`

	// Hash that was timestamped
	Hash [32]byte `json:"hash"`

	// Timestamp according to the provider
	// For pending proofs, this is the submission time
	Timestamp time.Time `json:"timestamp"`

	// Status of the proof
	Status ProofStatus `json:"status"`

	// RawProof contains the provider-specific proof data
	// - OpenTimestamps: .ots file contents
	// - RFC 3161: TimeStampResp ASN.1 DER
	// - EU Trust List validated: RFC 3161 with certificate validation
	RawProof []byte `json:"raw_proof"`

	// VerifyURL is an optional URL for independent verification
	VerifyURL string `json:"verify_url,omitempty"`

	// BlockchainAnchor contains blockchain-specific data (if applicable)
	BlockchainAnchor *BlockchainAnchor `json:"blockchain_anchor,omitempty"`

	// Certificate chain for PKI-based proofs
	CertificateChain [][]byte `json:"certificate_chain,omitempty"`

	// Metadata contains provider-specific additional data
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// ProofStatus indicates the current state of a proof.
type ProofStatus string

const (
	// StatusPending - proof submitted but not yet confirmed
	StatusPending ProofStatus = "pending"

	// StatusConfirmed - proof confirmed and independently verifiable
	StatusConfirmed ProofStatus = "confirmed"

	// StatusFailed - proof submission or verification failed
	StatusFailed ProofStatus = "failed"

	// StatusExpired - proof certificate has expired (RFC 3161)
	StatusExpired ProofStatus = "expired"

	// StatusRevoked - proof certificate has been revoked
	StatusRevoked ProofStatus = "revoked"
)

// BlockchainAnchor contains blockchain-specific anchor data.
type BlockchainAnchor struct {
	// Chain identifier (e.g., "bitcoin", "ethereum")
	Chain string `json:"chain"`

	// BlockHeight where the anchor was confirmed
	BlockHeight uint64 `json:"block_height"`

	// BlockHash of the anchoring block
	BlockHash string `json:"block_hash"`

	// BlockTime is the block's timestamp
	BlockTime time.Time `json:"block_time"`

	// TransactionID containing the anchor (if applicable)
	TransactionID string `json:"transaction_id,omitempty"`

	// MerkleRoot or commitment in the block
	MerkleRoot string `json:"merkle_root,omitempty"`
}

// VerifyResult contains the result of proof verification.
type VerifyResult struct {
	// Valid indicates if the proof is cryptographically valid
	Valid bool `json:"valid"`

	// Timestamp from the verified proof
	Timestamp time.Time `json:"timestamp"`

	// VerifiedHash is the hash that was verified
	VerifiedHash [32]byte `json:"verified_hash"`

	// Provider that issued the proof
	Provider string `json:"provider"`

	// Status of the proof after verification
	Status ProofStatus `json:"status"`

	// Chain is populated for blockchain-based proofs
	Chain *BlockchainAnchor `json:"chain,omitempty"`

	// CertificateInfo for PKI-based proofs
	CertificateInfo *CertificateInfo `json:"certificate_info,omitempty"`

	// Warnings contains non-fatal verification notes
	Warnings []string `json:"warnings,omitempty"`

	// Error message if verification failed
	Error string `json:"error,omitempty"`
}

// CertificateInfo contains information about the signing certificate.
type CertificateInfo struct {
	// Issuer DN
	Issuer string `json:"issuer"`

	// Subject DN
	Subject string `json:"subject"`

	// Serial number
	Serial string `json:"serial"`

	// NotBefore validity start
	NotBefore time.Time `json:"not_before"`

	// NotAfter validity end
	NotAfter time.Time `json:"not_after"`

	// IsQualified indicates EU eIDAS qualified status
	IsQualified bool `json:"is_qualified,omitempty"`

	// PolicyOIDs lists certificate policies
	PolicyOIDs []string `json:"policy_oids,omitempty"`
}

// ProviderStatus contains the current status of a provider.
type ProviderStatus struct {
	// Available indicates if the provider is currently usable
	Available bool `json:"available"`

	// Configured indicates if required configuration is set
	Configured bool `json:"configured"`

	// LastCheck when status was last verified
	LastCheck time.Time `json:"last_check"`

	// Message provides additional status information
	Message string `json:"message,omitempty"`

	// PendingProofs count of proofs awaiting confirmation
	PendingProofs int `json:"pending_proofs,omitempty"`
}

// Encode serializes the proof to JSON.
func (p *Proof) Encode() ([]byte, error) {
	return json.MarshalIndent(p, "", "  ")
}

// DecodeProof deserializes a proof from JSON.
func DecodeProof(data []byte) (*Proof, error) {
	var p Proof
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// IsPending returns true if the proof is awaiting confirmation.
func (p *Proof) IsPending() bool {
	return p.Status == StatusPending
}

// IsConfirmed returns true if the proof is confirmed.
func (p *Proof) IsConfirmed() bool {
	return p.Status == StatusConfirmed
}

// IsBlockchainBacked returns true if this is a blockchain-based proof.
func (p *Proof) IsBlockchainBacked() bool {
	return p.BlockchainAnchor != nil
}
