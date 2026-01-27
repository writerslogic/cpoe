// Keybase timestamp provider stub.
//
// STATUS: STUB - Not implemented (service discontinued)
//
// Keybase was a decentralized identity and file sharing platform that provided
// cryptographic proofs and timestamping via the Stellar blockchain. Keybase was
// acquired by Zoom in 2020 and the service has been largely discontinued.
//
// This stub is preserved for:
// - Historical reference
// - Verification of existing Keybase proofs
// - Potential future decentralized alternatives
//
// Key characteristics (historical):
// - DECENTRALIZED: Identity proofs across multiple platforms
// - STELLAR ANCHORED: Timestamps anchored to Stellar blockchain
// - FREE: No cost for basic usage
// - IDENTITY FOCUSED: Strong link between timestamps and verified identities
//
// How it worked:
// 1. User had verified Keybase identity (linked to social proofs)
// 2. Data hashes were signed by user's Keybase key
// 3. Signatures were anchored to Stellar blockchain
// 4. Merkle tree of all Keybase operations provided audit trail
//
// Service status:
// - Keybase app still functions but feature-limited
// - New signups no longer available
// - Stellar anchoring discontinued
// - Existing proofs may still be verifiable
//
// Alternatives for decentralized timestamping:
// - OpenTimestamps (Bitcoin-based, implemented in this package)
// - OriginStamp: https://originstamp.com/
// - Chainpoint: https://chainpoint.org/ (deprecated)
// - Decentralized identity protocols (DID, Verifiable Credentials)
//
// Implementation notes:
// - Could implement verification of existing Keybase proofs
// - Would need to parse Keybase signature format
// - Stellar blockchain queries for historical anchors
//
// References:
// - https://keybase.io/ (limited functionality)
// - https://book.keybase.io/docs/server (documentation)
// - Stellar: https://www.stellar.org/
//
// Interested contributors: Please open an issue if you need Keybase proof verification.

package anchors

import (
	"context"
	"errors"
	"time"
)

// KeybaseProvider implements TimestampProvider for Keybase (historical).
type KeybaseProvider struct {
	// For verification of existing proofs only
	verifyOnly bool
}

// KeybaseConfig holds configuration for Keybase provider.
type KeybaseConfig struct {
	// VerifyOnly mode - only verify existing proofs, no new timestamps
	VerifyOnly bool
}

// NewKeybaseProvider creates a new Keybase provider.
func NewKeybaseProvider(config KeybaseConfig) *KeybaseProvider {
	return &KeybaseProvider{
		verifyOnly: true, // Always verify-only since service is discontinued
	}
}

// Name returns the provider identifier.
func (p *KeybaseProvider) Name() string {
	return "keybase"
}

// DisplayName returns a human-readable name.
func (p *KeybaseProvider) DisplayName() string {
	return "Keybase (Discontinued)"
}

// Type returns the provider category.
func (p *KeybaseProvider) Type() ProviderType {
	return TypeDecentralized
}

// Regions returns jurisdictions where this provider has legal standing.
func (p *KeybaseProvider) Regions() []string {
	return []string{"GLOBAL"} // Decentralized, no specific jurisdiction
}

// LegalStanding returns the legal recognition level.
func (p *KeybaseProvider) LegalStanding() LegalStanding {
	return StandingEvidentiary
}

// Timestamp is not available - service discontinued.
func (p *KeybaseProvider) Timestamp(ctx context.Context, hash [32]byte) (*Proof, error) {
	return nil, errors.New("keybase: service discontinued - new timestamps not available")
}

// Verify could potentially verify existing Keybase proofs.
//
// TODO: Implement verification of existing Keybase signature chains
// This would require:
// - Parsing Keybase signature format
// - Verifying signature chain
// - Querying Stellar blockchain for anchor (if still available)
func (p *KeybaseProvider) Verify(ctx context.Context, proof *Proof) (*VerifyResult, error) {
	return nil, errors.New("keybase: proof verification not implemented")
}

// Upgrade is not available.
func (p *KeybaseProvider) Upgrade(ctx context.Context, proof *Proof) (*Proof, error) {
	return nil, errors.New("keybase: service discontinued")
}

// RequiresPayment returns false.
func (p *KeybaseProvider) RequiresPayment() bool {
	return false
}

// RequiresNetwork returns true.
func (p *KeybaseProvider) RequiresNetwork() bool {
	return true
}

// RequiresCredentials returns false.
func (p *KeybaseProvider) RequiresCredentials() bool {
	return false
}

// Configure sets provider configuration.
func (p *KeybaseProvider) Configure(config map[string]interface{}) error {
	return nil
}

// Status returns the provider status.
func (p *KeybaseProvider) Status(ctx context.Context) (*ProviderStatus, error) {
	return &ProviderStatus{
		Available:  false,
		Configured: true,
		LastCheck:  time.Now(),
		Message:    "Keybase timestamping service discontinued (acquired by Zoom 2020)",
	}, nil
}

var _ Provider = (*KeybaseProvider)(nil)
