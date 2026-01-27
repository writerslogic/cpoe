// China Financial Certification Authority (CFCA) timestamp provider stub.
//
// STATUS: STUB - Not implemented
//
// CFCA is a major certification authority in China that provides timestamp
// services recognized by Chinese courts and government agencies.
//
// Key characteristics:
// - GOVERNMENT AFFILIATED: Under supervision of People's Bank of China
// - LEGALLY BINDING: Recognized for legal proceedings in mainland China
// - SM ALGORITHMS: Uses Chinese national cryptographic standards (SM2/SM3/SM4)
// - CHINESE LANGUAGE: Documentation and interfaces primarily in Chinese
//
// Implementation requirements:
// - CFCA account and API credentials
// - Implementation of SM2/SM3/SM4 cryptographic algorithms
// - Understanding of CFCA's proprietary API format
// - Compliance with Chinese data localization requirements
// - Chinese business entity may be required for account
//
// Cryptographic considerations:
// - SM2: Chinese elliptic curve algorithm (similar to ECDSA)
// - SM3: Chinese hash function (similar to SHA-256)
// - SM4: Chinese block cipher (similar to AES)
// - May require hardware security modules (HSMs) certified in China
//
// Legal context:
// - Electronic Signature Law of the People's Republic of China (2019 revision)
// - Cryptography Law of the People's Republic of China (2020)
// - Required for certain government and financial transactions
//
// References:
// - https://www.cfca.com.cn/ (Chinese)
// - GB/T 32918 (SM2 standard)
// - GB/T 32905 (SM3 standard)
// - GB/T 32907 (SM4 standard)
//
// Interested contributors: Please open an issue to coordinate implementation.

package anchors

import (
	"context"
	"errors"
	"time"
)

// CFCAProvider implements TimestampProvider for CFCA timestamp services.
type CFCAProvider struct {
	// API endpoint
	apiURL string

	// Authentication
	appID     string
	appSecret string

	// SM algorithm implementations would go here
}

// CFCAConfig holds configuration for CFCA provider.
type CFCAConfig struct {
	APIURL    string
	AppID     string
	AppSecret string
}

// NewCFCAProvider creates a new CFCA provider.
func NewCFCAProvider(config CFCAConfig) *CFCAProvider {
	return &CFCAProvider{
		apiURL:    config.APIURL,
		appID:     config.AppID,
		appSecret: config.AppSecret,
	}
}

// Name returns the provider identifier.
func (p *CFCAProvider) Name() string {
	return "cfca"
}

// DisplayName returns a human-readable name.
func (p *CFCAProvider) DisplayName() string {
	return "CFCA (China)"
}

// Type returns the provider category.
func (p *CFCAProvider) Type() ProviderType {
	return TypeGovernment
}

// Regions returns jurisdictions where this provider has legal standing.
func (p *CFCAProvider) Regions() []string {
	return []string{"CN"}
}

// LegalStanding returns the legal recognition level.
func (p *CFCAProvider) LegalStanding() LegalStanding {
	return StandingLegal
}

// Timestamp is not implemented.
func (p *CFCAProvider) Timestamp(ctx context.Context, hash [32]byte) (*Proof, error) {
	return nil, errors.New("cfca: not implemented - requires SM2/SM3/SM4 cryptographic implementation and CFCA account")
}

// Verify is not implemented.
func (p *CFCAProvider) Verify(ctx context.Context, proof *Proof) (*VerifyResult, error) {
	return nil, errors.New("cfca: not implemented - requires SM algorithm verification")
}

// Upgrade is not implemented.
func (p *CFCAProvider) Upgrade(ctx context.Context, proof *Proof) (*Proof, error) {
	return nil, errors.New("cfca: not implemented")
}

// RequiresPayment returns true.
func (p *CFCAProvider) RequiresPayment() bool {
	return true
}

// RequiresNetwork returns true.
func (p *CFCAProvider) RequiresNetwork() bool {
	return true
}

// RequiresCredentials returns true.
func (p *CFCAProvider) RequiresCredentials() bool {
	return true
}

// Configure sets provider configuration.
func (p *CFCAProvider) Configure(config map[string]interface{}) error {
	if url, ok := config["api_url"].(string); ok {
		p.apiURL = url
	}
	if id, ok := config["app_id"].(string); ok {
		p.appID = id
	}
	if secret, ok := config["app_secret"].(string); ok {
		p.appSecret = secret
	}
	return nil
}

// Status returns the provider status.
func (p *CFCAProvider) Status(ctx context.Context) (*ProviderStatus, error) {
	return &ProviderStatus{
		Available:  false,
		Configured: false,
		LastCheck:  time.Now(),
		Message:    "CFCA provider not implemented - contributions welcome",
	}, nil
}

var _ Provider = (*CFCAProvider)(nil)
