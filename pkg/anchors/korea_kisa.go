// Korea Internet & Security Agency (KISA) timestamp provider stub.
//
// STATUS: STUB - Not implemented
//
// KISA oversees South Korea's PKI infrastructure and accredits timestamp
// authorities for legal use in Korean courts and government proceedings.
//
// Key characteristics:
// - GOVERNMENT OPERATED: KISA is a government agency under MSIT
// - KOREAN ESA: Framework under Korean Electronic Signature Act
// - NPKI BASED: Part of National PKI infrastructure
// - KOREAN LANGUAGE: Documentation primarily in Korean
//
// NOTE: Legal status depends on specific use case and compliance requirements.
// Consult legal counsel for binding legal determinations.
//
// Legal framework:
// - Electronic Signature Act (전자서명법, 2020 revision)
// - Electronic Government Act (전자정부법)
// - Digital Signature Act amendments
//
// Accredited TSAs:
// - KISA operates its own timestamp service
// - CrossCert: https://www.crosscert.com/
// - KTNET: https://www.ktnet.com/
// - Korea Information Certificate Authority: https://www.signgate.com/
//
// Implementation requirements:
// - KISA or accredited CA credentials
// - Understanding of Korean NPKI standards
// - ARIA/SEED algorithm support (Korean national ciphers)
// - Korean business registration may be required
//
// Technical standards:
// - Based on RFC 3161
// - ARIA cipher (Korean national standard, similar to AES)
// - SEED cipher (older Korean standard)
// - KCDSA (Korean Certificate-based Digital Signature Algorithm)
//
// References:
// - https://www.kisa.or.kr/ (Korean)
// - https://www.rootca.or.kr/ (Korean Root CA)
// - TTA (Telecommunications Technology Association) standards
//
// Interested contributors: Please open an issue to coordinate implementation.

package anchors

import (
	"context"
	"errors"
	"time"
)

// KISAProvider implements TimestampProvider for Korean accredited TSAs.
type KISAProvider struct {
	tsaURL      string
	tsaName     string
	credentials string
}

// KISAConfig holds configuration for KISA provider.
type KISAConfig struct {
	TSAURL      string
	TSAName     string
	Credentials string
}

// NewKISAProvider creates a new KISA provider.
func NewKISAProvider(config KISAConfig) *KISAProvider {
	return &KISAProvider{
		tsaURL:      config.TSAURL,
		tsaName:     config.TSAName,
		credentials: config.Credentials,
	}
}

// Name returns the provider identifier.
func (p *KISAProvider) Name() string {
	return "kisa"
}

// DisplayName returns a human-readable name.
func (p *KISAProvider) DisplayName() string {
	return "KISA (South Korea)"
}

// Type returns the provider category.
func (p *KISAProvider) Type() ProviderType {
	return TypeGovernment
}

// Regions returns jurisdictions where this provider has legal standing.
func (p *KISAProvider) Regions() []string {
	return []string{"KR"}
}

// LegalStanding returns the legal recognition level.
func (p *KISAProvider) LegalStanding() LegalStanding {
	return StandingLegal
}

// Timestamp is not implemented.
func (p *KISAProvider) Timestamp(ctx context.Context, hash [32]byte) (*Proof, error) {
	return nil, errors.New("kisa: not implemented - requires KISA-accredited TSA credentials")
}

// Verify is not implemented.
func (p *KISAProvider) Verify(ctx context.Context, proof *Proof) (*VerifyResult, error) {
	return nil, errors.New("kisa: not implemented")
}

// Upgrade is not implemented.
func (p *KISAProvider) Upgrade(ctx context.Context, proof *Proof) (*Proof, error) {
	return nil, errors.New("kisa: not implemented")
}

// RequiresPayment returns true.
func (p *KISAProvider) RequiresPayment() bool {
	return true
}

// RequiresNetwork returns true.
func (p *KISAProvider) RequiresNetwork() bool {
	return true
}

// RequiresCredentials returns true.
func (p *KISAProvider) RequiresCredentials() bool {
	return true
}

// Configure sets provider configuration.
func (p *KISAProvider) Configure(config map[string]interface{}) error {
	if url, ok := config["tsa_url"].(string); ok {
		p.tsaURL = url
	}
	if name, ok := config["tsa_name"].(string); ok {
		p.tsaName = name
	}
	return nil
}

// Status returns the provider status.
func (p *KISAProvider) Status(ctx context.Context) (*ProviderStatus, error) {
	return &ProviderStatus{
		Available:  false,
		Configured: false,
		LastCheck:  time.Now(),
		Message:    "KISA provider not implemented - contributions welcome",
	}, nil
}

var _ Provider = (*KISAProvider)(nil)
