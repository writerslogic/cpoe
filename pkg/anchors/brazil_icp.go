// ICP-Brasil (Infraestrutura de Chaves Públicas Brasileira) timestamp provider stub.
//
// STATUS: STUB - Not implemented
//
// ICP-Brasil is Brazil's national PKI infrastructure, providing legally
// recognized digital certificates and timestamps for Brazilian legal proceedings.
//
// Key characteristics:
// - GOVERNMENT MANDATED: Required for many official Brazilian transactions
// - ICP-BRASIL FRAMEWORK: Brazilian PKI regulations
// - HIERARCHICAL PKI: Root CA operated by ITI (Instituto Nacional de TI)
// - PORTUGUESE: Documentation primarily in Portuguese
//
// NOTE: Legal status depends on specific use case and compliance requirements.
// Consult legal counsel for binding legal determinations.
//
// Implementation requirements:
// - Accredited TSA certificate from ICP-Brasil hierarchy
// - Understanding of ICP-Brasil normative documents
// - Compliance with ITI regulations
// - Brazilian entity may be required for some services
//
// TSA Requirements (DOC-ICP-12):
// - Must use ICP-Brasil certificates
// - Must follow RFC 3161 with ICP-Brasil extensions
// - Must maintain audit logs per ITI requirements
//
// Legal context:
// - Medida Provisória 2.200-2/2001 (Legal framework for ICP-Brasil)
// - DOC-ICP documents (Technical standards)
// - Required for NFe (electronic invoices), judicial processes, etc.
//
// Accredited TSAs:
// - Certisign: https://www.certisign.com.br/
// - Serasa Experian: https://serasa.certificadodigital.com.br/
// - Serpro: https://www.serpro.gov.br/
// - Valid Certificadora: https://www.validcertificadora.com.br/
//
// References:
// - https://www.gov.br/iti/pt-br/assuntos/icp-brasil
// - DOC-ICP-12 (Timestamp requirements)
// - DOC-ICP-05 (Certificate policies)
//
// Interested contributors: Please open an issue to coordinate implementation.

package anchors

import (
	"context"
	"errors"
	"time"
)

// ICPBrasilProvider implements TimestampProvider for ICP-Brasil TSAs.
type ICPBrasilProvider struct {
	tsaURL   string
	tsaName  string
	certPath string
	keyPath  string
}

// ICPBrasilConfig holds configuration for ICP-Brasil provider.
type ICPBrasilConfig struct {
	TSAURL   string
	TSAName  string
	CertPath string // Path to ICP-Brasil certificate
	KeyPath  string // Path to private key
}

// NewICPBrasilProvider creates a new ICP-Brasil provider.
func NewICPBrasilProvider(config ICPBrasilConfig) *ICPBrasilProvider {
	return &ICPBrasilProvider{
		tsaURL:   config.TSAURL,
		tsaName:  config.TSAName,
		certPath: config.CertPath,
		keyPath:  config.KeyPath,
	}
}

// Name returns the provider identifier.
func (p *ICPBrasilProvider) Name() string {
	return "icp-brasil"
}

// DisplayName returns a human-readable name.
func (p *ICPBrasilProvider) DisplayName() string {
	return "ICP-Brasil"
}

// Type returns the provider category.
func (p *ICPBrasilProvider) Type() ProviderType {
	return TypeGovernment
}

// Regions returns jurisdictions where this provider has legal standing.
func (p *ICPBrasilProvider) Regions() []string {
	return []string{"BR"}
}

// LegalStanding returns the legal recognition level.
func (p *ICPBrasilProvider) LegalStanding() LegalStanding {
	return StandingLegal
}

// Timestamp is not implemented.
func (p *ICPBrasilProvider) Timestamp(ctx context.Context, hash [32]byte) (*Proof, error) {
	return nil, errors.New("icp-brasil: not implemented - requires ICP-Brasil accredited TSA credentials")
}

// Verify is not implemented.
func (p *ICPBrasilProvider) Verify(ctx context.Context, proof *Proof) (*VerifyResult, error) {
	return nil, errors.New("icp-brasil: not implemented - requires ICP-Brasil certificate chain validation")
}

// Upgrade is not implemented.
func (p *ICPBrasilProvider) Upgrade(ctx context.Context, proof *Proof) (*Proof, error) {
	return nil, errors.New("icp-brasil: not implemented")
}

// RequiresPayment returns true.
func (p *ICPBrasilProvider) RequiresPayment() bool {
	return true
}

// RequiresNetwork returns true.
func (p *ICPBrasilProvider) RequiresNetwork() bool {
	return true
}

// RequiresCredentials returns true.
func (p *ICPBrasilProvider) RequiresCredentials() bool {
	return true
}

// Configure sets provider configuration.
func (p *ICPBrasilProvider) Configure(config map[string]interface{}) error {
	if url, ok := config["tsa_url"].(string); ok {
		p.tsaURL = url
	}
	if name, ok := config["tsa_name"].(string); ok {
		p.tsaName = name
	}
	if cert, ok := config["cert_path"].(string); ok {
		p.certPath = cert
	}
	if key, ok := config["key_path"].(string); ok {
		p.keyPath = key
	}
	return nil
}

// Status returns the provider status.
func (p *ICPBrasilProvider) Status(ctx context.Context) (*ProviderStatus, error) {
	return &ProviderStatus{
		Available:  false,
		Configured: false,
		LastCheck:  time.Now(),
		Message:    "ICP-Brasil provider not implemented - contributions welcome",
	}, nil
}

var _ Provider = (*ICPBrasilProvider)(nil)
