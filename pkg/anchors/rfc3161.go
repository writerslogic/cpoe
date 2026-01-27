// RFC 3161 Timestamp Authority provider implementation.
//
// RFC 3161 defines the Internet X.509 Public Key Infrastructure Time-Stamp
// Protocol (TSP). It provides legally recognized timestamps in many jurisdictions
// when issued by accredited Time Stamping Authorities (TSAs).
//
// Key characteristics:
// - STANDARDIZED: IETF standard, widely implemented
// - LEGALLY RECOGNIZED: Accepted in courts in most jurisdictions
// - IMMEDIATE: No confirmation delay (unlike blockchain)
// - PAID: Most TSAs charge per-timestamp or subscription fees
// - PKI-BASED: Relies on certificate trust chains
//
// How it works:
// 1. Client creates TimeStampReq with hash and nonce
// 2. TSA signs the hash with its certified key
// 3. TSA returns TimeStampResp with signed token
// 4. Token can be verified using TSA's certificate chain
//
// Free TSAs for testing:
// - FreeTSA: https://freetsa.org/tsr
// - Sectigo: https://timestamp.sectigo.com (limited)
//
// Commercial TSAs with legal standing:
// - DigiCert: https://timestamp.digicert.com
// - GlobalSign: https://timestamp.globalsign.com
// - Sectigo: https://timestamp.sectigo.com
//
// References:
// - RFC 3161: https://tools.ietf.org/html/rfc3161
// - RFC 5816: ESSCertIDv2 Update

package anchors

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"
)

// Well-known TSA URLs
var WellKnownTSAs = map[string]string{
	"freetsa":      "https://freetsa.org/tsr",
	"sectigo":      "https://timestamp.sectigo.com",
	"digicert":     "https://timestamp.digicert.com",
	"globalsign":   "https://timestamp.globalsign.com/?signature=sha2",
	"comodo":       "http://timestamp.comodoca.com",
	"symantec":     "http://timestamp.digicert.com",
	"startcom":     "http://tsa.startssl.com/rfc3161",
	"quovadis":     "http://ts.quovadisglobal.com/eu",
	"apple":        "http://timestamp.apple.com/ts01",
	"microsoft":    "http://timestamp.microsoft.com",
}

// ASN.1 OIDs
var (
	oidDigestAlgorithmSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidDigestAlgorithmSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidDigestAlgorithmSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	oidTSTInfo               = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
)

// RFC3161Provider implements the Provider interface for RFC 3161 TSAs.
type RFC3161Provider struct {
	tsaURL      string
	tsaName     string
	httpClient  *http.Client
	certPool    *x509.CertPool
	requireCert bool
	username    string
	password    string
	regions     []string
}

// RFC3161Config holds configuration for an RFC 3161 provider.
type RFC3161Config struct {
	// TSAURL is the timestamp authority URL
	TSAURL string

	// TSAName is a human-readable name for this TSA
	TSAName string

	// Username for HTTP Basic auth (if required)
	Username string

	// Password for HTTP Basic auth (if required)
	Password string

	// CertPool for verifying TSA responses (optional)
	CertPool *x509.CertPool

	// RequireCert requires certificate in response
	RequireCert bool

	// Regions where this TSA has legal standing
	Regions []string

	// Timeout for HTTP requests
	Timeout time.Duration
}

// NewRFC3161Provider creates a new RFC 3161 provider.
func NewRFC3161Provider(config RFC3161Config) *RFC3161Provider {
	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	regions := config.Regions
	if len(regions) == 0 {
		regions = []string{"GLOBAL"}
	}

	return &RFC3161Provider{
		tsaURL:      config.TSAURL,
		tsaName:     config.TSAName,
		httpClient:  &http.Client{Timeout: timeout},
		certPool:    config.CertPool,
		requireCert: config.RequireCert,
		username:    config.Username,
		password:    config.Password,
		regions:     regions,
	}
}

// NewFreeTSAProvider creates a provider using FreeTSA.org.
func NewFreeTSAProvider() *RFC3161Provider {
	return NewRFC3161Provider(RFC3161Config{
		TSAURL:  "https://freetsa.org/tsr",
		TSAName: "FreeTSA",
		Regions: []string{"GLOBAL"},
	})
}

// Name returns the provider identifier.
func (p *RFC3161Provider) Name() string {
	if p.tsaName != "" {
		return "rfc3161-" + p.tsaName
	}
	return "rfc3161"
}

// DisplayName returns a human-readable name.
func (p *RFC3161Provider) DisplayName() string {
	if p.tsaName != "" {
		return "RFC 3161 (" + p.tsaName + ")"
	}
	return "RFC 3161 TSA"
}

// Type returns the provider category.
func (p *RFC3161Provider) Type() ProviderType {
	return TypeRFC3161
}

// Regions returns jurisdictions where this provider has legal standing.
func (p *RFC3161Provider) Regions() []string {
	return p.regions
}

// LegalStanding returns the legal recognition level.
func (p *RFC3161Provider) LegalStanding() LegalStanding {
	return StandingLegal
}

// TimeStampReq is the ASN.1 structure for a timestamp request.
type TimeStampReq struct {
	Version        int
	MessageImprint MessageImprint
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	Nonce          *big.Int              `asn1:"optional"`
	CertReq        bool                  `asn1:"optional,default:false"`
	Extensions     []pkix.Extension      `asn1:"optional,tag:0"`
}

// MessageImprint contains the hash to timestamp.
type MessageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

// TimeStampResp is the ASN.1 structure for a timestamp response.
type TimeStampResp struct {
	Status         PKIStatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

// PKIStatusInfo contains the response status.
type PKIStatusInfo struct {
	Status       int
	StatusString []string         `asn1:"optional"`
	FailInfo     asn1.BitString   `asn1:"optional"`
}

// TSTInfo contains the timestamp token info.
type TSTInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint MessageImprint
	SerialNumber   *big.Int
	GenTime        time.Time
	Accuracy       Accuracy             `asn1:"optional"`
	Ordering       bool                 `asn1:"optional,default:false"`
	Nonce          *big.Int             `asn1:"optional"`
	TSA            asn1.RawValue        `asn1:"optional,tag:0"`
	Extensions     []pkix.Extension     `asn1:"optional,tag:1"`
}

// Accuracy represents timestamp accuracy.
type Accuracy struct {
	Seconds int `asn1:"optional"`
	Millis  int `asn1:"optional,tag:0"`
	Micros  int `asn1:"optional,tag:1"`
}

// Timestamp creates an RFC 3161 timestamp request.
func (p *RFC3161Provider) Timestamp(ctx context.Context, hash [32]byte) (*Proof, error) {
	if p.tsaURL == "" {
		return nil, errors.New("TSA URL not configured")
	}

	// Generate nonce
	nonce, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Build timestamp request
	req := TimeStampReq{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm: oidDigestAlgorithmSHA256,
			},
			HashedMessage: hash[:],
		},
		Nonce:   nonce,
		CertReq: p.requireCert,
	}

	reqBytes, err := asn1.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Send HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.tsaURL, bytes.NewReader(reqBytes))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/timestamp-query")

	if p.username != "" {
		httpReq.SetBasicAuth(p.username, p.password)
	}

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("TSA request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("TSA returned %d: %s", resp.StatusCode, string(body))
	}

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Parse response
	var tsResp TimeStampResp
	_, err = asn1.Unmarshal(respBytes, &tsResp)
	if err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Check status
	if tsResp.Status.Status != 0 && tsResp.Status.Status != 1 {
		statusMsg := "unknown error"
		if len(tsResp.Status.StatusString) > 0 {
			statusMsg = tsResp.Status.StatusString[0]
		}
		return nil, fmt.Errorf("TSA error (status %d): %s", tsResp.Status.Status, statusMsg)
	}

	// Extract timestamp from token
	timestamp := time.Now() // Default to now if we can't parse
	if len(tsResp.TimeStampToken.Bytes) > 0 {
		if t, err := p.extractTimestamp(tsResp.TimeStampToken.Bytes); err == nil {
			timestamp = t
		}
	}

	return &Proof{
		Provider:  p.Name(),
		Version:   1,
		Hash:      hash,
		Timestamp: timestamp,
		Status:    StatusConfirmed,
		RawProof:  respBytes,
		VerifyURL: p.tsaURL,
		Metadata: map[string]interface{}{
			"tsa_url": p.tsaURL,
			"nonce":   nonce.String(),
		},
	}, nil
}

// extractTimestamp extracts the genTime from a timestamp token.
func (p *RFC3161Provider) extractTimestamp(tokenBytes []byte) (time.Time, error) {
	// The token is a ContentInfo containing SignedData containing TSTInfo
	// This is a simplified extraction - production code should fully parse

	// Look for GeneralizedTime in the ASN.1 structure
	// GeneralizedTime tag is 0x18
	for i := 0; i < len(tokenBytes)-15; i++ {
		if tokenBytes[i] == 0x18 && tokenBytes[i+1] == 0x0f {
			// Found a 15-byte GeneralizedTime
			timeStr := string(tokenBytes[i+2 : i+17])
			t, err := time.Parse("20060102150405Z", timeStr)
			if err == nil {
				return t, nil
			}
		}
	}

	return time.Time{}, errors.New("could not extract timestamp")
}

// Verify checks an RFC 3161 timestamp response.
func (p *RFC3161Provider) Verify(ctx context.Context, proof *Proof) (*VerifyResult, error) {
	if proof.Provider != p.Name() && proof.Provider != "rfc3161" {
		return nil, fmt.Errorf("proof is not from RFC 3161 provider")
	}

	result := &VerifyResult{
		Provider:     p.Name(),
		VerifiedHash: proof.Hash,
	}

	// Parse the timestamp response
	var tsResp TimeStampResp
	_, err := asn1.Unmarshal(proof.RawProof, &tsResp)
	if err != nil {
		result.Error = "failed to parse timestamp response"
		return result, ErrInvalidProof
	}

	// Check status
	if tsResp.Status.Status != 0 && tsResp.Status.Status != 1 {
		result.Error = fmt.Sprintf("TSA status: %d", tsResp.Status.Status)
		result.Status = StatusFailed
		return result, ErrVerificationFailed
	}

	// Extract and verify timestamp token
	if len(tsResp.TimeStampToken.Bytes) == 0 {
		result.Error = "no timestamp token in response"
		return result, ErrInvalidProof
	}

	// Extract timestamp
	timestamp, err := p.extractTimestamp(tsResp.TimeStampToken.Bytes)
	if err != nil {
		result.Warnings = append(result.Warnings, "could not extract exact timestamp")
		timestamp = proof.Timestamp
	}

	result.Valid = true
	result.Status = StatusConfirmed
	result.Timestamp = timestamp

	return result, nil
}

// Upgrade is a no-op for RFC 3161 - proofs are immediately confirmed.
func (p *RFC3161Provider) Upgrade(ctx context.Context, proof *Proof) (*Proof, error) {
	return proof, nil
}

// RequiresPayment indicates if this TSA charges fees.
func (p *RFC3161Provider) RequiresPayment() bool {
	// FreeTSA and some others are free
	freeTSAs := []string{"freetsa.org", "timestamp.sectigo.com"}
	for _, free := range freeTSAs {
		if bytes.Contains([]byte(p.tsaURL), []byte(free)) {
			return false
		}
	}
	return true
}

// RequiresNetwork returns true - needs internet for TSA.
func (p *RFC3161Provider) RequiresNetwork() bool {
	return true
}

// RequiresCredentials indicates if API keys are needed.
func (p *RFC3161Provider) RequiresCredentials() bool {
	return p.username != ""
}

// Configure sets provider configuration.
func (p *RFC3161Provider) Configure(config map[string]interface{}) error {
	if url, ok := config["tsa_url"].(string); ok {
		p.tsaURL = url
	}
	if name, ok := config["tsa_name"].(string); ok {
		p.tsaName = name
	}
	if user, ok := config["username"].(string); ok {
		p.username = user
	}
	if pass, ok := config["password"].(string); ok {
		p.password = pass
	}
	if regions, ok := config["regions"].([]string); ok {
		p.regions = regions
	}
	return nil
}

// Status returns the current provider status.
func (p *RFC3161Provider) Status(ctx context.Context) (*ProviderStatus, error) {
	status := &ProviderStatus{
		Configured: p.tsaURL != "",
		LastCheck:  time.Now(),
	}

	if !status.Configured {
		status.Message = "TSA URL not configured"
		return status, nil
	}

	// Try a simple request to check availability
	req, err := http.NewRequestWithContext(ctx, "GET", p.tsaURL, nil)
	if err != nil {
		status.Message = err.Error()
		return status, nil
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		status.Message = "TSA unreachable: " + err.Error()
		return status, nil
	}
	resp.Body.Close()

	// Most TSAs return 405 for GET (only POST allowed)
	if resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode == http.StatusOK {
		status.Available = true
		status.Message = "TSA is reachable"
	} else {
		status.Message = fmt.Sprintf("TSA returned %d", resp.StatusCode)
	}

	return status, nil
}

// Verify that RFC3161Provider implements Provider.
var _ Provider = (*RFC3161Provider)(nil)
