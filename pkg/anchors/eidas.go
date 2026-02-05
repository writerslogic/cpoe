// EU Trust List integration for timestamp provider validation.
//
// This package implements EU Trusted List parsing and validation according to
// ETSI EN 319 612. It allows validation of timestamp provider certificates
// against the official EU Trust Lists published by member states.
//
// IMPORTANT DISCLAIMER:
// This implementation does NOT make timestamps "eIDAS-certified", "Qualified",
// or "Legally binding under EU law". Legal status depends on many factors
// including the specific QTSP used, contractual arrangements, and applicable
// jurisdiction. Consult legal counsel for compliance requirements.
//
// What this package provides:
// - Fetches and parses EU Trust Lists (LOTL and member state lists)
// - Validates certificates against Trust List entries
// - Identifies providers with "granted" or "recognised" service status
// - Caches Trust Lists for 24 hours
//
// EU Trust Lists browser:
// - https://webgate.ec.europa.eu/tl-browser/
//
// References:
// - ETSI EN 319 612 (Trusted Lists format specification)
// - ETSI EN 319 421 (Policy and security requirements for TSPs)
// - ETSI EN 319 422 (Time-stamping protocol and profile)

package anchors

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// EU Trust List URLs
const (
	// LOTL (List of Trusted Lists) - the root trust list
	EULOTLUrl = "https://ec.europa.eu/tools/lotl/eu-lotl.xml"

	// Service type identifiers for qualified time stamping
	QTSAServiceType    = "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST"
	TSAServiceType     = "http://uri.etsi.org/TrstSvc/Svctype/TSA"
	QTSPServiceType    = "http://uri.etsi.org/TrstSvc/Svctype/TSA/TSS-QC"

	// Service status for granted/qualified
	ServiceStatusGranted    = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"
	ServiceStatusRecognised = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel"

	// Trust list cache duration
	TrustListCacheDuration = 24 * time.Hour
)

// EIDASProvider implements TimestampProvider for EU eIDAS QTSPs.
type EIDASProvider struct {
	// Underlying RFC 3161 provider
	rfc3161 *RFC3161Provider

	// QTSP-specific configuration
	qtspName     string
	trustListURL string
	policyOID    string
	memberState  string

	// Certificate validation
	validateQualified bool

	// Trust list cache
	trustListCache *TrustListCache

	// HTTP client for trust list fetching
	httpClient *http.Client
}

// EIDASConfig holds configuration for an eIDAS provider.
type EIDASConfig struct {
	// QTSP URL (RFC 3161 endpoint)
	QTSPURL string

	// QTSP display name
	QTSPName string

	// EU member state code (e.g., "DE", "FR", "NL")
	MemberState string

	// Trust List URL for this member state (optional, auto-discovered from LOTL)
	TrustListURL string

	// Policy OID for qualified timestamps (optional)
	PolicyOID string

	// Username for authentication (if required)
	Username string

	// Password for authentication (if required)
	Password string

	// Timeout for requests
	Timeout time.Duration

	// Skip trust list validation (for testing)
	SkipTrustListValidation bool
}

// WellKnownEIDASProviders lists some well-known eIDAS QTSPs.
// NOTE: Verify current qualified status on EU Trust Lists before production use.
var WellKnownEIDASProviders = map[string]EIDASConfig{
	"digicert-eu": {
		QTSPName:    "DigiCert Qualified TSA",
		MemberState: "NL",
		QTSPURL:     "https://timestamp.digicert.com",
	},
	"globalsign-eu": {
		QTSPName:    "GlobalSign Qualified TSA",
		MemberState: "BE",
		QTSPURL:     "https://timestamp.globalsign.com/?signature=sha2",
	},
	"sectigo-eu": {
		QTSPName:    "Sectigo Qualified TSA",
		MemberState: "NL",
		QTSPURL:     "https://timestamp.sectigo.com",
	},
}

// TrustListCache caches parsed EU Trust Lists.
type TrustListCache struct {
	mu          sync.RWMutex
	lists       map[string]*TrustList // keyed by member state
	lastUpdated map[string]time.Time
}

// TrustList represents a parsed EU Trust List (ETSI TS 119 612).
type TrustList struct {
	SchemeTerritory     string
	SchemeOperatorName  string
	ListIssueDateTime   time.Time
	NextUpdate          time.Time
	TrustServiceProviders []TrustServiceProvider
}

// TrustServiceProvider represents a TSP in the Trust List.
type TrustServiceProvider struct {
	Name     string
	Services []TrustService
}

// TrustService represents a trust service.
type TrustService struct {
	ServiceType        string
	ServiceName        string
	ServiceStatus      string
	StatusStartingTime time.Time
	ServiceDigitalIdentity []ServiceCertificate
}

// ServiceCertificate holds certificate info for a service.
type ServiceCertificate struct {
	X509Certificate *x509.Certificate
	X509SKI         []byte // Subject Key Identifier
	Fingerprint     [32]byte
}

// XML structures for ETSI TS 119 612 Trust List parsing

type xmlTrustServiceStatusList struct {
	XMLName               xml.Name `xml:"TrustServiceStatusList"`
	SchemeInformation     xmlSchemeInformation `xml:"SchemeInformation"`
	TrustServiceProviders xmlTrustServiceProviderList `xml:"TrustServiceProviderList"`
}

type xmlSchemeInformation struct {
	TSLType             string `xml:"TSLType"`
	SchemeTerritory     string `xml:"SchemeTerritory"`
	SchemeOperatorName  xmlInternationalNames `xml:"SchemeOperatorName"`
	ListIssueDateTime   string `xml:"ListIssueDateTime"`
	NextUpdate          xmlNextUpdate `xml:"NextUpdate"`
	PointersToOtherTSL  xmlPointersToOtherTSL `xml:"PointersToOtherTSL"`
}

type xmlInternationalNames struct {
	Names []xmlName `xml:"Name"`
}

type xmlName struct {
	Lang string `xml:"lang,attr"`
	Value string `xml:",chardata"`
}

type xmlNextUpdate struct {
	DateTime string `xml:"dateTime"`
}

type xmlPointersToOtherTSL struct {
	OtherTSLPointers []xmlOtherTSLPointer `xml:"OtherTSLPointer"`
}

type xmlOtherTSLPointer struct {
	TSLLocation string `xml:"TSLLocation"`
	AdditionalInformation xmlAdditionalInformation `xml:"AdditionalInformation"`
}

type xmlAdditionalInformation struct {
	OtherInformation []xmlOtherInformation `xml:"OtherInformation"`
}

type xmlOtherInformation struct {
	SchemeTerritory string `xml:"SchemeTerritory"`
}

type xmlTrustServiceProviderList struct {
	TrustServiceProviders []xmlTrustServiceProvider `xml:"TrustServiceProvider"`
}

type xmlTrustServiceProvider struct {
	TSPInformation xmlTSPInformation `xml:"TSPInformation"`
	TSPServices    xmlTSPServices `xml:"TSPServices"`
}

type xmlTSPInformation struct {
	TSPName xmlInternationalNames `xml:"TSPName"`
}

type xmlTSPServices struct {
	TSPService []xmlTSPService `xml:"TSPService"`
}

type xmlTSPService struct {
	ServiceInformation xmlServiceInformation `xml:"ServiceInformation"`
}

type xmlServiceInformation struct {
	ServiceTypeIdentifier string `xml:"ServiceTypeIdentifier"`
	ServiceName           xmlInternationalNames `xml:"ServiceName"`
	ServiceDigitalIdentity xmlServiceDigitalIdentity `xml:"ServiceDigitalIdentity"`
	ServiceStatus         string `xml:"ServiceStatus"`
	StatusStartingTime    string `xml:"StatusStartingTime"`
}

type xmlServiceDigitalIdentity struct {
	DigitalId []xmlDigitalId `xml:"DigitalId"`
}

type xmlDigitalId struct {
	X509Certificate string `xml:"X509Certificate"`
	X509SKI         string `xml:"X509SubjectKeyIdentifier"`
}

// NewTrustListCache creates a new trust list cache.
func NewTrustListCache() *TrustListCache {
	return &TrustListCache{
		lists:       make(map[string]*TrustList),
		lastUpdated: make(map[string]time.Time),
	}
}

// Global trust list cache
var globalTrustListCache = NewTrustListCache()

// NewEIDASProvider creates a new eIDAS QTSP provider.
func NewEIDASProvider(config EIDASConfig) *EIDASProvider {
	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	rfc3161 := NewRFC3161Provider(RFC3161Config{
		TSAURL:   config.QTSPURL,
		TSAName:  config.QTSPName,
		Username: config.Username,
		Password: config.Password,
		Timeout:  timeout,
		Regions:  []string{"EU", config.MemberState},
	})

	return &EIDASProvider{
		rfc3161:           rfc3161,
		qtspName:          config.QTSPName,
		trustListURL:      config.TrustListURL,
		policyOID:         config.PolicyOID,
		memberState:       config.MemberState,
		validateQualified: !config.SkipTrustListValidation,
		trustListCache:    globalTrustListCache,
		httpClient:        &http.Client{Timeout: 60 * time.Second},
	}
}

// Name returns the provider identifier.
func (p *EIDASProvider) Name() string {
	return "eidas"
}

// DisplayName returns a human-readable name.
func (p *EIDASProvider) DisplayName() string {
	if p.qtspName != "" {
		return "eIDAS QTSP (" + p.qtspName + ")"
	}
	return "eIDAS Qualified TSA"
}

// Type returns the provider category.
func (p *EIDASProvider) Type() ProviderType {
	return TypeQualified
}

// Regions returns jurisdictions where this provider has legal standing.
func (p *EIDASProvider) Regions() []string {
	// EU-wide recognition plus specific member state
	regions := []string{"EU"}
	if p.memberState != "" {
		regions = append(regions, p.memberState)
	}
	return regions
}

// LegalStanding returns the legal recognition level.
func (p *EIDASProvider) LegalStanding() LegalStanding {
	return StandingQualified
}

// Timestamp creates an eIDAS qualified timestamp.
func (p *EIDASProvider) Timestamp(ctx context.Context, hash [32]byte) (*Proof, error) {
	if p.rfc3161.tsaURL == "" {
		return nil, errors.New("eidas: QTSP URL not configured - see EU Trust Lists for qualified providers")
	}

	// Use underlying RFC 3161
	proof, err := p.rfc3161.Timestamp(ctx, hash)
	if err != nil {
		return nil, err
	}

	// Mark as eIDAS provider
	proof.Provider = p.Name()
	proof.Metadata["qtsp"] = p.qtspName
	proof.Metadata["member_state"] = p.memberState

	// Validate qualified status if enabled
	if p.validateQualified && len(proof.CertificateChain) > 0 {
		qualified, err := p.ValidateQualifiedStatus(ctx, proof.CertificateChain)
		if err != nil {
			proof.Metadata["qualified_validation"] = fmt.Sprintf("validation error: %v", err)
		} else if qualified {
			proof.Metadata["qualified_validation"] = "verified against EU Trust List"
			proof.Metadata["qualified"] = true
		} else {
			proof.Metadata["qualified_validation"] = "certificate not found in EU Trust List"
			proof.Metadata["qualified"] = false
		}
	} else if !p.validateQualified {
		proof.Metadata["qualified_validation"] = "validation disabled"
	} else {
		proof.Metadata["qualified_validation"] = "no certificate chain available for validation"
	}

	return proof, nil
}

// Verify checks an eIDAS qualified timestamp.
func (p *EIDASProvider) Verify(ctx context.Context, proof *Proof) (*VerifyResult, error) {
	if proof.Provider != p.Name() {
		return nil, errors.New("proof is not from eIDAS provider")
	}

	// Use underlying RFC 3161 verification
	result, err := p.rfc3161.Verify(ctx, proof)
	if err != nil {
		return result, err
	}

	// Validate qualified status
	if p.validateQualified && len(proof.CertificateChain) > 0 {
		qualified, verr := p.ValidateQualifiedStatus(ctx, proof.CertificateChain)
		if verr != nil {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("Trust list validation error: %v", verr))
		} else if qualified {
			if result.CertificateInfo != nil {
				result.CertificateInfo.IsQualified = true
			}
		} else {
			result.Warnings = append(result.Warnings,
				"Certificate not found in EU Trust List - qualified status unverified")
		}
	}

	return result, nil
}

// Upgrade is a no-op for eIDAS - proofs are immediately confirmed.
func (p *EIDASProvider) Upgrade(ctx context.Context, proof *Proof) (*Proof, error) {
	return proof, nil
}

// RequiresPayment indicates if this QTSP charges fees.
func (p *EIDASProvider) RequiresPayment() bool {
	return true // All QTSPs are commercial services
}

// RequiresNetwork returns true.
func (p *EIDASProvider) RequiresNetwork() bool {
	return true
}

// RequiresCredentials indicates if authentication is needed.
func (p *EIDASProvider) RequiresCredentials() bool {
	return true // Most QTSPs require accounts
}

// Configure sets provider configuration.
func (p *EIDASProvider) Configure(config map[string]interface{}) error {
	if url, ok := config["qtsp_url"].(string); ok {
		p.rfc3161.tsaURL = url
	}
	if name, ok := config["qtsp_name"].(string); ok {
		p.qtspName = name
	}
	if state, ok := config["member_state"].(string); ok {
		p.memberState = state
	}
	if policy, ok := config["policy_oid"].(string); ok {
		p.policyOID = policy
	}
	if skip, ok := config["skip_validation"].(bool); ok {
		p.validateQualified = !skip
	}
	return p.rfc3161.Configure(config)
}

// Status returns the current provider status.
func (p *EIDASProvider) Status(ctx context.Context) (*ProviderStatus, error) {
	status, err := p.rfc3161.Status(ctx)
	if err != nil {
		return status, err
	}

	if !status.Configured {
		status.Message = "eIDAS QTSP not configured - obtain credentials from a Qualified Trust Service Provider"
	}

	return status, nil
}

// ValidateQualifiedStatus checks if a certificate is on the EU Trust List.
func (p *EIDASProvider) ValidateQualifiedStatus(ctx context.Context, certChain [][]byte) (bool, error) {
	if len(certChain) == 0 {
		return false, errors.New("empty certificate chain")
	}

	// Parse the first certificate (TSA certificate)
	cert, err := x509.ParseCertificate(certChain[0])
	if err != nil {
		return false, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Calculate certificate fingerprint
	fingerprint := sha256.Sum256(cert.Raw)

	// Get trust list for member state
	trustList, err := p.getTrustList(ctx, p.memberState)
	if err != nil {
		return false, fmt.Errorf("failed to fetch trust list: %w", err)
	}

	// Search for certificate in trust list
	for _, tsp := range trustList.TrustServiceProviders {
		for _, service := range tsp.Services {
			// Check if this is a qualified TSA service
			if !isQualifiedTSAService(service) {
				continue
			}

			// Check certificates
			for _, serviceCert := range service.ServiceDigitalIdentity {
				if serviceCert.Fingerprint == fingerprint {
					return true, nil
				}
				// Also check by Subject Key Identifier if available
				if len(serviceCert.X509SKI) > 0 && len(cert.SubjectKeyId) > 0 {
					if string(serviceCert.X509SKI) == string(cert.SubjectKeyId) {
						return true, nil
					}
				}
			}
		}
	}

	return false, nil
}

// isQualifiedTSAService checks if a service is a qualified TSA.
func isQualifiedTSAService(service TrustService) bool {
	// Check service type
	isQTSA := service.ServiceType == QTSAServiceType ||
		service.ServiceType == TSAServiceType ||
		service.ServiceType == QTSPServiceType

	// Check service status
	isGranted := service.ServiceStatus == ServiceStatusGranted ||
		service.ServiceStatus == ServiceStatusRecognised

	return isQTSA && isGranted
}

// getTrustList fetches and parses the trust list for a member state.
func (p *EIDASProvider) getTrustList(ctx context.Context, memberState string) (*TrustList, error) {
	// Check cache
	p.trustListCache.mu.RLock()
	if list, ok := p.trustListCache.lists[memberState]; ok {
		if time.Since(p.trustListCache.lastUpdated[memberState]) < TrustListCacheDuration {
			p.trustListCache.mu.RUnlock()
			return list, nil
		}
	}
	p.trustListCache.mu.RUnlock()

	// Need to fetch - get write lock
	p.trustListCache.mu.Lock()
	defer p.trustListCache.mu.Unlock()

	// Double-check after acquiring write lock
	if list, ok := p.trustListCache.lists[memberState]; ok {
		if time.Since(p.trustListCache.lastUpdated[memberState]) < TrustListCacheDuration {
			return list, nil
		}
	}

	// Get trust list URL from LOTL if not specified
	trustListURL := p.trustListURL
	if trustListURL == "" {
		url, err := p.getTrustListURLFromLOTL(ctx, memberState)
		if err != nil {
			return nil, fmt.Errorf("failed to get trust list URL: %w", err)
		}
		trustListURL = url
	}

	// Fetch trust list
	list, err := p.fetchAndParseTrustList(ctx, trustListURL)
	if err != nil {
		return nil, err
	}

	// Cache it
	p.trustListCache.lists[memberState] = list
	p.trustListCache.lastUpdated[memberState] = time.Now()

	return list, nil
}

// getTrustListURLFromLOTL gets the trust list URL for a member state from the LOTL.
func (p *EIDASProvider) getTrustListURLFromLOTL(ctx context.Context, memberState string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", EULOTLUrl, nil)
	if err != nil {
		return "", err
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("LOTL returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var lotl xmlTrustServiceStatusList
	if err := xml.Unmarshal(body, &lotl); err != nil {
		return "", fmt.Errorf("failed to parse LOTL: %w", err)
	}

	// Find pointer to member state trust list
	for _, pointer := range lotl.SchemeInformation.PointersToOtherTSL.OtherTSLPointers {
		for _, info := range pointer.AdditionalInformation.OtherInformation {
			if strings.EqualFold(info.SchemeTerritory, memberState) {
				return pointer.TSLLocation, nil
			}
		}
	}

	return "", fmt.Errorf("trust list not found for member state: %s", memberState)
}

// fetchAndParseTrustList fetches and parses a trust list.
func (p *EIDASProvider) fetchAndParseTrustList(ctx context.Context, url string) (*TrustList, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("trust list returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var xmlList xmlTrustServiceStatusList
	if err := xml.Unmarshal(body, &xmlList); err != nil {
		return nil, fmt.Errorf("failed to parse trust list: %w", err)
	}

	return parseTrustList(&xmlList)
}

// parseTrustList converts XML trust list to our internal format.
func parseTrustList(xmlList *xmlTrustServiceStatusList) (*TrustList, error) {
	list := &TrustList{
		SchemeTerritory: xmlList.SchemeInformation.SchemeTerritory,
	}

	// Get operator name (prefer English)
	for _, name := range xmlList.SchemeInformation.SchemeOperatorName.Names {
		if name.Lang == "en" || list.SchemeOperatorName == "" {
			list.SchemeOperatorName = name.Value
		}
	}

	// Parse dates
	if t, err := time.Parse(time.RFC3339, xmlList.SchemeInformation.ListIssueDateTime); err == nil {
		list.ListIssueDateTime = t
	}
	if t, err := time.Parse(time.RFC3339, xmlList.SchemeInformation.NextUpdate.DateTime); err == nil {
		list.NextUpdate = t
	}

	// Parse TSPs
	for _, xmlTSP := range xmlList.TrustServiceProviders.TrustServiceProviders {
		tsp := TrustServiceProvider{}

		// Get TSP name (prefer English)
		for _, name := range xmlTSP.TSPInformation.TSPName.Names {
			if name.Lang == "en" || tsp.Name == "" {
				tsp.Name = name.Value
			}
		}

		// Parse services
		for _, xmlService := range xmlTSP.TSPServices.TSPService {
			service := TrustService{
				ServiceType:   xmlService.ServiceInformation.ServiceTypeIdentifier,
				ServiceStatus: xmlService.ServiceInformation.ServiceStatus,
			}

			// Get service name (prefer English)
			for _, name := range xmlService.ServiceInformation.ServiceName.Names {
				if name.Lang == "en" || service.ServiceName == "" {
					service.ServiceName = name.Value
				}
			}

			// Parse status starting time
			if t, err := time.Parse(time.RFC3339, xmlService.ServiceInformation.StatusStartingTime); err == nil {
				service.StatusStartingTime = t
			}

			// Parse digital identities
			for _, digitalId := range xmlService.ServiceInformation.ServiceDigitalIdentity.DigitalId {
				var serviceCert ServiceCertificate

				// Parse X509 certificate
				if digitalId.X509Certificate != "" {
					certBytes, err := base64.StdEncoding.DecodeString(
						strings.ReplaceAll(strings.ReplaceAll(digitalId.X509Certificate, "\n", ""), " ", ""))
					if err == nil {
						cert, err := x509.ParseCertificate(certBytes)
						if err == nil {
							serviceCert.X509Certificate = cert
							serviceCert.Fingerprint = sha256.Sum256(certBytes)
						}
					}
				}

				// Parse SKI
				if digitalId.X509SKI != "" {
					ski, err := hex.DecodeString(strings.ReplaceAll(digitalId.X509SKI, ":", ""))
					if err == nil {
						serviceCert.X509SKI = ski
					}
				}

				if serviceCert.X509Certificate != nil || len(serviceCert.X509SKI) > 0 {
					service.ServiceDigitalIdentity = append(service.ServiceDigitalIdentity, serviceCert)
				}
			}

			tsp.Services = append(tsp.Services, service)
		}

		list.TrustServiceProviders = append(list.TrustServiceProviders, tsp)
	}

	return list, nil
}

// ListQualifiedTSPs returns all qualified TSA providers from a member state's trust list.
func (p *EIDASProvider) ListQualifiedTSPs(ctx context.Context, memberState string) ([]string, error) {
	list, err := p.getTrustList(ctx, memberState)
	if err != nil {
		return nil, err
	}

	var tsps []string
	for _, tsp := range list.TrustServiceProviders {
		for _, service := range tsp.Services {
			if isQualifiedTSAService(service) {
				tsps = append(tsps, fmt.Sprintf("%s - %s", tsp.Name, service.ServiceName))
			}
		}
	}

	return tsps, nil
}

// Verify that EIDASProvider implements Provider.
var _ Provider = (*EIDASProvider)(nil)
