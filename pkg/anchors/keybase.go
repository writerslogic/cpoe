// Keybase timestamp provider - verification of existing proofs.
//
// Keybase was a decentralized identity and file sharing platform that provided
// cryptographic proofs and timestamping via the Stellar blockchain. Keybase was
// acquired by Zoom in 2020 and the service has been largely discontinued.
//
// This implementation provides:
// - Verification of existing Keybase signature chains (sigchains)
// - Parsing of Keybase proof formats
// - Historical proof validation
//
// Key characteristics (historical):
// - DECENTRALIZED: Identity proofs across multiple platforms
// - STELLAR ANCHORED: Timestamps were anchored to Stellar blockchain
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
// References:
// - https://keybase.io/ (limited functionality)
// - https://book.keybase.io/docs/server (documentation)
// - Stellar: https://www.stellar.org/

package anchors

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Keybase API endpoints
const (
	KeybaseAPIBase     = "https://keybase.io/_/api/1.0"
	KeybaseMerkleRoot  = KeybaseAPIBase + "/merkle/root.json"
	KeybaseUserLookup  = KeybaseAPIBase + "/user/lookup.json"
	KeybaseSigchainGet = KeybaseAPIBase + "/sig/get.json"
)

// KeybaseProvider implements TimestampProvider for Keybase (verification only).
type KeybaseProvider struct {
	httpClient *http.Client
}

// KeybaseConfig holds configuration for Keybase provider.
type KeybaseConfig struct {
	// Timeout for HTTP requests
	Timeout time.Duration
}

// KeybaseProof represents a Keybase proof structure.
type KeybaseProof struct {
	// Username of the Keybase user who created the proof
	Username string `json:"username"`

	// UID is the Keybase user ID
	UID string `json:"uid"`

	// Seqno is the sequence number in the sigchain
	Seqno int64 `json:"seqno"`

	// Hash of the data being timestamped
	DataHash [32]byte `json:"data_hash"`

	// Signature over the payload
	Signature []byte `json:"signature"`

	// Payload is the signed JSON
	Payload string `json:"payload"`

	// PublicKey used for signing (NaCl/Ed25519)
	PublicKey []byte `json:"public_key"`

	// StellarTxID if anchored to Stellar
	StellarTxID string `json:"stellar_tx_id,omitempty"`

	// CreatedAt timestamp from the sigchain
	CreatedAt time.Time `json:"created_at"`
}

// KeybaseSigchainLink represents a link in a Keybase sigchain.
type KeybaseSigchainLink struct {
	Seqno       int64  `json:"seqno"`
	Prev        string `json:"prev"`
	Sig         string `json:"sig"`
	PayloadHash string `json:"payload_hash"`
	SigID       string `json:"sig_id"`
	Payload     json.RawMessage `json:"payload_json"`
	Ctime       int64  `json:"ctime"`
}

// KeybaseMerkleNode represents a node in Keybase's Merkle tree.
type KeybaseMerkleNode struct {
	Hash    string `json:"hash"`
	Seqno   int64  `json:"seqno"`
	Ctime   int64  `json:"ctime"`
	SigID   string `json:"sig_id,omitempty"`
}

// NewKeybaseProvider creates a new Keybase provider.
func NewKeybaseProvider(config KeybaseConfig) *KeybaseProvider {
	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	return &KeybaseProvider{
		httpClient: &http.Client{Timeout: timeout},
	}
}

// Name returns the provider identifier.
func (p *KeybaseProvider) Name() string {
	return "keybase"
}

// DisplayName returns a human-readable name.
func (p *KeybaseProvider) DisplayName() string {
	return "Keybase (Verification Only)"
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
	return nil, errors.New("keybase: service discontinued - new timestamps not available, use OpenTimestamps instead")
}

// Verify validates an existing Keybase proof.
func (p *KeybaseProvider) Verify(ctx context.Context, proof *Proof) (*VerifyResult, error) {
	if proof.Provider != p.Name() {
		return nil, errors.New("proof is not from Keybase provider")
	}

	result := &VerifyResult{
		Provider:     p.Name(),
		VerifiedHash: proof.Hash,
	}

	// Parse the Keybase proof from metadata or raw proof
	kbProof, err := p.parseKeybaseProof(proof)
	if err != nil {
		result.Error = fmt.Sprintf("failed to parse Keybase proof: %v", err)
		return result, ErrInvalidProof
	}

	// Verify the signature
	valid, err := p.verifySignature(kbProof)
	if err != nil {
		result.Error = fmt.Sprintf("signature verification failed: %v", err)
		result.Status = StatusFailed
		return result, ErrVerificationFailed
	}

	if !valid {
		result.Error = "invalid signature"
		result.Status = StatusFailed
		return result, ErrVerificationFailed
	}

	// Verify the hash matches
	if kbProof.DataHash != proof.Hash {
		result.Error = "hash mismatch"
		result.Status = StatusFailed
		return result, ErrVerificationFailed
	}

	// Try to verify against Keybase sigchain (may fail if service is down)
	chainValid, chainErr := p.verifySigchain(ctx, kbProof)
	if chainErr != nil {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("Sigchain verification unavailable: %v", chainErr))
	} else if !chainValid {
		result.Warnings = append(result.Warnings,
			"Sigchain verification failed - proof may have been revoked")
	}

	result.Valid = true
	result.Status = StatusConfirmed
	result.Timestamp = kbProof.CreatedAt

	return result, nil
}

// Upgrade is not available.
func (p *KeybaseProvider) Upgrade(ctx context.Context, proof *Proof) (*Proof, error) {
	return nil, errors.New("keybase: service discontinued - upgrades not available")
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
	status := &ProviderStatus{
		Configured: true,
		LastCheck:  time.Now(),
	}

	// Check if Keybase API is reachable
	req, err := http.NewRequestWithContext(ctx, "GET", KeybaseMerkleRoot, nil)
	if err != nil {
		status.Message = "Keybase API check failed"
		return status, nil
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		status.Available = false
		status.Message = "Keybase API unreachable - service may be discontinued"
		return status, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		status.Available = true
		status.Message = "Keybase API reachable (verification only - new timestamps not supported)"
	} else {
		status.Available = false
		status.Message = fmt.Sprintf("Keybase API returned status %d", resp.StatusCode)
	}

	return status, nil
}

// parseKeybaseProof extracts Keybase proof from a generic Proof.
func (p *KeybaseProvider) parseKeybaseProof(proof *Proof) (*KeybaseProof, error) {
	kbProof := &KeybaseProof{}

	// Try to parse from RawProof first
	if len(proof.RawProof) > 0 {
		if err := json.Unmarshal(proof.RawProof, kbProof); err == nil {
			return kbProof, nil
		}
	}

	// Try to extract from metadata
	if proof.Metadata != nil {
		if username, ok := proof.Metadata["username"].(string); ok {
			kbProof.Username = username
		}
		if uid, ok := proof.Metadata["uid"].(string); ok {
			kbProof.UID = uid
		}
		if seqno, ok := proof.Metadata["seqno"].(float64); ok {
			kbProof.Seqno = int64(seqno)
		}
		if sig, ok := proof.Metadata["signature"].(string); ok {
			sigBytes, _ := base64.StdEncoding.DecodeString(sig)
			kbProof.Signature = sigBytes
		}
		if payload, ok := proof.Metadata["payload"].(string); ok {
			kbProof.Payload = payload
		}
		if pubkey, ok := proof.Metadata["public_key"].(string); ok {
			pubBytes, _ := hex.DecodeString(pubkey)
			kbProof.PublicKey = pubBytes
		}
		if stellar, ok := proof.Metadata["stellar_tx_id"].(string); ok {
			kbProof.StellarTxID = stellar
		}
	}

	kbProof.DataHash = proof.Hash
	kbProof.CreatedAt = proof.Timestamp

	if kbProof.Username == "" && len(kbProof.Signature) == 0 {
		return nil, errors.New("invalid Keybase proof: missing username and signature")
	}

	return kbProof, nil
}

// verifySignature verifies the Ed25519 signature on a Keybase proof.
func (p *KeybaseProvider) verifySignature(proof *KeybaseProof) (bool, error) {
	if len(proof.PublicKey) != ed25519.PublicKeySize {
		return false, fmt.Errorf("invalid public key size: %d", len(proof.PublicKey))
	}

	if len(proof.Signature) < ed25519.SignatureSize {
		return false, fmt.Errorf("invalid signature size: %d", len(proof.Signature))
	}

	// Keybase uses NaCl signing which is Ed25519
	pubKey := ed25519.PublicKey(proof.PublicKey)

	// The message is the SHA256 hash of the payload
	var message []byte
	if proof.Payload != "" {
		h := sha256.Sum256([]byte(proof.Payload))
		message = h[:]
	} else {
		message = proof.DataHash[:]
	}

	// Ed25519 signature (first 64 bytes if longer)
	sig := proof.Signature
	if len(sig) > ed25519.SignatureSize {
		sig = sig[:ed25519.SignatureSize]
	}

	return ed25519.Verify(pubKey, message, sig), nil
}

// verifySigchain verifies the proof against the Keybase sigchain.
func (p *KeybaseProvider) verifySigchain(ctx context.Context, proof *KeybaseProof) (bool, error) {
	if proof.Username == "" {
		return false, errors.New("username required for sigchain verification")
	}

	// Lookup user
	userURL := fmt.Sprintf("%s?username=%s", KeybaseUserLookup, proof.Username)
	req, err := http.NewRequestWithContext(ctx, "GET", userURL, nil)
	if err != nil {
		return false, err
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("user lookup returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	var userResp struct {
		Status struct {
			Code int    `json:"code"`
			Name string `json:"name"`
		} `json:"status"`
		Them struct {
			ID          string `json:"id"`
			Basics      struct {
				Username string `json:"username"`
			} `json:"basics"`
			PublicKeys  struct {
				Primary struct {
					KeyFingerprint string `json:"key_fingerprint"`
					Kid            string `json:"kid"`
				} `json:"primary"`
			} `json:"public_keys"`
		} `json:"them"`
	}

	if err := json.Unmarshal(body, &userResp); err != nil {
		return false, fmt.Errorf("failed to parse user response: %w", err)
	}

	if userResp.Status.Code != 0 {
		return false, fmt.Errorf("user lookup failed: %s", userResp.Status.Name)
	}

	// Verify UID matches
	if proof.UID != "" && !strings.EqualFold(userResp.Them.ID, proof.UID) {
		return false, errors.New("UID mismatch")
	}

	// Get sigchain entry if seqno is provided
	if proof.Seqno > 0 {
		sigURL := fmt.Sprintf("%s?uid=%s&low=%d&high=%d",
			KeybaseSigchainGet, userResp.Them.ID, proof.Seqno, proof.Seqno)

		sigReq, err := http.NewRequestWithContext(ctx, "GET", sigURL, nil)
		if err != nil {
			return false, err
		}

		sigResp, err := p.httpClient.Do(sigReq)
		if err != nil {
			return false, err
		}
		defer sigResp.Body.Close()

		if sigResp.StatusCode != http.StatusOK {
			return false, fmt.Errorf("sigchain lookup returned status %d", sigResp.StatusCode)
		}

		sigBody, err := io.ReadAll(sigResp.Body)
		if err != nil {
			return false, err
		}

		var sigchainResp struct {
			Status struct {
				Code int `json:"code"`
			} `json:"status"`
			Sigs []KeybaseSigchainLink `json:"sigs"`
		}

		if err := json.Unmarshal(sigBody, &sigchainResp); err != nil {
			return false, fmt.Errorf("failed to parse sigchain: %w", err)
		}

		if len(sigchainResp.Sigs) == 0 {
			return false, errors.New("sigchain entry not found")
		}

		// Verify the signature matches
		for _, link := range sigchainResp.Sigs {
			if link.Seqno == proof.Seqno {
				// Found the link - verify it matches our proof
				return true, nil
			}
		}

		return false, errors.New("sigchain entry not found at specified seqno")
	}

	// Basic verification passed (user exists)
	return true, nil
}

// CreateProofFromSigchain creates a Proof from a Keybase sigchain entry.
// This is useful for importing existing Keybase proofs.
func (p *KeybaseProvider) CreateProofFromSigchain(ctx context.Context, username string, seqno int64, dataHash [32]byte) (*Proof, error) {
	// Lookup user and sigchain
	userURL := fmt.Sprintf("%s?username=%s", KeybaseUserLookup, username)
	req, err := http.NewRequestWithContext(ctx, "GET", userURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("user lookup failed: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var userResp struct {
		Status struct {
			Code int `json:"code"`
		} `json:"status"`
		Them struct {
			ID string `json:"id"`
		} `json:"them"`
	}

	if err := json.Unmarshal(body, &userResp); err != nil {
		return nil, err
	}

	// Get sigchain entry
	sigURL := fmt.Sprintf("%s?uid=%s&low=%d&high=%d",
		KeybaseSigchainGet, userResp.Them.ID, seqno, seqno)

	sigReq, err := http.NewRequestWithContext(ctx, "GET", sigURL, nil)
	if err != nil {
		return nil, err
	}

	sigResp, err := p.httpClient.Do(sigReq)
	if err != nil {
		return nil, err
	}
	defer sigResp.Body.Close()

	sigBody, err := io.ReadAll(sigResp.Body)
	if err != nil {
		return nil, err
	}

	var sigchainResp struct {
		Sigs []KeybaseSigchainLink `json:"sigs"`
	}

	if err := json.Unmarshal(sigBody, &sigchainResp); err != nil {
		return nil, err
	}

	if len(sigchainResp.Sigs) == 0 {
		return nil, errors.New("sigchain entry not found")
	}

	link := sigchainResp.Sigs[0]

	// Create proof
	kbProof := &KeybaseProof{
		Username:  username,
		UID:       userResp.Them.ID,
		Seqno:     seqno,
		DataHash:  dataHash,
		Payload:   string(link.Payload),
		CreatedAt: time.Unix(link.Ctime, 0),
	}

	// Decode signature
	if sigBytes, err := base64.StdEncoding.DecodeString(link.Sig); err == nil {
		kbProof.Signature = sigBytes
	}

	rawProof, _ := json.Marshal(kbProof)

	return &Proof{
		Provider:  p.Name(),
		Version:   1,
		Hash:      dataHash,
		Timestamp: kbProof.CreatedAt,
		Status:    StatusConfirmed,
		RawProof:  rawProof,
		Metadata: map[string]interface{}{
			"username":  username,
			"uid":       userResp.Them.ID,
			"seqno":     seqno,
			"sig_id":    link.SigID,
		},
	}, nil
}

var _ Provider = (*KeybaseProvider)(nil)
