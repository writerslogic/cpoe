// Package evidence integration with external anchors.

package evidence

import (
	"context"
	"encoding/hex"
	"time"

	"witnessd/pkg/anchors"
)

// AnchorManager handles external timestamp anchoring for evidence.
type AnchorManager struct {
	registry *anchors.Registry
	timeout  time.Duration
}

// NewAnchorManager creates an anchor manager with the given registry.
// If registry is nil, uses the default registry.
func NewAnchorManager(registry *anchors.Registry) *AnchorManager {
	if registry == nil {
		registry = anchors.DefaultRegistry
	}
	return &AnchorManager{
		registry: registry,
		timeout:  30 * time.Second,
	}
}

// SetTimeout sets the timeout for anchor operations.
func (m *AnchorManager) SetTimeout(d time.Duration) {
	m.timeout = d
}

// EnableProvider enables a provider for anchoring.
func (m *AnchorManager) EnableProvider(name string) error {
	return m.registry.Enable(name, nil)
}

// EnableProviderWithConfig enables a provider with configuration.
func (m *AnchorManager) EnableProviderWithConfig(name string, config map[string]interface{}) error {
	return m.registry.Enable(name, config)
}

// EnableFreeProviders enables all providers that don't require payment.
func (m *AnchorManager) EnableFreeProviders() {
	for _, p := range m.registry.FreeProviders() {
		if !p.RequiresCredentials() {
			m.registry.Enable(p.Name(), nil)
		}
	}
}

// ListEnabled returns names of enabled providers.
func (m *AnchorManager) ListEnabled() []string {
	var names []string
	for _, p := range m.registry.EnabledProviders() {
		names = append(names, p.Name())
	}
	return names
}

// AnchorChain submits the chain hash to all enabled providers.
// Returns proofs for all successful submissions.
func (m *AnchorManager) AnchorChain(chainHash [32]byte) ([]*anchors.Proof, error) {
	ctx, cancel := context.WithTimeout(context.Background(), m.timeout)
	defer cancel()

	return m.registry.Timestamp(ctx, chainHash)
}

// AnchorChainAsync submits to providers asynchronously and returns immediately.
// Results can be retrieved later using UpgradeProofs.
func (m *AnchorManager) AnchorChainAsync(chainHash [32]byte) chan *AnchorResult {
	resultChan := make(chan *AnchorResult, len(m.registry.EnabledProviders()))

	go func() {
		defer close(resultChan)

		ctx, cancel := context.WithTimeout(context.Background(), m.timeout)
		defer cancel()

		proofs, err := m.registry.Timestamp(ctx, chainHash)
		resultChan <- &AnchorResult{
			Proofs: proofs,
			Error:  err,
		}
	}()

	return resultChan
}

// AnchorResult contains the result of an anchor operation.
type AnchorResult struct {
	Proofs []*anchors.Proof
	Error  error
}

// UpgradeProofs attempts to upgrade pending proofs to confirmed status.
func (m *AnchorManager) UpgradeProofs(proofs []*anchors.Proof) ([]*anchors.Proof, error) {
	ctx, cancel := context.WithTimeout(context.Background(), m.timeout)
	defer cancel()

	return m.registry.Upgrade(ctx, proofs)
}

// VerifyProof verifies a single proof.
func (m *AnchorManager) VerifyProof(proof *anchors.Proof) (*anchors.VerifyResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), m.timeout)
	defer cancel()

	return m.registry.Verify(ctx, proof)
}

// AddAnchorsToBuilder adds anchor proofs to an evidence builder.
// Convenience function for integrating anchors into evidence.
func AddAnchorsToBuilder(builder *Builder, proofs []*anchors.Proof) *Builder {
	return builder.WithAnchors(proofs)
}

// AnchorAndBuild anchors the chain hash and adds proofs to the evidence.
// This is a convenience function that combines anchoring and building.
func AnchorAndBuild(builder *Builder, chainHash string, mgr *AnchorManager) (*Packet, error) {
	// Parse chain hash
	hashBytes, err := hex.DecodeString(chainHash)
	if err != nil {
		// If hash parsing fails, just build without anchors
		return builder.Build()
	}

	var hash [32]byte
	copy(hash[:], hashBytes)

	// Try to anchor
	proofs, err := mgr.AnchorChain(hash)
	if err != nil {
		// Anchoring failed, but we can still build
		return builder.Build()
	}

	// Add proofs and build
	return builder.WithAnchors(proofs).Build()
}
