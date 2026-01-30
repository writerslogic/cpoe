package evidence

import (
	"testing"
	"time"

	"witnessd/pkg/anchors"
)

func TestNewAnchorManager(t *testing.T) {
	// Test with nil registry (should use default)
	mgr := NewAnchorManager(nil)
	if mgr == nil {
		t.Fatal("expected non-nil manager")
	}

	// Test with custom registry
	registry := anchors.NewRegistry()
	mgr2 := NewAnchorManager(registry)
	if mgr2 == nil {
		t.Fatal("expected non-nil manager")
	}
}

func TestAnchorManagerSetTimeout(t *testing.T) {
	mgr := NewAnchorManager(nil)

	mgr.SetTimeout(60 * time.Second)
	if mgr.timeout != 60*time.Second {
		t.Errorf("expected 60s timeout, got %v", mgr.timeout)
	}
}

func TestAnchorManagerListEnabled(t *testing.T) {
	registry := anchors.NewRegistry()
	registry.RegisterDefaults()

	mgr := NewAnchorManager(registry)

	// Initially no providers enabled
	enabled := mgr.ListEnabled()
	if len(enabled) != 0 {
		t.Errorf("expected 0 enabled providers, got %d", len(enabled))
	}
}

func TestAnchorManagerEnableProvider(t *testing.T) {
	registry := anchors.NewRegistry()
	registry.RegisterDefaults()

	mgr := NewAnchorManager(registry)

	// Enable opentimestamps
	err := mgr.EnableProvider("opentimestamps")
	if err != nil {
		t.Fatalf("failed to enable provider: %v", err)
	}

	enabled := mgr.ListEnabled()
	if len(enabled) != 1 {
		t.Errorf("expected 1 enabled provider, got %d", len(enabled))
	}
}

func TestAnchorManagerEnableFreeProviders(t *testing.T) {
	registry := anchors.NewRegistry()
	registry.RegisterDefaults()

	mgr := NewAnchorManager(registry)
	mgr.EnableFreeProviders()

	enabled := mgr.ListEnabled()
	// Should have at least opentimestamps and freetsa
	if len(enabled) < 2 {
		t.Errorf("expected at least 2 free providers, got %d", len(enabled))
	}
}

func TestAnchorManagerEnableInvalidProvider(t *testing.T) {
	registry := anchors.NewRegistry()
	mgr := NewAnchorManager(registry)

	err := mgr.EnableProvider("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent provider")
	}
}
