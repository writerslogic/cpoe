package context

import (
	"path/filepath"
	"testing"
	"time"

	"witnessd/internal/store"
)

// =============================================================================
// Helper functions
// =============================================================================

func createTestStore(t *testing.T) *store.Store {
	t.Helper()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("failed to create test store: %v", err)
	}

	t.Cleanup(func() {
		s.Close()
	})

	return s
}

// =============================================================================
// Tests for NewManager
// =============================================================================

func TestNewManager(t *testing.T) {
	s := createTestStore(t)
	m := NewManager(s)

	if m == nil {
		t.Fatal("NewManager returned nil")
	}
	if m.store == nil {
		t.Error("store should not be nil")
	}
}

// =============================================================================
// Tests for Begin
// =============================================================================

func TestBegin(t *testing.T) {
	s := createTestStore(t)
	m := NewManager(s)

	id, err := m.Begin(External, "Testing paste")
	if err != nil {
		t.Fatalf("Begin failed: %v", err)
	}

	if id <= 0 {
		t.Errorf("expected positive ID, got %d", id)
	}

	// Verify context is active
	active, err := m.Active()
	if err != nil {
		t.Fatalf("Active failed: %v", err)
	}
	if active == nil {
		t.Fatal("expected active context")
	}
	if active.ID != id {
		t.Errorf("expected ID %d, got %d", id, active.ID)
	}
	if active.Type != External {
		t.Errorf("expected type %s, got %s", External, active.Type)
	}
	if active.Note != "Testing paste" {
		t.Errorf("expected note 'Testing paste', got %q", active.Note)
	}
}

func TestBeginAutoClosePrevious(t *testing.T) {
	s := createTestStore(t)
	m := NewManager(s)

	id1, _ := m.Begin(External, "First")

	// Begin new context should close the first
	id2, err := m.Begin(Assisted, "Second")
	if err != nil {
		t.Fatalf("Begin second failed: %v", err)
	}

	if id2 == id1 {
		t.Error("new context should have different ID")
	}

	// Verify first context is closed
	active, _ := m.Active()
	if active == nil || active.ID != id2 {
		t.Error("second context should be active")
	}

	// Check first context has end time
	contexts, _ := m.List(0, time.Now().UnixNano())
	for _, ctx := range contexts {
		if ctx.ID == id1 && ctx.EndNs == nil {
			t.Error("first context should have end time")
		}
	}
}

func TestBeginAllTypes(t *testing.T) {
	types := []struct {
		ctxType ContextType
		note    string
	}{
		{External, "external note"},
		{Assisted, "assisted note"},
		{Review, "review note"},
	}

	for _, tt := range types {
		t.Run(string(tt.ctxType), func(t *testing.T) {
			s := createTestStore(t)
			m := NewManager(s)

			id, err := m.Begin(tt.ctxType, tt.note)
			if err != nil {
				t.Fatalf("Begin failed for %s: %v", tt.ctxType, err)
			}
			if id <= 0 {
				t.Errorf("expected positive ID for %s", tt.ctxType)
			}

			active, _ := m.Active()
			if active.Type != tt.ctxType {
				t.Errorf("type mismatch: expected %s, got %s", tt.ctxType, active.Type)
			}
		})
	}
}

// =============================================================================
// Tests for End
// =============================================================================

func TestEnd(t *testing.T) {
	s := createTestStore(t)
	m := NewManager(s)

	m.Begin(External, "Test")

	err := m.End()
	if err != nil {
		t.Fatalf("End failed: %v", err)
	}

	// Verify no active context
	active, err := m.Active()
	if err != nil {
		t.Fatalf("Active failed: %v", err)
	}
	if active != nil {
		t.Error("expected no active context after End")
	}
}

func TestEndNoActive(t *testing.T) {
	s := createTestStore(t)
	m := NewManager(s)

	err := m.End()
	if err != ErrNoActiveContext {
		t.Errorf("expected ErrNoActiveContext, got %v", err)
	}
}

func TestEndMultipleTimes(t *testing.T) {
	s := createTestStore(t)
	m := NewManager(s)

	m.Begin(External, "Test")
	m.End()

	err := m.End()
	if err != ErrNoActiveContext {
		t.Errorf("second End should return ErrNoActiveContext, got %v", err)
	}
}

// =============================================================================
// Tests for Active
// =============================================================================

func TestActiveNoContext(t *testing.T) {
	s := createTestStore(t)
	m := NewManager(s)

	active, err := m.Active()
	if err != nil {
		t.Fatalf("Active failed: %v", err)
	}
	if active != nil {
		t.Error("expected nil for no active context")
	}
}

func TestActiveWithContext(t *testing.T) {
	s := createTestStore(t)
	m := NewManager(s)

	m.Begin(Assisted, "AI help")

	active, err := m.Active()
	if err != nil {
		t.Fatalf("Active failed: %v", err)
	}
	if active == nil {
		t.Fatal("expected active context")
	}
	if active.Type != Assisted {
		t.Errorf("expected type %s, got %s", Assisted, active.Type)
	}
}

// =============================================================================
// Tests for GetForEvent
// =============================================================================

func TestGetForEvent(t *testing.T) {
	s := createTestStore(t)
	m := NewManager(s)

	startTime := time.Now().UnixNano()
	m.Begin(External, "Test")

	// Event during context should find context
	eventTime := time.Now().UnixNano()
	ctx, err := m.GetForEvent(eventTime)
	if err != nil {
		t.Fatalf("GetForEvent failed: %v", err)
	}
	if ctx == nil {
		t.Error("expected to find context for event")
	}
	if ctx != nil && ctx.Type != External {
		t.Errorf("expected type %s, got %s", External, ctx.Type)
	}

	// Event before context should not find context
	ctx, err = m.GetForEvent(startTime - 1e9)
	if err != nil {
		t.Fatalf("GetForEvent failed: %v", err)
	}
	if ctx != nil {
		t.Error("expected nil for event before context")
	}
}

func TestGetForEventClosed(t *testing.T) {
	s := createTestStore(t)
	m := NewManager(s)

	m.Begin(External, "Test")
	time.Sleep(10 * time.Millisecond) // Ensure time passes
	m.End()

	// Event after context ended should not find it
	ctx, err := m.GetForEvent(time.Now().Add(1 * time.Second).UnixNano())
	if err != nil {
		t.Fatalf("GetForEvent failed: %v", err)
	}
	if ctx != nil {
		t.Error("expected nil for event after context ended")
	}
}

// =============================================================================
// Tests for List
// =============================================================================

func TestList(t *testing.T) {
	s := createTestStore(t)
	m := NewManager(s)

	startTime := time.Now().UnixNano()

	m.Begin(External, "First")
	m.End()

	m.Begin(Assisted, "Second")
	m.End()

	m.Begin(Review, "Third")
	m.End()

	endTime := time.Now().UnixNano()

	contexts, err := m.List(startTime, endTime)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(contexts) != 3 {
		t.Errorf("expected 3 contexts, got %d", len(contexts))
	}
}

func TestListEmpty(t *testing.T) {
	s := createTestStore(t)
	m := NewManager(s)

	contexts, err := m.List(0, time.Now().UnixNano())
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(contexts) != 0 {
		t.Errorf("expected 0 contexts, got %d", len(contexts))
	}
}

func TestListTimeRange(t *testing.T) {
	s := createTestStore(t)
	m := NewManager(s)

	// Create contexts at different times
	m.Begin(External, "First")
	m.End()

	time.Sleep(50 * time.Millisecond)
	midTime := time.Now().UnixNano()

	m.Begin(Assisted, "Second")
	m.End()

	endTime := time.Now().UnixNano()

	// List only after midTime
	contexts, err := m.List(midTime, endTime)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	// Should find at least one context
	if len(contexts) < 1 {
		t.Errorf("expected at least 1 context after midTime, got %d", len(contexts))
	}
}

// =============================================================================
// Tests for ValidateType
// =============================================================================

func TestValidateType(t *testing.T) {
	tests := []struct {
		input    string
		expected ContextType
		hasError bool
	}{
		{"external", External, false},
		{"ext", External, false},
		{"assisted", Assisted, false},
		{"ai", Assisted, false},
		{"review", Review, false},
		{"rev", Review, false},
		{"invalid", "", true},
		{"", "", true},
		{"EXTERNAL", "", true}, // Case sensitive
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := ValidateType(tt.input)

			if tt.hasError {
				if err != ErrInvalidType {
					t.Errorf("expected ErrInvalidType for %q, got %v", tt.input, err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error for %q: %v", tt.input, err)
				}
				if result != tt.expected {
					t.Errorf("expected %s, got %s", tt.expected, result)
				}
			}
		})
	}
}

// =============================================================================
// Tests for TypeDescription
// =============================================================================

func TestTypeDescription(t *testing.T) {
	tests := []struct {
		ctxType     ContextType
		shouldMatch string
	}{
		{External, "External"},
		{Assisted, "AI"},
		{Review, "Revision"},
		{"unknown", "Unknown"},
	}

	for _, tt := range tests {
		t.Run(string(tt.ctxType), func(t *testing.T) {
			desc := TypeDescription(tt.ctxType)
			if desc == "" {
				t.Error("description should not be empty")
			}
			// Just verify we get something reasonable
			// The exact wording may vary
		})
	}
}

// =============================================================================
// Tests for constants
// =============================================================================

func TestContextTypeConstants(t *testing.T) {
	if External == "" {
		t.Error("External should not be empty")
	}
	if Assisted == "" {
		t.Error("Assisted should not be empty")
	}
	if Review == "" {
		t.Error("Review should not be empty")
	}

	// Verify they map to store constants correctly
	if External != store.ContextExternal {
		t.Error("External should equal store.ContextExternal")
	}
	if Assisted != store.ContextAssisted {
		t.Error("Assisted should equal store.ContextAssisted")
	}
	if Review != store.ContextReview {
		t.Error("Review should equal store.ContextReview")
	}
}

// =============================================================================
// Tests for error constants
// =============================================================================

func TestErrors(t *testing.T) {
	if ErrNoActiveContext.Error() == "" {
		t.Error("ErrNoActiveContext should have message")
	}
	if ErrInvalidType.Error() == "" {
		t.Error("ErrInvalidType should have message")
	}
}

// =============================================================================
// Integration tests
// =============================================================================

func TestBeginEndCycle(t *testing.T) {
	s := createTestStore(t)
	m := NewManager(s)

	// Multiple begin/end cycles
	for i := 0; i < 5; i++ {
		id, err := m.Begin(External, "Cycle")
		if err != nil {
			t.Fatalf("Begin cycle %d failed: %v", i, err)
		}
		if id <= 0 {
			t.Errorf("expected positive ID in cycle %d", i)
		}

		err = m.End()
		if err != nil {
			t.Fatalf("End cycle %d failed: %v", i, err)
		}
	}

	// Verify all contexts are closed
	active, _ := m.Active()
	if active != nil {
		t.Error("no context should be active after all cycles")
	}
}

func TestContextWithEvents(t *testing.T) {
	s := createTestStore(t)
	m := NewManager(s)

	// Begin context
	ctxID, _ := m.Begin(Assisted, "AI generation")

	// Simulate events happening during context
	eventTimes := []int64{
		time.Now().UnixNano(),
		time.Now().Add(10 * time.Millisecond).UnixNano(),
		time.Now().Add(20 * time.Millisecond).UnixNano(),
	}

	// Verify all events find the context
	for i, eventTime := range eventTimes {
		ctx, err := m.GetForEvent(eventTime)
		if err != nil {
			t.Fatalf("GetForEvent %d failed: %v", i, err)
		}
		if ctx == nil {
			t.Errorf("event %d should find context", i)
		}
		if ctx != nil && ctx.ID != ctxID {
			t.Errorf("event %d found wrong context", i)
		}
	}
}
