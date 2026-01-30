package keystroke

import (
	"context"
	"sync"
	"testing"
	"time"
)

// =============================================================================
// Tests for BaseCounter
// =============================================================================

func TestBaseCounterCount(t *testing.T) {
	bc := &BaseCounter{}

	if bc.Count() != 0 {
		t.Error("initial count should be 0")
	}

	bc.Increment()
	bc.Increment()
	bc.Increment()

	if bc.Count() != 3 {
		t.Errorf("expected count 3, got %d", bc.Count())
	}
}

func TestBaseCounterIncrement(t *testing.T) {
	bc := &BaseCounter{}

	for i := 0; i < 100; i++ {
		bc.Increment()
	}

	if bc.Count() != 100 {
		t.Errorf("expected count 100, got %d", bc.Count())
	}
}

func TestBaseCounterIncrementConcurrent(t *testing.T) {
	bc := &BaseCounter{}
	var wg sync.WaitGroup

	// Concurrent increments
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				bc.Increment()
			}
		}()
	}

	wg.Wait()

	if bc.Count() != 1000 {
		t.Errorf("expected count 1000, got %d", bc.Count())
	}
}

func TestBaseCounterSubscribe(t *testing.T) {
	bc := &BaseCounter{}

	ch := bc.Subscribe(5)
	if ch == nil {
		t.Fatal("Subscribe returned nil channel")
	}

	// Increment 5 times - should trigger event
	for i := 0; i < 5; i++ {
		bc.Increment()
	}

	select {
	case event := <-ch:
		if event.Count != 5 {
			t.Errorf("expected count 5, got %d", event.Count)
		}
		if event.Timestamp.IsZero() {
			t.Error("timestamp should not be zero")
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("expected event on channel")
	}
}

func TestBaseCounterSubscribeMultipleListeners(t *testing.T) {
	bc := &BaseCounter{}

	ch5 := bc.Subscribe(5)
	ch10 := bc.Subscribe(10)

	// Increment 10 times
	for i := 0; i < 10; i++ {
		bc.Increment()
	}

	// ch5 should have received 2 events (at 5 and 10)
	// ch10 should have received 1 event (at 10)
	select {
	case event := <-ch5:
		if event.Count < 5 {
			t.Errorf("expected count >= 5, got %d", event.Count)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("expected event on ch5")
	}

	select {
	case event := <-ch10:
		if event.Count < 10 {
			t.Errorf("expected count >= 10, got %d", event.Count)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("expected event on ch10")
	}
}

func TestBaseCounterCloseListeners(t *testing.T) {
	bc := &BaseCounter{}

	ch := bc.Subscribe(1)
	bc.CloseListeners()

	// Channel should be closed
	_, ok := <-ch
	if ok {
		t.Error("channel should be closed")
	}
}

func TestBaseCounterRunningState(t *testing.T) {
	bc := &BaseCounter{}

	if bc.IsRunning() {
		t.Error("initial running state should be false")
	}

	bc.SetRunning(true)
	if !bc.IsRunning() {
		t.Error("running state should be true")
	}

	bc.SetRunning(false)
	if bc.IsRunning() {
		t.Error("running state should be false")
	}
}

// =============================================================================
// Tests for SimulatedCounter
// =============================================================================

func TestSimulatedCounterNew(t *testing.T) {
	sc := NewSimulated()
	if sc == nil {
		t.Fatal("NewSimulated returned nil")
	}
}

func TestSimulatedCounterStart(t *testing.T) {
	sc := NewSimulated()
	ctx := context.Background()

	err := sc.Start(ctx)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	if !sc.IsRunning() {
		t.Error("should be running after Start")
	}
}

func TestSimulatedCounterStartAlreadyRunning(t *testing.T) {
	sc := NewSimulated()
	ctx := context.Background()

	sc.Start(ctx)
	err := sc.Start(ctx)

	if err != ErrAlreadyRunning {
		t.Errorf("expected ErrAlreadyRunning, got %v", err)
	}
}

func TestSimulatedCounterStop(t *testing.T) {
	sc := NewSimulated()
	ctx := context.Background()

	sc.Start(ctx)
	err := sc.Stop()

	if err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	if sc.IsRunning() {
		t.Error("should not be running after Stop")
	}
}

func TestSimulatedCounterStopNotRunning(t *testing.T) {
	sc := NewSimulated()

	err := sc.Stop()
	if err != nil {
		t.Errorf("Stop on non-running counter should not error: %v", err)
	}
}

func TestSimulatedCounterSimulateKeystroke(t *testing.T) {
	sc := NewSimulated()
	ctx := context.Background()

	// Keystrokes before start should not count
	sc.SimulateKeystroke()
	if sc.Count() != 0 {
		t.Error("keystrokes before start should not count")
	}

	sc.Start(ctx)

	sc.SimulateKeystroke()
	if sc.Count() != 1 {
		t.Errorf("expected count 1, got %d", sc.Count())
	}

	sc.SimulateKeystroke()
	sc.SimulateKeystroke()
	if sc.Count() != 3 {
		t.Errorf("expected count 3, got %d", sc.Count())
	}
}

func TestSimulatedCounterSimulateKeystrokes(t *testing.T) {
	sc := NewSimulated()
	ctx := context.Background()

	sc.Start(ctx)
	sc.SimulateKeystrokes(50)

	if sc.Count() != 50 {
		t.Errorf("expected count 50, got %d", sc.Count())
	}
}

func TestSimulatedCounterAvailable(t *testing.T) {
	sc := NewSimulated()

	available, msg := sc.Available()
	if !available {
		t.Error("simulated counter should always be available")
	}
	if msg == "" {
		t.Error("should have availability message")
	}
}

func TestSimulatedCounterSubscribeWithEvents(t *testing.T) {
	sc := NewSimulated()
	ctx := context.Background()

	sc.Start(ctx)

	ch := sc.Subscribe(10)
	received := make(chan bool, 1)

	go func() {
		<-ch
		received <- true
	}()

	// Simulate 10 keystrokes
	sc.SimulateKeystrokes(10)

	select {
	case <-received:
		// Success
	case <-time.After(100 * time.Millisecond):
		t.Error("expected event after 10 keystrokes")
	}
}

func TestSimulatedCounterStopClosesListeners(t *testing.T) {
	sc := NewSimulated()
	ctx := context.Background()

	sc.Start(ctx)
	ch := sc.Subscribe(1)

	sc.Stop()

	// Channel should be closed
	_, ok := <-ch
	if ok {
		t.Error("channel should be closed after Stop")
	}
}

// =============================================================================
// Tests for Event struct
// =============================================================================

func TestEvent(t *testing.T) {
	now := time.Now()
	event := Event{
		Count:     100,
		Timestamp: now,
	}

	if event.Count != 100 {
		t.Error("count mismatch")
	}
	if event.Timestamp != now {
		t.Error("timestamp mismatch")
	}
}

// =============================================================================
// Tests for error constants
// =============================================================================

func TestErrors(t *testing.T) {
	errors := []error{
		ErrNotAvailable,
		ErrPermissionDenied,
		ErrAlreadyRunning,
	}

	for _, err := range errors {
		if err.Error() == "" {
			t.Errorf("error %v should have message", err)
		}
	}
}

// =============================================================================
// Tests for New() function
// =============================================================================

func TestNew(t *testing.T) {
	counter := New()
	if counter == nil {
		t.Fatal("New returned nil")
	}
}

// =============================================================================
// Integration tests
// =============================================================================

func TestSimulatedCounterWorkflow(t *testing.T) {
	sc := NewSimulated()
	ctx := context.Background()

	// Start session
	if err := sc.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Subscribe for events
	ch := sc.Subscribe(20)

	// Simulate typing
	for i := 0; i < 5; i++ {
		sc.SimulateKeystrokes(10)
		time.Sleep(10 * time.Millisecond)
	}

	// Should have received events
	eventCount := 0
	timeout := time.After(100 * time.Millisecond)
loop:
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				break loop
			}
			eventCount++
		case <-timeout:
			break loop
		}
	}

	if eventCount < 2 {
		t.Errorf("expected at least 2 events, got %d", eventCount)
	}

	// Stop session
	if err := sc.Stop(); err != nil {
		t.Errorf("Stop failed: %v", err)
	}

	// Verify final count
	if sc.Count() != 50 {
		t.Errorf("expected final count 50, got %d", sc.Count())
	}
}

func TestSimulatedCounterContextCancellation(t *testing.T) {
	sc := NewSimulated()
	ctx, cancel := context.WithCancel(context.Background())

	sc.Start(ctx)

	// Cancel context
	cancel()

	// Counter should still be running (Start stored its own context)
	// But the external context was used
	if !sc.IsRunning() {
		t.Skip("Implementation may or may not stop on parent context cancellation")
	}
}

// =============================================================================
// Tests for listener behavior
// =============================================================================

func TestListenerChannelFull(t *testing.T) {
	bc := &BaseCounter{}

	// Create listener with small buffer
	bc.Subscribe(1)

	// Flood with increments - should not block
	done := make(chan bool)
	go func() {
		for i := 0; i < 100; i++ {
			bc.Increment()
		}
		done <- true
	}()

	select {
	case <-done:
		// Good - didn't block
	case <-time.After(1 * time.Second):
		t.Error("Increment blocked when channel was full")
	}
}

func TestMultipleSubscribersIndependent(t *testing.T) {
	bc := &BaseCounter{}

	// Subscribe at different intervals
	ch1 := bc.Subscribe(1)
	ch2 := bc.Subscribe(100)

	// Increment a few times
	for i := 0; i < 5; i++ {
		bc.Increment()
	}

	// ch1 should have events, ch2 should not yet
	select {
	case <-ch1:
		// Expected
	case <-time.After(100 * time.Millisecond):
		t.Error("ch1 should have received events")
	}

	select {
	case <-ch2:
		t.Error("ch2 should not have received events yet")
	default:
		// Expected - no events yet
	}
}

// =============================================================================
// Tests for Counter Interface Polymorphism (Fix #4)
// =============================================================================

// TestCounterInterfaceSimulated verifies that SimulatedCounter correctly
// implements the Counter interface.
func TestCounterInterfaceSimulated(t *testing.T) {
	var counter Counter = NewSimulated()

	// Verify all interface methods work
	ctx := context.Background()

	// Start
	err := counter.Start(ctx)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Count
	initialCount := counter.Count()
	if initialCount != 0 {
		t.Errorf("expected initial count 0, got %d", initialCount)
	}

	// Subscribe
	ch := counter.Subscribe(5)
	if ch == nil {
		t.Error("Subscribe should return a channel")
	}

	// Available
	available, msg := counter.Available()
	if !available {
		t.Error("SimulatedCounter should always be available")
	}
	if msg == "" {
		t.Error("availability message should not be empty")
	}

	// Stop
	err = counter.Stop()
	if err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
}

// TestCounterInterfacePolymorphism verifies that code written against
// the Counter interface works with different implementations.
func TestCounterInterfacePolymorphism(t *testing.T) {
	// This test simulates how SecureTrackingSession uses the Counter interface
	type sessionLike struct {
		counter Counter
	}

	// Test with simulated counter
	session := &sessionLike{
		counter: NewSimulated(),
	}

	ctx := context.Background()

	// Start the counter
	if err := session.counter.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Subscribe for events
	ch := session.counter.Subscribe(10)

	// Simulate some activity (via type assertion for SimulatedCounter)
	if sc, ok := session.counter.(*SimulatedCounter); ok {
		sc.SimulateKeystrokes(15)
	}

	// Verify count
	count := session.counter.Count()
	if count != 15 {
		t.Errorf("expected count 15, got %d", count)
	}

	// Verify event received
	select {
	case event := <-ch:
		if event.Count < 10 {
			t.Errorf("expected event count >= 10, got %d", event.Count)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("expected to receive an event")
	}

	// Stop the counter
	if err := session.counter.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
}

// TestCounterTypeAssertion verifies that type assertions work correctly
// for accessing implementation-specific methods.
func TestCounterTypeAssertion(t *testing.T) {
	var counter Counter = NewSimulated()

	// Type assertion to SimulatedCounter should succeed
	sc, ok := counter.(*SimulatedCounter)
	if !ok {
		t.Fatal("type assertion to *SimulatedCounter should succeed")
	}

	// SimulatedCounter-specific method should work
	ctx := context.Background()
	sc.Start(ctx)
	sc.SimulateKeystroke() // This method is not on Counter interface
	if sc.Count() != 1 {
		t.Error("SimulateKeystroke should have incremented count")
	}
	sc.Stop()
}

// TestCounterInterfaceNilCheck verifies interface nil checks work correctly.
func TestCounterInterfaceNilCheck(t *testing.T) {
	var counter Counter

	// Nil interface check
	if counter != nil {
		t.Error("uninitialized Counter should be nil")
	}

	// Assign a value
	counter = NewSimulated()
	if counter == nil {
		t.Error("assigned Counter should not be nil")
	}
}
