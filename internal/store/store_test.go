package store

import (
	"math"
	"path/filepath"
	"testing"
	"time"
)

func TestOpenAndClose(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	if err := s.Close(); err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

func TestOpenCreatesDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "subdir", "nested", "test.db")

	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer s.Close()
}

func TestCloseNilDB(t *testing.T) {
	s := &Store{db: nil}
	if err := s.Close(); err != nil {
		t.Errorf("Close on nil db should not error: %v", err)
	}
}

func TestInsertAndGetDevice(t *testing.T) {
	tmpDir := t.TempDir()
	s, err := Open(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer s.Close()

	device := &Device{
		DeviceID:      [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		CreatedAt:     time.Now().UnixNano(),
		SigningPubkey: [32]byte{0xaa, 0xbb, 0xcc},
		Hostname:      "test-host",
	}

	if err := s.InsertDevice(device); err != nil {
		t.Fatalf("InsertDevice failed: %v", err)
	}

	retrieved, err := s.GetDevice(device.DeviceID)
	if err != nil {
		t.Fatalf("GetDevice failed: %v", err)
	}
	if retrieved == nil {
		t.Fatal("GetDevice returned nil")
	}

	if retrieved.DeviceID != device.DeviceID {
		t.Error("DeviceID mismatch")
	}
	if retrieved.Hostname != device.Hostname {
		t.Errorf("Hostname mismatch: expected %s, got %s", device.Hostname, retrieved.Hostname)
	}
}

func TestGetDeviceNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	s, err := Open(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer s.Close()

	device, err := s.GetDevice([16]byte{0xff})
	if err != nil {
		t.Fatalf("GetDevice failed: %v", err)
	}
	if device != nil {
		t.Error("expected nil for nonexistent device")
	}
}

func TestInsertAndGetEvent(t *testing.T) {
	tmpDir := t.TempDir()
	s, err := Open(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer s.Close()

	// Insert device first (foreign key)
	device := &Device{
		DeviceID:      [16]byte{1, 2, 3},
		CreatedAt:     time.Now().UnixNano(),
		SigningPubkey: [32]byte{},
		Hostname:      "test",
	}
	if err := s.InsertDevice(device); err != nil {
		t.Fatalf("InsertDevice failed: %v", err)
	}

	event := &Event{
		DeviceID:    device.DeviceID,
		MMRIndex:    0,
		MMRLeafHash: [32]byte{0xde, 0xad},
		TimestampNs: time.Now().UnixNano(),
		FilePath:    "/test/file.txt",
		ContentHash: [32]byte{0xbe, 0xef},
		FileSize:    1024,
		SizeDelta:   100,
	}

	id, err := s.InsertEvent(event)
	if err != nil {
		t.Fatalf("InsertEvent failed: %v", err)
	}
	if id <= 0 {
		t.Error("expected positive event ID")
	}

	retrieved, err := s.GetEvent(id)
	if err != nil {
		t.Fatalf("GetEvent failed: %v", err)
	}
	if retrieved == nil {
		t.Fatal("GetEvent returned nil")
	}

	if retrieved.FilePath != event.FilePath {
		t.Errorf("FilePath mismatch: expected %s, got %s", event.FilePath, retrieved.FilePath)
	}
	if retrieved.FileSize != event.FileSize {
		t.Errorf("FileSize mismatch: expected %d, got %d", event.FileSize, retrieved.FileSize)
	}
}

func TestGetEventNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	s, err := Open(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer s.Close()

	event, err := s.GetEvent(99999)
	if err != nil {
		t.Fatalf("GetEvent failed: %v", err)
	}
	if event != nil {
		t.Error("expected nil for nonexistent event")
	}
}

func TestGetEventByMMRIndex(t *testing.T) {
	tmpDir := t.TempDir()
	s, err := Open(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer s.Close()

	device := &Device{DeviceID: [16]byte{1}, CreatedAt: time.Now().UnixNano()}
	s.InsertDevice(device)

	event := &Event{
		DeviceID:    device.DeviceID,
		MMRIndex:    42,
		TimestampNs: time.Now().UnixNano(),
		FilePath:    "/test.txt",
	}
	s.InsertEvent(event)

	retrieved, err := s.GetEventByMMRIndex(42)
	if err != nil {
		t.Fatalf("GetEventByMMRIndex failed: %v", err)
	}
	if retrieved == nil {
		t.Fatal("expected event, got nil")
	}
	if retrieved.MMRIndex != 42 {
		t.Errorf("expected MMRIndex 42, got %d", retrieved.MMRIndex)
	}
}

func TestGetEventsByFile(t *testing.T) {
	tmpDir := t.TempDir()
	s, err := Open(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer s.Close()

	device := &Device{DeviceID: [16]byte{1}, CreatedAt: time.Now().UnixNano()}
	s.InsertDevice(device)

	baseTime := time.Now().UnixNano()
	for i := 0; i < 5; i++ {
		event := &Event{
			DeviceID:    device.DeviceID,
			MMRIndex:    uint64(i),
			TimestampNs: baseTime + int64(i*1000000),
			FilePath:    "/test/file.txt",
		}
		s.InsertEvent(event)
	}

	// Also insert events for a different file
	for i := 5; i < 8; i++ {
		event := &Event{
			DeviceID:    device.DeviceID,
			MMRIndex:    uint64(i),
			TimestampNs: baseTime + int64(i*1000000),
			FilePath:    "/test/other.txt",
		}
		s.InsertEvent(event)
	}

	events, err := s.GetEventsByFile("/test/file.txt", baseTime, baseTime+10000000)
	if err != nil {
		t.Fatalf("GetEventsByFile failed: %v", err)
	}
	if len(events) != 5 {
		t.Errorf("expected 5 events, got %d", len(events))
	}
}

func TestGetEventRange(t *testing.T) {
	tmpDir := t.TempDir()
	s, err := Open(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer s.Close()

	device := &Device{DeviceID: [16]byte{1}, CreatedAt: time.Now().UnixNano()}
	s.InsertDevice(device)

	baseTime := int64(1000000000)
	for i := 0; i < 10; i++ {
		event := &Event{
			DeviceID:    device.DeviceID,
			MMRIndex:    uint64(i),
			TimestampNs: baseTime + int64(i*100),
			FilePath:    "/test.txt",
		}
		s.InsertEvent(event)
	}

	// Get middle range
	events, err := s.GetEventRange(baseTime+200, baseTime+700)
	if err != nil {
		t.Fatalf("GetEventRange failed: %v", err)
	}
	if len(events) != 6 { // indices 2,3,4,5,6,7
		t.Errorf("expected 6 events, got %d", len(events))
	}
}

func TestGetLastEventForFile(t *testing.T) {
	tmpDir := t.TempDir()
	s, err := Open(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer s.Close()

	device := &Device{DeviceID: [16]byte{1}, CreatedAt: time.Now().UnixNano()}
	s.InsertDevice(device)

	baseTime := time.Now().UnixNano()
	for i := 0; i < 5; i++ {
		event := &Event{
			DeviceID:    device.DeviceID,
			MMRIndex:    uint64(i),
			TimestampNs: baseTime + int64(i*1000),
			FilePath:    "/test.txt",
			FileSize:    int64(i * 100),
		}
		s.InsertEvent(event)
	}

	last, err := s.GetLastEventForFile("/test.txt")
	if err != nil {
		t.Fatalf("GetLastEventForFile failed: %v", err)
	}
	if last == nil {
		t.Fatal("expected event, got nil")
	}
	if last.FileSize != 400 {
		t.Errorf("expected FileSize 400, got %d", last.FileSize)
	}
}

func TestInsertAndGetEditRegions(t *testing.T) {
	tmpDir := t.TempDir()
	s, err := Open(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer s.Close()

	device := &Device{DeviceID: [16]byte{1}, CreatedAt: time.Now().UnixNano()}
	s.InsertDevice(device)

	event := &Event{
		DeviceID:    device.DeviceID,
		MMRIndex:    0,
		TimestampNs: time.Now().UnixNano(),
		FilePath:    "/test.txt",
	}
	eventID, _ := s.InsertEvent(event)

	regions := []EditRegion{
		{EventID: eventID, Ordinal: 0, StartPct: 0.0, EndPct: 0.25, DeltaSign: 1, ByteCount: 100},
		{EventID: eventID, Ordinal: 1, StartPct: 0.5, EndPct: 0.75, DeltaSign: -1, ByteCount: 50},
		{EventID: eventID, Ordinal: 2, StartPct: 0.9, EndPct: 1.0, DeltaSign: 1, ByteCount: 25},
	}

	if err := s.InsertEditRegions(eventID, regions); err != nil {
		t.Fatalf("InsertEditRegions failed: %v", err)
	}

	retrieved, err := s.GetEditRegions(eventID)
	if err != nil {
		t.Fatalf("GetEditRegions failed: %v", err)
	}
	if len(retrieved) != 3 {
		t.Errorf("expected 3 regions, got %d", len(retrieved))
	}

	// Verify order and values
	if retrieved[0].Ordinal != 0 || retrieved[0].ByteCount != 100 {
		t.Error("first region mismatch")
	}
	if retrieved[1].Ordinal != 1 || retrieved[1].DeltaSign != -1 {
		t.Error("second region mismatch")
	}
}

func TestContextOperations(t *testing.T) {
	tmpDir := t.TempDir()
	s, err := Open(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer s.Close()

	// Insert a context
	ctx := &Context{
		Type:    ContextExternal,
		Note:    "test paste",
		StartNs: time.Now().UnixNano(),
	}
	id, err := s.InsertContext(ctx)
	if err != nil {
		t.Fatalf("InsertContext failed: %v", err)
	}
	if id <= 0 {
		t.Error("expected positive context ID")
	}

	// Get active context
	active, err := s.GetActiveContext()
	if err != nil {
		t.Fatalf("GetActiveContext failed: %v", err)
	}
	if active == nil {
		t.Fatal("expected active context")
	}
	if active.Type != ContextExternal {
		t.Errorf("expected type external, got %s", active.Type)
	}
	if active.Note != "test paste" {
		t.Errorf("expected note 'test paste', got '%s'", active.Note)
	}

	// Close context
	endNs := time.Now().UnixNano()
	if err := s.CloseContext(id, endNs); err != nil {
		t.Fatalf("CloseContext failed: %v", err)
	}

	// No active context now
	active, err = s.GetActiveContext()
	if err != nil {
		t.Fatalf("GetActiveContext failed: %v", err)
	}
	if active != nil {
		t.Error("expected no active context after close")
	}
}

func TestCloseContextNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	s, err := Open(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer s.Close()

	err = s.CloseContext(99999, time.Now().UnixNano())
	if err == nil {
		t.Error("expected error for nonexistent context")
	}
}

func TestGetContextForTimestamp(t *testing.T) {
	tmpDir := t.TempDir()
	s, err := Open(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer s.Close()

	startNs := int64(1000000)
	endNs := int64(2000000)

	ctx := &Context{
		Type:    ContextAssisted,
		Note:    "AI help",
		StartNs: startNs,
	}
	id, _ := s.InsertContext(ctx)
	s.CloseContext(id, endNs)

	// Within range
	found, err := s.GetContextForTimestamp(1500000)
	if err != nil {
		t.Fatalf("GetContextForTimestamp failed: %v", err)
	}
	if found == nil {
		t.Fatal("expected to find context")
	}
	if found.Type != ContextAssisted {
		t.Errorf("expected type assisted, got %s", found.Type)
	}

	// Before range
	found, err = s.GetContextForTimestamp(500000)
	if err != nil {
		t.Fatalf("GetContextForTimestamp failed: %v", err)
	}
	if found != nil {
		t.Error("expected nil for timestamp before context")
	}

	// After range
	found, err = s.GetContextForTimestamp(3000000)
	if err != nil {
		t.Fatalf("GetContextForTimestamp failed: %v", err)
	}
	if found != nil {
		t.Error("expected nil for timestamp after context")
	}
}

func TestGetContextsInRange(t *testing.T) {
	tmpDir := t.TempDir()
	s, err := Open(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer s.Close()

	// Create multiple contexts
	// Context i: start=i*1000, end=i*1000+500
	// 0: [0, 500], 1: [1000, 1500], 2: [2000, 2500], 3: [3000, 3500], 4: [4000, 4500]
	for i := 0; i < 5; i++ {
		ctx := &Context{
			Type:    ContextReview,
			StartNs: int64(i * 1000),
		}
		id, _ := s.InsertContext(ctx)
		s.CloseContext(id, int64(i*1000+500))
	}

	// Query range [1000, 3500]
	// Overlapping contexts: 1 (1000-1500), 2 (2000-2500), 3 (3000-3500)
	// Context 0 ends at 500 < 1000, Context 4 starts at 4000 > 3500
	contexts, err := s.GetContextsInRange(1000, 3500)
	if err != nil {
		t.Fatalf("GetContextsInRange failed: %v", err)
	}
	if len(contexts) != 3 {
		t.Errorf("expected 3 contexts, got %d", len(contexts))
	}
}

func TestVerificationEntry(t *testing.T) {
	tmpDir := t.TempDir()
	s, err := Open(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer s.Close()

	regionsRoot := [32]byte{0xaa, 0xbb}
	entry := &VerificationEntry{
		MMRIndex:     100,
		LeafHash:     [32]byte{0x11, 0x22},
		MetadataHash: [32]byte{0x33, 0x44},
		RegionsRoot:  &regionsRoot,
	}

	if err := s.InsertVerificationEntry(entry); err != nil {
		t.Fatalf("InsertVerificationEntry failed: %v", err)
	}

	retrieved, err := s.GetVerificationEntry(100)
	if err != nil {
		t.Fatalf("GetVerificationEntry failed: %v", err)
	}
	if retrieved == nil {
		t.Fatal("expected entry, got nil")
	}

	if retrieved.MMRIndex != 100 {
		t.Errorf("MMRIndex mismatch")
	}
	if retrieved.RegionsRoot == nil {
		t.Error("expected RegionsRoot")
	} else if *retrieved.RegionsRoot != regionsRoot {
		t.Error("RegionsRoot mismatch")
	}
}

func TestVerificationEntryNilRegionsRoot(t *testing.T) {
	tmpDir := t.TempDir()
	s, err := Open(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer s.Close()

	entry := &VerificationEntry{
		MMRIndex:     200,
		LeafHash:     [32]byte{0x11},
		MetadataHash: [32]byte{0x22},
		RegionsRoot:  nil,
	}

	if err := s.InsertVerificationEntry(entry); err != nil {
		t.Fatalf("InsertVerificationEntry failed: %v", err)
	}

	retrieved, err := s.GetVerificationEntry(200)
	if err != nil {
		t.Fatalf("GetVerificationEntry failed: %v", err)
	}
	if retrieved.RegionsRoot != nil {
		t.Error("expected nil RegionsRoot")
	}
}

func TestWeaveOperations(t *testing.T) {
	tmpDir := t.TempDir()
	s, err := Open(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer s.Close()

	weave := &Weave{
		TimestampNs: time.Now().UnixNano(),
		DeviceRoots: map[string]string{
			"device1": "root1",
			"device2": "root2",
		},
		WeaveHash: [32]byte{0xaa, 0xbb},
		Signature: []byte("signature"),
	}

	id, err := s.InsertWeave(weave)
	if err != nil {
		t.Fatalf("InsertWeave failed: %v", err)
	}
	if id <= 0 {
		t.Error("expected positive weave ID")
	}

	retrieved, err := s.GetWeave(id)
	if err != nil {
		t.Fatalf("GetWeave failed: %v", err)
	}
	if retrieved == nil {
		t.Fatal("expected weave, got nil")
	}

	if len(retrieved.DeviceRoots) != 2 {
		t.Errorf("expected 2 device roots, got %d", len(retrieved.DeviceRoots))
	}
	if retrieved.DeviceRoots["device1"] != "root1" {
		t.Error("device1 root mismatch")
	}
	if retrieved.WeaveHash != weave.WeaveHash {
		t.Error("WeaveHash mismatch")
	}
}

func TestGetWeaveNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	s, err := Open(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer s.Close()

	weave, err := s.GetWeave(99999)
	if err != nil {
		t.Fatalf("GetWeave failed: %v", err)
	}
	if weave != nil {
		t.Error("expected nil for nonexistent weave")
	}
}

func TestContextTypes(t *testing.T) {
	if ContextExternal != "external" {
		t.Errorf("expected external, got %s", ContextExternal)
	}
	if ContextAssisted != "assisted" {
		t.Errorf("expected assisted, got %s", ContextAssisted)
	}
	if ContextReview != "review" {
		t.Errorf("expected review, got %s", ContextReview)
	}
}

// =============================================================================
// Tests for verify.go functions
// =============================================================================

func TestVerifyEventIntegrity(t *testing.T) {
	event := &Event{
		DeviceID:    [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		MMRIndex:    42,
		TimestampNs: 1234567890,
		FilePath:    "/test/file.txt",
		ContentHash: [32]byte{0xaa, 0xbb, 0xcc},
		FileSize:    1024,
		SizeDelta:   100,
	}

	regions := []EditRegion{
		{Ordinal: 0, StartPct: 0.0, EndPct: 0.25, DeltaSign: 1, ByteCount: 50},
		{Ordinal: 1, StartPct: 0.5, EndPct: 0.75, DeltaSign: -1, ByteCount: 25},
	}

	// Compute the expected hash
	expectedHash := computeLeafHash(event, regions)

	// Should pass with correct hash
	err := VerifyEventIntegrity(event, regions, expectedHash)
	if err != nil {
		t.Errorf("VerifyEventIntegrity failed for valid event: %v", err)
	}

	// Should fail with wrong hash
	wrongHash := [32]byte{0xff, 0xff, 0xff}
	err = VerifyEventIntegrity(event, regions, wrongHash)
	if err == nil {
		t.Error("VerifyEventIntegrity should fail with wrong hash")
	}
}

func TestVerifyEventIntegrityNoRegions(t *testing.T) {
	event := &Event{
		DeviceID:    [16]byte{1},
		TimestampNs: 1234567890,
		FilePath:    "/test.txt",
		ContentHash: [32]byte{0xde, 0xad},
		FileSize:    512,
		SizeDelta:   0,
	}

	// Compute hash with no regions
	expectedHash := computeLeafHash(event, nil)

	err := VerifyEventIntegrity(event, nil, expectedHash)
	if err != nil {
		t.Errorf("VerifyEventIntegrity failed with no regions: %v", err)
	}
}

func TestVerifyAllEvents(t *testing.T) {
	tmpDir := t.TempDir()
	s, err := Open(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer s.Close()

	// Insert device
	device := &Device{DeviceID: [16]byte{1, 2, 3}, CreatedAt: time.Now().UnixNano()}
	s.InsertDevice(device)

	// Insert events with correct leaf hashes
	for i := 0; i < 3; i++ {
		event := &Event{
			DeviceID:    device.DeviceID,
			MMRIndex:    uint64(i),
			TimestampNs: time.Now().UnixNano() + int64(i*1000),
			FilePath:    "/test.txt",
			ContentHash: [32]byte{byte(i)},
			FileSize:    int64(100 * (i + 1)),
			SizeDelta:   int32(10 * i),
		}
		// Compute correct leaf hash
		event.MMRLeafHash = computeLeafHash(event, nil)
		s.InsertEvent(event)
	}

	// Verify all - should find no corruption
	corrupted, err := s.VerifyAllEvents(nil)
	if err != nil {
		t.Fatalf("VerifyAllEvents failed: %v", err)
	}
	if len(corrupted) != 0 {
		t.Errorf("expected no corrupted events, got %d", len(corrupted))
	}
}

func TestVerifyAllEventsWithCorruption(t *testing.T) {
	tmpDir := t.TempDir()
	s, err := Open(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer s.Close()

	device := &Device{DeviceID: [16]byte{1}, CreatedAt: time.Now().UnixNano()}
	s.InsertDevice(device)

	// Insert event with WRONG leaf hash
	event := &Event{
		DeviceID:    device.DeviceID,
		MMRIndex:    0,
		MMRLeafHash: [32]byte{0xff, 0xff, 0xff}, // Wrong hash
		TimestampNs: time.Now().UnixNano(),
		FilePath:    "/test.txt",
		ContentHash: [32]byte{0xaa},
		FileSize:    100,
		SizeDelta:   10,
	}
	s.InsertEvent(event)

	corrupted, err := s.VerifyAllEvents(nil)
	if err != nil {
		t.Fatalf("VerifyAllEvents failed: %v", err)
	}
	if len(corrupted) != 1 {
		t.Errorf("expected 1 corrupted event, got %d", len(corrupted))
	}
	if len(corrupted) > 0 && corrupted[0] != 0 {
		t.Errorf("expected corrupted MMRIndex 0, got %d", corrupted[0])
	}
}

func TestVerifyAllEventsWithMMRGetter(t *testing.T) {
	tmpDir := t.TempDir()
	s, err := Open(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer s.Close()

	device := &Device{DeviceID: [16]byte{1}, CreatedAt: time.Now().UnixNano()}
	s.InsertDevice(device)

	// Create event with correct leaf hash
	event := &Event{
		DeviceID:    device.DeviceID,
		MMRIndex:    0,
		TimestampNs: time.Now().UnixNano(),
		FilePath:    "/test.txt",
		ContentHash: [32]byte{0xaa},
		FileSize:    100,
		SizeDelta:   10,
	}
	event.MMRLeafHash = computeLeafHash(event, nil)
	s.InsertEvent(event)

	// MMR getter returns wrong hash - simulates MMR corruption
	mmrGetter := func(index uint64) ([32]byte, error) {
		return [32]byte{0xbb, 0xbb, 0xbb}, nil // Wrong hash
	}

	corrupted, err := s.VerifyAllEvents(mmrGetter)
	if err != nil {
		t.Fatalf("VerifyAllEvents failed: %v", err)
	}
	if len(corrupted) != 1 {
		t.Errorf("expected 1 corrupted event (MMR mismatch), got %d", len(corrupted))
	}
}

func TestVerifyAllEventsWithRegions(t *testing.T) {
	tmpDir := t.TempDir()
	s, err := Open(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer s.Close()

	device := &Device{DeviceID: [16]byte{1}, CreatedAt: time.Now().UnixNano()}
	s.InsertDevice(device)

	// Create event
	event := &Event{
		DeviceID:    device.DeviceID,
		MMRIndex:    0,
		TimestampNs: time.Now().UnixNano(),
		FilePath:    "/test.txt",
		ContentHash: [32]byte{0xaa},
		FileSize:    100,
		SizeDelta:   10,
	}

	regions := []EditRegion{
		{Ordinal: 0, StartPct: 0.1, EndPct: 0.3, DeltaSign: 1, ByteCount: 20},
	}

	// Compute correct leaf hash WITH regions
	event.MMRLeafHash = computeLeafHash(event, regions)
	eventID, _ := s.InsertEvent(event)

	// Insert the regions
	for i := range regions {
		regions[i].EventID = eventID
	}
	s.InsertEditRegions(eventID, regions)

	// Should verify correctly
	corrupted, err := s.VerifyAllEvents(nil)
	if err != nil {
		t.Fatalf("VerifyAllEvents failed: %v", err)
	}
	if len(corrupted) != 0 {
		t.Errorf("expected no corrupted events, got %d", len(corrupted))
	}
}

func TestComputeLeafHashDeterminism(t *testing.T) {
	event := &Event{
		DeviceID:    [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		MMRIndex:    42,
		TimestampNs: 1234567890,
		FilePath:    "/test/file.txt",
		ContentHash: [32]byte{0xaa, 0xbb, 0xcc},
		FileSize:    1024,
		SizeDelta:   100,
	}

	regions := []EditRegion{
		{Ordinal: 0, StartPct: 0.0, EndPct: 0.25, DeltaSign: 1, ByteCount: 50},
	}

	// Compute multiple times - should be deterministic
	hash1 := computeLeafHash(event, regions)
	hash2 := computeLeafHash(event, regions)
	hash3 := computeLeafHash(event, regions)

	if hash1 != hash2 || hash2 != hash3 {
		t.Error("computeLeafHash should be deterministic")
	}

	// Different event should have different hash
	event2 := *event
	event2.FileSize = 2048
	hash4 := computeLeafHash(&event2, regions)
	if hash4 == hash1 {
		t.Error("different events should have different hashes")
	}
}

func TestComputeRegionsHashEmpty(t *testing.T) {
	// Empty regions should return zero hash
	hash := computeRegionsHash(nil)
	if hash != [32]byte{} {
		t.Error("empty regions should return zero hash")
	}

	hash = computeRegionsHash([]EditRegion{})
	if hash != [32]byte{} {
		t.Error("empty slice should return zero hash")
	}
}

func TestComputeRegionsHashDeterminism(t *testing.T) {
	regions := []EditRegion{
		{Ordinal: 0, StartPct: 0.1, EndPct: 0.2, DeltaSign: 1, ByteCount: 10},
		{Ordinal: 1, StartPct: 0.5, EndPct: 0.8, DeltaSign: -1, ByteCount: 30},
	}

	hash1 := computeRegionsHash(regions)
	hash2 := computeRegionsHash(regions)

	if hash1 != hash2 {
		t.Error("computeRegionsHash should be deterministic")
	}

	// Different regions should have different hash
	regions2 := []EditRegion{
		{Ordinal: 0, StartPct: 0.2, EndPct: 0.3, DeltaSign: 1, ByteCount: 15},
	}
	hash3 := computeRegionsHash(regions2)
	if hash3 == hash1 {
		t.Error("different regions should have different hashes")
	}
}

func TestFloatBits(t *testing.T) {
	tests := []struct {
		input float32
	}{
		{0.0},
		{1.0},
		{-1.0},
		{0.5},
		{0.123456},
		{100.0},
	}

	for _, tt := range tests {
		bits := floatBits(tt.input)
		// Verify round-trip through math.Float32frombits
		roundTrip := math.Float32frombits(bits)
		if roundTrip != tt.input {
			t.Errorf("floatBits(%f) round-trip failed: got %f", tt.input, roundTrip)
		}
	}
}

func TestComputeLeafHashWithLongFilePath(t *testing.T) {
	// Test with a long file path to ensure length-prefixing works
	longPath := "/very/long/path/"
	for i := 0; i < 50; i++ {
		longPath += "subdir/"
	}
	longPath += "file.txt"

	event := &Event{
		DeviceID:    [16]byte{1},
		TimestampNs: 1234567890,
		FilePath:    longPath,
		ContentHash: [32]byte{0xaa},
		FileSize:    100,
		SizeDelta:   0,
	}

	// Should not panic
	hash := computeLeafHash(event, nil)
	if hash == [32]byte{} {
		t.Error("expected non-zero hash")
	}
}

func TestComputeLeafHashEmptyFilePath(t *testing.T) {
	event := &Event{
		DeviceID:    [16]byte{1},
		TimestampNs: 1234567890,
		FilePath:    "",
		ContentHash: [32]byte{0xaa},
		FileSize:    100,
		SizeDelta:   0,
	}

	// Should not panic with empty path
	hash := computeLeafHash(event, nil)
	if hash == [32]byte{} {
		t.Error("expected non-zero hash even with empty path")
	}
}

func TestComputeRegionsHashAllFields(t *testing.T) {
	// Test that all fields affect the hash
	base := []EditRegion{
		{Ordinal: 5, StartPct: 0.25, EndPct: 0.75, DeltaSign: 1, ByteCount: 100},
	}

	baseHash := computeRegionsHash(base)

	// Change each field and verify hash changes
	tests := []struct {
		name    string
		regions []EditRegion
	}{
		{"different ordinal", []EditRegion{{Ordinal: 6, StartPct: 0.25, EndPct: 0.75, DeltaSign: 1, ByteCount: 100}}},
		{"different start", []EditRegion{{Ordinal: 5, StartPct: 0.3, EndPct: 0.75, DeltaSign: 1, ByteCount: 100}}},
		{"different end", []EditRegion{{Ordinal: 5, StartPct: 0.25, EndPct: 0.8, DeltaSign: 1, ByteCount: 100}}},
		{"different delta", []EditRegion{{Ordinal: 5, StartPct: 0.25, EndPct: 0.75, DeltaSign: -1, ByteCount: 100}}},
		{"different bytes", []EditRegion{{Ordinal: 5, StartPct: 0.25, EndPct: 0.75, DeltaSign: 1, ByteCount: 200}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := computeRegionsHash(tt.regions)
			if hash == baseHash {
				t.Errorf("%s should produce different hash", tt.name)
			}
		})
	}
}

// =============================================================================
// Benchmarks
// =============================================================================

func BenchmarkComputeLeafHash(b *testing.B) {
	event := &Event{
		DeviceID:    [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		MMRIndex:    42,
		TimestampNs: 1234567890,
		FilePath:    "/test/file.txt",
		ContentHash: [32]byte{0xaa, 0xbb, 0xcc},
		FileSize:    1024,
		SizeDelta:   100,
	}

	regions := []EditRegion{
		{Ordinal: 0, StartPct: 0.0, EndPct: 0.25, DeltaSign: 1, ByteCount: 50},
		{Ordinal: 1, StartPct: 0.5, EndPct: 0.75, DeltaSign: -1, ByteCount: 25},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		computeLeafHash(event, regions)
	}
}

func BenchmarkComputeRegionsHash(b *testing.B) {
	regions := make([]EditRegion, 10)
	for i := 0; i < 10; i++ {
		regions[i] = EditRegion{
			Ordinal:   int16(i),
			StartPct:  float32(i) / 10.0,
			EndPct:    float32(i+1) / 10.0,
			DeltaSign: 1,
			ByteCount: 100,
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		computeRegionsHash(regions)
	}
}

func BenchmarkInsertEvent(b *testing.B) {
	tmpDir := b.TempDir()
	s, err := Open(filepath.Join(tmpDir, "bench.db"))
	if err != nil {
		b.Fatalf("Open failed: %v", err)
	}
	defer s.Close()

	device := &Device{DeviceID: [16]byte{1}, CreatedAt: time.Now().UnixNano()}
	s.InsertDevice(device)

	baseTime := time.Now().UnixNano()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		event := &Event{
			DeviceID:    device.DeviceID,
			MMRIndex:    uint64(i),
			TimestampNs: baseTime + int64(i*1000),
			FilePath:    "/test.txt",
			ContentHash: [32]byte{byte(i)},
			FileSize:    int64(100 * (i + 1)),
			SizeDelta:   int32(10 * i),
		}
		s.InsertEvent(event)
	}
}

func BenchmarkGetEvent(b *testing.B) {
	tmpDir := b.TempDir()
	s, err := Open(filepath.Join(tmpDir, "bench.db"))
	if err != nil {
		b.Fatalf("Open failed: %v", err)
	}
	defer s.Close()

	device := &Device{DeviceID: [16]byte{1}, CreatedAt: time.Now().UnixNano()}
	s.InsertDevice(device)

	// Insert events first
	for i := 0; i < 1000; i++ {
		event := &Event{
			DeviceID:    device.DeviceID,
			MMRIndex:    uint64(i),
			TimestampNs: time.Now().UnixNano() + int64(i),
			FilePath:    "/test.txt",
		}
		s.InsertEvent(event)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.GetEvent(int64((i % 1000) + 1))
	}
}
