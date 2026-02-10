//go:build integration

package integration

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"witnessd/internal/wal"
)

// TestCrashRecoveryBasic tests basic WAL recovery after simulated crash.
func TestCrashRecoveryBasic(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.InitWAL()

	// Write some entries before "crash"
	for i := 0; i < 10; i++ {
		payload := []byte("keystroke batch " + string(rune('0'+i)))
		env.WriteWALEntry(wal.EntryKeystrokeBatch, payload)
	}

	// Record state before crash
	entriesBefore, _ := env.WAL.ReadAll()
	lastSeqBefore := env.WAL.LastSequence()

	// Simulate crash by closing WAL without cleanup
	walPath := env.WAL.Path()
	env.WAL.Close()
	env.WAL = nil

	// "Restart" by reopening WAL
	var sessionID [32]byte
	rand.Read(sessionID[:])

	recoveredWAL, err := wal.Open(walPath, sessionID, env.HMACKey)
	AssertNoError(t, err, "WAL should reopen after crash")
	defer recoveredWAL.Close()

	// Verify all entries recovered
	entriesAfter, err := recoveredWAL.ReadAll()
	AssertNoError(t, err, "should read recovered entries")
	AssertEqual(t, len(entriesBefore), len(entriesAfter), "entry count should match")

	// Verify sequence numbers are correct
	lastSeqAfter := recoveredWAL.LastSequence()
	AssertEqual(t, lastSeqBefore, lastSeqAfter, "last sequence should match")

	// Verify we can continue writing
	err = recoveredWAL.Append(wal.EntryKeystrokeBatch, []byte("post-recovery entry"))
	AssertNoError(t, err, "should append after recovery")

	// Verify new entry has correct sequence
	newSeq := recoveredWAL.LastSequence()
	AssertEqual(t, lastSeqAfter+1, newSeq, "new entry should have next sequence")
}

// TestCrashRecoveryWithCorruption tests recovery when WAL has corrupted entries.
func TestCrashRecoveryWithCorruption(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.InitWAL()

	// Write valid entries
	for i := 0; i < 5; i++ {
		env.WriteWALEntry(wal.EntryKeystrokeBatch, []byte("valid entry"))
	}

	validEntryCount := 5
	walPath := env.WAL.Path()
	env.WAL.Close()

	// Corrupt the file by appending garbage
	f, err := os.OpenFile(walPath, os.O_APPEND|os.O_WRONLY, 0600)
	AssertNoError(t, err, "should open WAL for corruption")
	f.Write([]byte("GARBAGE DATA THAT LOOKS LIKE AN ENTRY BUT ISN'T"))
	f.Close()

	// Reopen - should recover valid entries and truncate garbage
	var sessionID [32]byte
	rand.Read(sessionID[:])

	recoveredWAL, err := wal.Open(walPath, sessionID, env.HMACKey)
	AssertNoError(t, err, "WAL should recover despite corruption")
	defer recoveredWAL.Close()

	// Should have recovered valid entries
	entries, err := recoveredWAL.ReadAll()
	AssertNoError(t, err, "should read recovered entries")
	AssertEqual(t, validEntryCount, len(entries), "should recover valid entries only")

	// Should be able to continue
	err = recoveredWAL.Append(wal.EntryHeartbeat, []byte("heartbeat"))
	AssertNoError(t, err, "should continue after recovery")
}

// TestCrashRecoveryChainIntegrity tests that WAL hash chain remains valid.
func TestCrashRecoveryChainIntegrity(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.InitWAL()

	// Write entries with known content
	payloads := []string{
		"First entry",
		"Second entry",
		"Third entry",
		"Fourth entry",
		"Fifth entry",
	}

	for _, p := range payloads {
		env.WriteWALEntry(wal.EntryKeystrokeBatch, []byte(p))
	}

	walPath := env.WAL.Path()
	env.WAL.Close()

	// Reopen
	var sessionID [32]byte
	rand.Read(sessionID[:])

	recoveredWAL, err := wal.Open(walPath, sessionID, env.HMACKey)
	AssertNoError(t, err, "WAL should reopen")
	defer recoveredWAL.Close()

	// Read and verify chain
	entries, err := recoveredWAL.ReadAll()
	AssertNoError(t, err, "should read entries")

	// Verify hash chain linkage
	var prevHash [32]byte
	for i, entry := range entries {
		AssertEqual(t, prevHash, entry.PrevHash, "entry %d hash chain should be valid", i)
		prevHash = entry.Hash()
	}

	// Verify payloads
	for i, entry := range entries {
		AssertEqual(t, payloads[i], string(entry.Payload), "entry %d payload should match", i)
	}
}

// TestCrashRecoveryMidWrite tests recovery from crash during write.
func TestCrashRecoveryMidWrite(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.InitWAL()

	// Write complete entries
	for i := 0; i < 5; i++ {
		env.WriteWALEntry(wal.EntryKeystrokeBatch, []byte("complete entry"))
	}

	completedEntries := 5
	walPath := env.WAL.Path()
	env.WAL.Close()

	// Simulate partial write by appending incomplete entry header
	f, err := os.OpenFile(walPath, os.O_APPEND|os.O_WRONLY, 0600)
	AssertNoError(t, err, "should open WAL")

	// Write partial entry - just the length field
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], 1000) // Claims to be 1000 bytes
	f.Write(lenBuf[:])
	// But we don't write the rest...
	f.Close()

	// Reopen - should recover to last complete entry
	var sessionID [32]byte
	rand.Read(sessionID[:])

	recoveredWAL, err := wal.Open(walPath, sessionID, env.HMACKey)
	AssertNoError(t, err, "WAL should recover from partial write")
	defer recoveredWAL.Close()

	entries, err := recoveredWAL.ReadAll()
	AssertNoError(t, err, "should read recovered entries")
	AssertEqual(t, completedEntries, len(entries), "should recover complete entries only")
}

// TestCrashRecoveryEmptyWAL tests recovery when WAL is empty.
func TestCrashRecoveryEmptyWAL(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.InitWAL()

	// Close immediately without writing
	walPath := env.WAL.Path()
	env.WAL.Close()

	// Reopen empty WAL
	var sessionID [32]byte
	rand.Read(sessionID[:])

	recoveredWAL, err := wal.Open(walPath, sessionID, env.HMACKey)
	AssertNoError(t, err, "empty WAL should reopen")
	defer recoveredWAL.Close()

	entries, err := recoveredWAL.ReadAll()
	AssertNoError(t, err, "should read empty WAL")
	AssertEqual(t, 0, len(entries), "should have no entries")

	// Should be able to write
	err = recoveredWAL.Append(wal.EntrySessionStart, []byte("new session"))
	AssertNoError(t, err, "should write to recovered empty WAL")
}

// TestCrashRecoveryCheckpointSync tests recovery respects checkpoint boundaries.
func TestCrashRecoveryCheckpointSync(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.InitWAL()

	// Write pre-checkpoint entries
	for i := 0; i < 5; i++ {
		env.WriteWALEntry(wal.EntryKeystrokeBatch, []byte("pre-checkpoint"))
	}

	// Write checkpoint marker
	checkpointPayload, _ := json.Marshal(map[string]interface{}{
		"ordinal":   0,
		"timestamp": time.Now().UnixNano(),
	})
	env.WriteWALEntry(wal.EntryCheckpoint, checkpointPayload)

	// Write post-checkpoint entries
	for i := 0; i < 3; i++ {
		env.WriteWALEntry(wal.EntryKeystrokeBatch, []byte("post-checkpoint"))
	}

	walPath := env.WAL.Path()
	env.WAL.Close()

	// Reopen
	var sessionID [32]byte
	rand.Read(sessionID[:])

	recoveredWAL, err := wal.Open(walPath, sessionID, env.HMACKey)
	AssertNoError(t, err, "WAL should recover")
	defer recoveredWAL.Close()

	entries, err := recoveredWAL.ReadAll()
	AssertNoError(t, err, "should read entries")

	// Should have all entries: 5 pre + 1 checkpoint + 3 post = 9
	AssertEqual(t, 9, len(entries), "should have all entries")

	// Find checkpoint entry
	checkpointFound := false
	checkpointSeq := uint64(0)
	for _, entry := range entries {
		if entry.Type == wal.EntryCheckpoint {
			checkpointFound = true
			checkpointSeq = entry.Sequence
			break
		}
	}
	AssertTrue(t, checkpointFound, "checkpoint should be recovered")
	AssertEqual(t, uint64(5), checkpointSeq, "checkpoint should be at sequence 5")
}

// TestCrashRecoveryReplayAfterCheckpoint tests replaying only entries after checkpoint.
func TestCrashRecoveryReplayAfterCheckpoint(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.InitWAL()

	// Write pre-checkpoint entries
	for i := 0; i < 10; i++ {
		env.WriteWALEntry(wal.EntryKeystrokeBatch, []byte("entry"))
	}

	// Write checkpoint
	checkpointSeq := env.WAL.LastSequence()
	env.WriteWALEntry(wal.EntryCheckpoint, []byte("checkpoint"))

	// Write more entries
	for i := 0; i < 5; i++ {
		env.WriteWALEntry(wal.EntryKeystrokeBatch, []byte("post-checkpoint"))
	}

	walPath := env.WAL.Path()
	env.WAL.Close()

	// Reopen and read only entries after checkpoint
	var sessionID [32]byte
	rand.Read(sessionID[:])

	recoveredWAL, err := wal.Open(walPath, sessionID, env.HMACKey)
	AssertNoError(t, err, "WAL should recover")
	defer recoveredWAL.Close()

	// Read entries after checkpoint sequence
	entriesAfter, err := recoveredWAL.ReadAfter(checkpointSeq)
	AssertNoError(t, err, "should read entries after checkpoint")

	// Should have checkpoint entry + 5 post-checkpoint entries = 6
	AssertEqual(t, 6, len(entriesAfter), "should have entries after checkpoint")

	// First entry should be the checkpoint
	AssertEqual(t, wal.EntryCheckpoint, entriesAfter[0].Type, "first should be checkpoint")
}

// TestCrashRecoveryLargeWAL tests recovery of a large WAL file.
func TestCrashRecoveryLargeWAL(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large WAL test in short mode")
	}

	env := NewTestEnv(t)
	defer env.Cleanup()

	env.InitWAL()

	// Write many entries
	entryCount := 1000
	for i := 0; i < entryCount; i++ {
		payload := make([]byte, 100) // 100 bytes each
		rand.Read(payload)
		env.WriteWALEntry(wal.EntryKeystrokeBatch, payload)
	}

	walPath := env.WAL.Path()
	sizeBefore := env.WAL.Size()
	env.WAL.Close()

	// Verify file exists and has size
	stat, err := os.Stat(walPath)
	AssertNoError(t, err, "WAL file should exist")
	AssertTrue(t, stat.Size() > 0, "WAL file should have content")

	// Reopen
	var sessionID [32]byte
	rand.Read(sessionID[:])

	start := time.Now()
	recoveredWAL, err := wal.Open(walPath, sessionID, env.HMACKey)
	recoveryTime := time.Since(start)
	AssertNoError(t, err, "large WAL should recover")
	defer recoveredWAL.Close()

	t.Logf("Recovery time for %d entries: %v", entryCount, recoveryTime)
	t.Logf("WAL size: %d bytes", sizeBefore)

	entries, err := recoveredWAL.ReadAll()
	AssertNoError(t, err, "should read all entries")
	AssertEqual(t, entryCount, len(entries), "should recover all entries")
}

// TestCrashRecoveryTruncate tests WAL truncation after checkpoint.
func TestCrashRecoveryTruncate(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.InitWAL()

	// Write entries
	for i := 0; i < 20; i++ {
		env.WriteWALEntry(wal.EntryKeystrokeBatch, []byte("entry"))
	}

	// Truncate to keep only entries after sequence 10
	err := env.WAL.Truncate(10)
	AssertNoError(t, err, "truncate should succeed")

	// Read remaining entries
	entries, err := env.WAL.ReadAll()
	AssertNoError(t, err, "should read after truncate")

	// Should have entries 10-19 (10 entries)
	AssertEqual(t, 10, len(entries), "should have entries after truncate point")

	// First entry should have sequence >= 10
	AssertTrue(t, entries[0].Sequence >= 10, "first entry should be at or after truncate point")
}

// TestCrashRecoverySessionContinuation tests continuing a session after crash.
func TestCrashRecoverySessionContinuation(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	// Initialize full environment
	env.InitAll()

	// Start tracking and create some activity
	err := env.TrackingSession.Start()
	AssertNoError(t, err, "tracking should start")

	// Record some WAL entries
	for i := 0; i < 5; i++ {
		env.WriteWALEntry(wal.EntryKeystrokeBatch, []byte("keystroke"))
		time.Sleep(10 * time.Millisecond)
	}

	// Get session state
	trackingEvidence := env.TrackingSession.Export()
	sessionID := trackingEvidence.SessionID

	// Simulate crash
	walPath := env.WAL.Path()
	env.TrackingSession.Stop()
	env.WAL.Close()

	// Recover
	var newSessionID [32]byte
	copy(newSessionID[:], []byte(sessionID)[:32])

	recoveredWAL, err := wal.Open(walPath, newSessionID, env.HMACKey)
	AssertNoError(t, err, "WAL should recover")
	defer recoveredWAL.Close()

	// Should be able to continue writing
	err = recoveredWAL.Append(wal.EntryKeystrokeBatch, []byte("post-recovery"))
	AssertNoError(t, err, "should continue session")

	// Read all entries
	entries, err := recoveredWAL.ReadAll()
	AssertNoError(t, err, "should read all")
	AssertEqual(t, 6, len(entries), "should have original + new entry")
}

// TestCrashRecoveryMultipleTypes tests recovery with different entry types.
func TestCrashRecoveryMultipleTypes(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.InitWAL()

	// Write different entry types
	env.WriteWALEntry(wal.EntrySessionStart, []byte("session start"))
	env.WriteWALEntry(wal.EntryKeystrokeBatch, []byte("keystrokes 1"))
	env.WriteWALEntry(wal.EntryDocumentHash, []byte("doc hash 1"))
	env.WriteWALEntry(wal.EntryJitterSample, []byte("jitter 1"))
	env.WriteWALEntry(wal.EntryHeartbeat, []byte("heartbeat"))
	env.WriteWALEntry(wal.EntryKeystrokeBatch, []byte("keystrokes 2"))
	env.WriteWALEntry(wal.EntryCheckpoint, []byte("checkpoint"))
	env.WriteWALEntry(wal.EntryKeystrokeBatch, []byte("keystrokes 3"))

	walPath := env.WAL.Path()
	env.WAL.Close()

	// Recover
	var sessionID [32]byte
	rand.Read(sessionID[:])

	recoveredWAL, err := wal.Open(walPath, sessionID, env.HMACKey)
	AssertNoError(t, err, "WAL should recover")
	defer recoveredWAL.Close()

	entries, err := recoveredWAL.ReadAll()
	AssertNoError(t, err, "should read entries")
	AssertEqual(t, 8, len(entries), "should have all entries")

	// Verify entry types in order
	expectedTypes := []wal.EntryType{
		wal.EntrySessionStart,
		wal.EntryKeystrokeBatch,
		wal.EntryDocumentHash,
		wal.EntryJitterSample,
		wal.EntryHeartbeat,
		wal.EntryKeystrokeBatch,
		wal.EntryCheckpoint,
		wal.EntryKeystrokeBatch,
	}

	for i, entry := range entries {
		AssertEqual(t, expectedTypes[i], entry.Type, "entry %d type should match", i)
	}
}

// TestCrashRecoveryDataIntegrity tests that recovered data is byte-for-byte correct.
func TestCrashRecoveryDataIntegrity(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.InitWAL()

	// Write entries with known random data
	type testEntry struct {
		Type    wal.EntryType
		Payload []byte
	}

	var entries []testEntry
	for i := 0; i < 10; i++ {
		payload := make([]byte, 50+i*10)
		rand.Read(payload)

		entry := testEntry{
			Type:    wal.EntryKeystrokeBatch,
			Payload: payload,
		}
		entries = append(entries, entry)
		env.WriteWALEntry(entry.Type, entry.Payload)
	}

	walPath := env.WAL.Path()
	env.WAL.Close()

	// Recover
	var sessionID [32]byte
	rand.Read(sessionID[:])

	recoveredWAL, err := wal.Open(walPath, sessionID, env.HMACKey)
	AssertNoError(t, err, "WAL should recover")
	defer recoveredWAL.Close()

	recovered, err := recoveredWAL.ReadAll()
	AssertNoError(t, err, "should read entries")
	AssertEqual(t, len(entries), len(recovered), "entry count should match")

	// Verify each payload matches exactly
	for i := range entries {
		AssertEqual(t, entries[i].Type, recovered[i].Type, "type should match")
		if len(entries[i].Payload) != len(recovered[i].Payload) {
			t.Fatalf("entry %d: payload length mismatch: %d vs %d",
				i, len(entries[i].Payload), len(recovered[i].Payload))
		}
		for j := range entries[i].Payload {
			if entries[i].Payload[j] != recovered[i].Payload[j] {
				t.Fatalf("entry %d: payload byte %d mismatch", i, j)
			}
		}
	}
}
