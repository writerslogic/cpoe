# Witnessd Integration Tests

This directory contains comprehensive end-to-end integration tests for the witnessd document witnessing system. These tests verify the complete flow from document monitoring through evidence packet creation and verification.

## Overview

The integration tests are designed to validate that all witnessd components work correctly together in realistic scenarios. Unlike unit tests that test individual functions in isolation, integration tests verify the behavior of the entire system.

## Test Categories

### 1. Full Witnessing Flow (`witnessing_flow_test.go`)

Tests the complete witnessing workflow:
- Initialize environment with software PUF
- Create and track a document
- Record keystroke events via WAL
- Create checkpoints at intervals
- Sign checkpoints with key hierarchy (ratcheting keys)
- Anchor to external timestamping services
- Export evidence packet
- Verify the entire evidence packet

**Key Tests:**
- `TestFullWitnessingFlow` - Complete end-to-end flow
- `TestWitnessingFlowWithAI` - Flow with AI assistance declared
- `TestWitnessingFlowWithExternalAnchors` - External timestamping
- `TestVDFProofVerification` - VDF proof generation and verification
- `TestKeyHierarchyRatcheting` - Key ratcheting for forward secrecy
- `TestChainIntegrity` - Checkpoint chain integrity
- `TestEvidenceStrengthLevels` - Evidence strength calculation

### 2. Crash Recovery (`crash_recovery_test.go`)

Tests WAL-based crash recovery:
- Start monitoring a document
- Write WAL entries
- Simulate crash (close files abruptly, corrupt data)
- Restart and recover
- Verify no data loss (or minimal expected loss)
- Continue session seamlessly

**Key Tests:**
- `TestCrashRecoveryBasic` - Basic recovery after crash
- `TestCrashRecoveryWithCorruption` - Recovery with corrupted WAL entries
- `TestCrashRecoveryChainIntegrity` - Hash chain verification after recovery
- `TestCrashRecoveryMidWrite` - Recovery from incomplete write
- `TestCrashRecoveryLargeWAL` - Performance with large WAL files
- `TestCrashRecoveryDataIntegrity` - Byte-for-byte data verification

### 3. Multi-Document (`multi_document_test.go`)

Tests simultaneous monitoring of multiple documents:
- Monitor multiple documents simultaneously
- Verify separate session tracking
- Test switching between active documents
- Verify chain isolation between documents

**Key Tests:**
- `TestMultiDocumentBasic` - Basic multi-document operations
- `TestMultiDocumentConcurrent` - Concurrent modifications
- `TestMultiDocumentTrackingSessions` - Separate tracking sessions
- `TestMultiDocumentSwitching` - Switching between documents
- `TestMultiDocumentPersistence` - Saving and loading multiple chains
- `TestMultiDocumentIsolation` - Chain isolation verification

### 4. Forensic Analysis (`forensics_test.go`)

Tests forensic authorship analysis:
- Generate keystroke patterns
- Run forensic analysis
- Verify profile generation
- Test anomaly detection
- Validate assessment determination

**Key Tests:**
- `TestForensicAnalysisBasic` - Basic profile generation
- `TestForensicAnalysisWithRealPatterns` - Human-like patterns
- `TestForensicAnalysisSuspiciousPatterns` - Suspicious pattern detection
- `TestForensicAnomalyDetection` - Anomaly detection (gaps, velocity, etc.)
- `TestForensicSessionDetection` - Editing session detection
- `TestForensicAssessmentDetermination` - Assessment logic
- `TestForensicMetricsComputation` - Individual metric calculations

### 5. Verification Pipeline (`verification_test.go`)

Tests the complete verification pipeline:
- Create complete evidence packet
- Verify all components (VDF proofs, signatures, anchors)
- Test with tampered evidence (should fail)

**Key Tests:**
- `TestVerificationPipelineComplete` - Full verification pipeline
- `TestVerificationPipelineWithTampering` - Tamper detection
- `TestVerificationPipelineKeyHierarchy` - Key hierarchy verification
- `TestVerificationPipelineVDF` - VDF proof verification
- `TestVerificationPipelineMMR` - MMR proof verification
- `TestVerificationPipelineDeclaration` - Declaration verification
- `TestVerificationPipelinePerformance` - Performance benchmarks

### 6. CLI Commands (`cli_test.go`)

Tests CLI command integration:
- `witnessd` daemon start/stop
- `witnessctl status`
- `witnessctl init/commit/log`
- `witnessctl verify`
- `witnessctl export`
- `witnessctl forensics`
- `witnessctl declare`

**Key Tests:**
- `TestCLIHelp` - Help commands
- `TestCLICommit` - Commit workflow
- `TestCLIVerify` - Verification command
- `TestCLIExport` - Evidence export
- `TestCLIForensics` - Forensic analysis command
- `TestCLIWorkflow` - Complete CLI workflow
- `TestCLIErrorHandling` - Error scenarios

## Running the Tests

### Prerequisites

- Go 1.21 or later
- Access to the witnessd source code
- ~500MB disk space for test artifacts

### Running All Integration Tests

```bash
# From the project root
go test -tags=integration -v ./tests/integration/...
```

### Running Specific Test Files

```bash
# Full witnessing flow tests
go test -tags=integration -v ./tests/integration/... -run TestFullWitnessingFlow

# Crash recovery tests
go test -tags=integration -v ./tests/integration/... -run TestCrashRecovery

# Multi-document tests
go test -tags=integration -v ./tests/integration/... -run TestMultiDocument

# Forensic tests
go test -tags=integration -v ./tests/integration/... -run TestForensic

# Verification tests
go test -tags=integration -v ./tests/integration/... -run TestVerification

# CLI tests
go test -tags=integration -v ./tests/integration/... -run TestCLI
```

### Running in Short Mode

Skip long-running tests:

```bash
go test -tags=integration -v -short ./tests/integration/...
```

### Running with Verbose Output

```bash
go test -tags=integration -v ./tests/integration/... 2>&1 | tee test_output.log
```

### Running with Race Detection

```bash
go test -tags=integration -race -v ./tests/integration/...
```

### Running with Coverage

```bash
go test -tags=integration -coverprofile=coverage.out ./tests/integration/...
go tool cover -html=coverage.out -o coverage.html
```

## Test Environment

The tests create isolated temporary environments for each test:

- Temporary directory for all test files
- Separate `.witnessd` directory with subdirectories:
  - `chains/` - Checkpoint chains
  - `wal/` - Write-ahead logs
  - `tracking/` - Tracking data
  - `keys/` - Key material
  - `evidence/` - Evidence packets

All temporary directories are automatically cleaned up after tests complete.

## Test Fixtures and Helpers

### TestEnv

The `TestEnv` struct provides a fully initialized test environment:

```go
env := NewTestEnv(t)
defer env.Cleanup()

// Initialize components
env.InitPUF()           // Software PUF
env.InitKeyHierarchy()  // Master identity and session
env.InitChain()         // Checkpoint chain
env.InitWAL()           // Write-ahead log
env.InitTracking()      // Keystroke tracking
env.InitAnchors()       // Anchor registry with mock provider

// Or initialize all at once
env.InitAll()
```

### Document Operations

```go
// Create test document
env := NewTestEnv(t)
defer env.Cleanup()
env.InitAll()

// Modify document
env.ModifyDocument("\nNew content")

// Create checkpoint
cp := env.CreateCheckpoint("Commit message")

// Sign with key hierarchy
sig := env.SignCheckpoint(cp)

// Write to WAL
env.WriteWALEntry(wal.EntryKeystrokeBatch, payload)
```

### Assertion Helpers

```go
// Error assertions
AssertNoError(t, err, "operation should succeed")
AssertError(t, err, "operation should fail")

// Value assertions
AssertEqual(t, expected, actual, "values should match")
AssertNotEqual(t, a, b, "values should differ")
AssertTrue(t, condition, "condition should be true")
AssertFalse(t, condition, "condition should be false")

// Evidence packet validation
AssertValidEvidencePacket(t, packet)
```

### Data Generation

```go
// Generate keystroke events
events := GenerateKeystrokeEvents(100, startTime)
regions := GenerateRegionData(events)

// Generate test declarations
decl := GenerateTestDeclaration(t, contentHash, chainHash, title)
declWithAI := GenerateTestDeclarationWithAI(t, contentHash, chainHash, title)
```

## Test Data

Tests use deterministic seed data where possible to ensure reproducibility:

- Document content: Predictable text content
- Keystroke patterns: Simulated human-like timing
- Cryptographic keys: Generated per-test for isolation
- Timestamps: Based on test start time

## Adding New Tests

1. Create a new test file with the `//go:build integration` build tag
2. Use the `integration` package
3. Use `NewTestEnv(t)` for setup
4. Follow existing patterns for assertions and cleanup
5. Document the test purpose with comments

Example:

```go
//go:build integration

package integration

import "testing"

func TestMyNewFeature(t *testing.T) {
    env := NewTestEnv(t)
    defer env.Cleanup()

    env.InitAll()

    // Test implementation
    t.Run("subtest_name", func(t *testing.T) {
        // ...
    })
}
```

## Troubleshooting

### Tests Fail to Build

Ensure the integration build tag is used:
```bash
go test -tags=integration ./tests/integration/...
```

### CLI Tests Fail to Build Binaries

Check that you're running from the project root and have write access:
```bash
cd /path/to/witnessd
go build ./cmd/witnessd
go build ./cmd/witnessctl
```

### Tests Time Out

Increase the test timeout:
```bash
go test -tags=integration -timeout 10m ./tests/integration/...
```

### Disk Space Issues

Integration tests create temporary files. Ensure adequate disk space (~500MB).

### Race Conditions

Run with race detector to identify issues:
```bash
go test -tags=integration -race ./tests/integration/...
```

## Continuous Integration

For CI/CD pipelines, use:

```yaml
# Example GitHub Actions
- name: Run Integration Tests
  run: |
    go test -tags=integration -v -timeout 10m ./tests/integration/... 2>&1 | tee test-results.log

- name: Upload Test Results
  uses: actions/upload-artifact@v3
  with:
    name: integration-test-results
    path: test-results.log
```

## License

These tests are part of the witnessd project. Patent Pending: USPTO Application No. 19/460,364.
