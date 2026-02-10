//go:build integration

package integration

import (
	"encoding/json"
	"testing"
	"time"

	"witnessd/internal/checkpoint"
	"witnessd/internal/declaration"
	"witnessd/internal/evidence"
	"witnessd/internal/keyhierarchy"
	"witnessd/internal/vdf"
	"witnessd/internal/wal"
)

// TestFullWitnessingFlow tests the complete witnessing workflow:
// 1. Initialize environment with software PUF
// 2. Create and track document
// 3. Record keystroke events via WAL
// 4. Create checkpoints at intervals
// 5. Sign checkpoints with key hierarchy
// 6. Anchor to mock external service
// 7. Export evidence packet
// 8. Verify the entire evidence packet
func TestFullWitnessingFlow(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	// Initialize all components
	env.InitAll()

	t.Run("initial_checkpoint", func(t *testing.T) {
		// Create initial checkpoint
		cp := env.CreateCheckpoint("Initial document state")

		AssertEqual(t, uint64(0), cp.Ordinal, "first checkpoint should have ordinal 0")
		AssertEqual(t, [32]byte{}, cp.PreviousHash, "first checkpoint should have zero previous hash")
		AssertTrue(t, cp.VDF == nil, "first checkpoint should not have VDF proof")

		// Sign with key hierarchy
		sig := env.SignCheckpoint(cp)
		AssertEqual(t, uint64(0), sig.Ordinal, "signature should have ordinal 0")
		AssertEqual(t, cp.Hash, sig.CheckpointHash, "signature should match checkpoint hash")

		// Record in WAL
		walPayload, _ := json.Marshal(map[string]interface{}{
			"checkpoint_ordinal": cp.Ordinal,
			"checkpoint_hash":    cp.Hash,
		})
		env.WriteWALEntry(wal.EntryCheckpoint, walPayload)
	})

	t.Run("document_modification_and_checkpoint", func(t *testing.T) {
		// Simulate typing with WAL entries
		for i := 0; i < 10; i++ {
			env.ModifyDocument("\nAdding more content... ")

			// Record keystroke batch in WAL
			keystrokePayload, _ := json.Marshal(map[string]interface{}{
				"count":     5,
				"timestamp": time.Now().UnixNano(),
			})
			env.WriteWALEntry(wal.EntryKeystrokeBatch, keystrokePayload)

			time.Sleep(10 * time.Millisecond)
		}

		// Create second checkpoint
		cp := env.CreateCheckpoint("Added more content")

		AssertEqual(t, uint64(1), cp.Ordinal, "second checkpoint should have ordinal 1")
		AssertNotEqual(t, [32]byte{}, cp.PreviousHash, "should link to previous checkpoint")
		AssertTrue(t, cp.VDF != nil, "should have VDF proof")

		// Sign checkpoint
		sig := env.SignCheckpoint(cp)
		AssertEqual(t, uint64(1), sig.Ordinal, "signature ordinal should match")

		// Record in WAL
		walPayload, _ := json.Marshal(map[string]interface{}{
			"checkpoint_ordinal": cp.Ordinal,
			"checkpoint_hash":    cp.Hash,
		})
		env.WriteWALEntry(wal.EntryCheckpoint, walPayload)
	})

	t.Run("multiple_checkpoints", func(t *testing.T) {
		// Create more checkpoints
		for i := 0; i < 3; i++ {
			env.ModifyDocument("\nSection " + string(rune('A'+i)) + " content")
			time.Sleep(20 * time.Millisecond)

			cp := env.CreateCheckpoint("Section " + string(rune('A'+i)))
			env.SignCheckpoint(cp)
		}

		AssertEqual(t, 5, len(env.Chain.Checkpoints), "should have 5 checkpoints total")
	})

	t.Run("chain_verification", func(t *testing.T) {
		err := env.Chain.Verify()
		AssertNoError(t, err, "chain should verify successfully")

		// Check total elapsed time
		elapsed := env.Chain.TotalElapsedTime()
		AssertTrue(t, elapsed >= 0, "elapsed time should be non-negative")
	})

	t.Run("key_hierarchy_verification", func(t *testing.T) {
		// Verify session certificate
		err := keyhierarchy.VerifySessionCertificate(env.Session.Certificate)
		AssertNoError(t, err, "session certificate should verify")

		// Verify all checkpoint signatures
		signatures := env.Session.Signatures()
		err = keyhierarchy.VerifyCheckpointSignatures(signatures)
		AssertNoError(t, err, "checkpoint signatures should verify")
	})

	t.Run("anchor_timestamping", func(t *testing.T) {
		// Get chain hash
		latest := env.Chain.Latest()
		proofs, err := env.AnchorRegistry.Timestamp(env.Ctx, latest.Hash)
		AssertNoError(t, err, "timestamping should succeed")
		AssertTrue(t, len(proofs) > 0, "should have at least one proof")

		// Verify the anchor
		result, err := env.AnchorRegistry.Verify(env.Ctx, proofs[0])
		AssertNoError(t, err, "anchor verification should succeed")
		AssertTrue(t, result.Valid, "anchor should be valid")
	})

	t.Run("evidence_packet_creation", func(t *testing.T) {
		latest := env.Chain.Latest()
		chainHash := latest.Hash

		// Create declaration
		decl := GenerateTestDeclaration(t, latest.ContentHash, chainHash, "test_document.md")

		// Build evidence packet
		packet, err := evidence.NewBuilder("test_document.md", env.Chain).
			WithDeclaration(decl).
			Build()

		AssertNoError(t, err, "evidence packet build should succeed")
		AssertValidEvidencePacket(t, packet)

		// Verify strength
		AssertTrue(t, packet.Strength >= evidence.Basic, "should have at least Basic strength")
	})

	t.Run("evidence_packet_verification", func(t *testing.T) {
		latest := env.Chain.Latest()
		decl := GenerateTestDeclaration(t, latest.ContentHash, latest.Hash, "test_document.md")

		packet, _ := evidence.NewBuilder("test_document.md", env.Chain).
			WithDeclaration(decl).
			Build()

		// Verify the packet
		err := packet.Verify(env.VDFParams)
		AssertNoError(t, err, "evidence packet should verify")
	})

	t.Run("evidence_packet_encode_decode", func(t *testing.T) {
		latest := env.Chain.Latest()
		decl := GenerateTestDeclaration(t, latest.ContentHash, latest.Hash, "test_document.md")

		original, _ := evidence.NewBuilder("test_document.md", env.Chain).
			WithDeclaration(decl).
			Build()

		// Encode
		data, err := original.Encode()
		AssertNoError(t, err, "encode should succeed")

		// Decode
		decoded, err := evidence.Decode(data)
		AssertNoError(t, err, "decode should succeed")

		// Compare
		AssertEqual(t, original.Document.Title, decoded.Document.Title, "document title should match")
		AssertEqual(t, len(original.Checkpoints), len(decoded.Checkpoints), "checkpoint count should match")
	})

	t.Run("wal_entries", func(t *testing.T) {
		entries, err := env.WAL.ReadAll()
		AssertNoError(t, err, "reading WAL should succeed")
		AssertTrue(t, len(entries) > 0, "should have WAL entries")

		// Verify entry types
		hasKeystroke := false
		hasCheckpoint := false
		for _, e := range entries {
			if e.Type == wal.EntryKeystrokeBatch {
				hasKeystroke = true
			}
			if e.Type == wal.EntryCheckpoint {
				hasCheckpoint = true
			}
		}
		AssertTrue(t, hasKeystroke, "should have keystroke entries")
		AssertTrue(t, hasCheckpoint, "should have checkpoint entries")
	})
}

// TestWitnessingFlowWithAI tests the witnessing flow when AI assistance is declared.
func TestWitnessingFlowWithAI(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.InitPUF()
	env.InitKeyHierarchy()
	env.InitChain()

	// Create document with simulated AI-assisted content
	env.ModifyDocument("\n\n[AI-assisted research section]\n")
	cp := env.CreateCheckpoint("Initial with AI notes")
	env.SignCheckpoint(cp)

	env.ModifyDocument("\n\n[Human-written analysis]\n")
	cp = env.CreateCheckpoint("Added human analysis")
	env.SignCheckpoint(cp)

	// Create declaration with AI disclosure
	latest := env.Chain.Latest()
	decl := GenerateTestDeclarationWithAI(t, latest.ContentHash, latest.Hash, "test_document.md")

	// Build packet
	packet, err := evidence.NewBuilder("test_document.md", env.Chain).
		WithDeclaration(decl).
		Build()

	AssertNoError(t, err, "packet build should succeed")
	AssertTrue(t, packet.Declaration.AITools != nil, "should have AI tools in declaration")

	// Check limitations include AI notice
	hasAILimitation := false
	for _, lim := range packet.Limitations {
		if lim == "Author declares AI tool usage - verify institutional policy compliance" {
			hasAILimitation = true
			break
		}
	}
	AssertTrue(t, hasAILimitation, "should have AI limitation notice")
}

// TestWitnessingFlowWithExternalAnchors tests anchoring to external services.
func TestWitnessingFlowWithExternalAnchors(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.InitPUF()
	env.InitKeyHierarchy()
	env.InitChain()
	env.InitAnchors()

	// Create checkpoints
	env.CreateCheckpoint("Initial")
	env.ModifyDocument("\nMore content\n")
	env.CreateCheckpoint("Second commit")

	// Timestamp with anchors
	latest := env.Chain.Latest()
	proofs, err := env.AnchorRegistry.Timestamp(env.Ctx, latest.Hash)
	AssertNoError(t, err, "timestamping should succeed")

	// Build evidence with anchors
	decl := GenerateTestDeclaration(t, latest.ContentHash, latest.Hash, "test_document.md")

	packet, err := evidence.NewBuilder("test_document.md", env.Chain).
		WithDeclaration(decl).
		WithAnchors(proofs).
		Build()

	AssertNoError(t, err, "packet build should succeed")
	AssertTrue(t, packet.External != nil, "should have external anchors")
	AssertTrue(t, len(packet.External.Proofs) > 0, "should have anchor proofs")
	AssertEqual(t, evidence.Maximum, packet.Strength, "should have Maximum strength with anchors")
}

// TestVDFProofVerification tests that VDF proofs are correctly generated and verified.
func TestVDFProofVerification(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.InitChain()

	// Create first checkpoint (no VDF)
	cp0 := env.CreateCheckpoint("Initial")
	AssertTrue(t, cp0.VDF == nil, "first checkpoint should not have VDF")

	// Wait a bit to ensure measurable elapsed time
	time.Sleep(50 * time.Millisecond)

	// Modify and create second checkpoint
	env.ModifyDocument("\nAdded content after delay\n")
	cp1 := env.CreateCheckpoint("After delay")

	AssertTrue(t, cp1.VDF != nil, "second checkpoint should have VDF")

	// Verify VDF input matches expected
	expectedInput := vdf.ChainInput(cp1.ContentHash, cp1.PreviousHash, cp1.Ordinal)
	AssertEqual(t, expectedInput, cp1.VDF.Input, "VDF input should match chain input")

	// Verify VDF proof
	AssertTrue(t, vdf.Verify(cp1.VDF), "VDF proof should verify")

	// Verify chain integrity
	err := env.Chain.Verify()
	AssertNoError(t, err, "chain should verify with VDF proofs")
}

// TestKeyHierarchyRatcheting tests that the ratcheting key hierarchy works correctly.
func TestKeyHierarchyRatcheting(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.InitPUF()
	env.InitKeyHierarchy()
	env.InitChain()

	// Create and sign multiple checkpoints
	var signatures []*keyhierarchy.CheckpointSignature
	for i := 0; i < 5; i++ {
		env.ModifyDocument("\nContent version " + string(rune('1'+i)))
		cp := env.CreateCheckpoint("Version " + string(rune('1'+i)))
		sig := env.SignCheckpoint(cp)
		signatures = append(signatures, sig)
	}

	// Verify each signature uses a different public key (ratcheting)
	pubKeys := make(map[string]bool)
	for _, sig := range signatures {
		keyHex := string(sig.PublicKey)
		AssertFalse(t, pubKeys[keyHex], "each checkpoint should use a unique ratcheted key")
		pubKeys[keyHex] = true
	}

	// Verify all signatures
	allSigs := env.Session.Signatures()
	err := keyhierarchy.VerifyCheckpointSignatures(allSigs)
	AssertNoError(t, err, "all signatures should verify")
}

// TestChainIntegrity tests that the checkpoint chain maintains integrity.
func TestChainIntegrity(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.InitChain()

	// Create a series of checkpoints
	for i := 0; i < 10; i++ {
		env.ModifyDocument("\nParagraph " + string(rune('A'+i)))
		env.CreateCheckpoint("Added paragraph " + string(rune('A'+i)))
	}

	// Verify chain integrity
	err := env.Chain.Verify()
	AssertNoError(t, err, "valid chain should verify")

	// Tamper with a checkpoint hash and verify it fails
	originalHash := env.Chain.Checkpoints[5].Hash
	env.Chain.Checkpoints[5].Hash[0] ^= 0xff

	err = env.Chain.Verify()
	AssertError(t, err, "tampered chain should fail verification")

	// Restore and verify again
	env.Chain.Checkpoints[5].Hash = originalHash
	err = env.Chain.Verify()
	AssertNoError(t, err, "restored chain should verify")

	// Tamper with chain linkage
	if len(env.Chain.Checkpoints) > 1 {
		env.Chain.Checkpoints[3].PreviousHash[0] ^= 0xff

		err = env.Chain.Verify()
		AssertError(t, err, "broken chain link should fail verification")
	}
}

// TestCheckpointPersistence tests saving and loading checkpoint chains.
func TestCheckpointPersistence(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.InitChain()

	// Create checkpoints
	for i := 0; i < 5; i++ {
		env.ModifyDocument("\nContent " + string(rune('1'+i)))
		env.CreateCheckpoint("Commit " + string(rune('1'+i)))
	}

	// Save chain
	chainPath := env.Chain.StoragePath()
	if chainPath == "" {
		chainPath = env.WitnessdDir + "/chains/" + env.DocumentID + ".json"
	}
	err := env.Chain.Save(chainPath)
	AssertNoError(t, err, "chain save should succeed")

	// Load chain
	loaded, err := checkpoint.Load(chainPath)
	AssertNoError(t, err, "chain load should succeed")

	// Verify loaded chain matches original
	AssertEqual(t, len(env.Chain.Checkpoints), len(loaded.Checkpoints), "checkpoint count should match")
	AssertEqual(t, env.Chain.DocumentID, loaded.DocumentID, "document ID should match")

	// Verify loaded chain integrity
	err = loaded.Verify()
	AssertNoError(t, err, "loaded chain should verify")
}

// TestEvidenceStrengthLevels tests that evidence strength is calculated correctly.
func TestEvidenceStrengthLevels(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.InitAll()

	// Create checkpoints
	env.CreateCheckpoint("Initial")
	env.ModifyDocument("\nContent\n")
	env.CreateCheckpoint("Second")

	latest := env.Chain.Latest()

	t.Run("basic_strength", func(t *testing.T) {
		// Declaration only = Basic
		decl := GenerateTestDeclaration(t, latest.ContentHash, latest.Hash, "test.md")
		packet, err := evidence.NewBuilder("test.md", env.Chain).
			WithDeclaration(decl).
			Build()

		AssertNoError(t, err, "build should succeed")
		AssertEqual(t, evidence.Basic, packet.Strength, "declaration only should be Basic strength")
	})

	t.Run("maximum_strength", func(t *testing.T) {
		// Declaration + Behavioral + External = Maximum
		decl := GenerateTestDeclaration(t, latest.ContentHash, latest.Hash, "test.md")

		metrics := &evidence.ForensicMetrics{
			MonotonicAppendRatio:  0.75,
			EditEntropy:           2.5,
			MedianInterval:        30.0,
			PositiveNegativeRatio: 0.8,
			DeletionClustering:    1.1,
			Assessment:            "CONSISTENT WITH HUMAN AUTHORSHIP",
		}

		// Get anchor proofs
		proofs, _ := env.AnchorRegistry.Timestamp(env.Ctx, latest.Hash)

		packet, err := evidence.NewBuilder("test.md", env.Chain).
			WithDeclaration(decl).
			WithBehavioral(nil, metrics).
			WithAnchors(proofs).
			Build()

		AssertNoError(t, err, "build should succeed")
		AssertEqual(t, evidence.Maximum, packet.Strength, "full evidence should be Maximum strength")
	})
}
