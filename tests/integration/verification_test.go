//go:build integration

package integration

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"witnessd/internal/checkpoint"
	"witnessd/internal/declaration"
	"witnessd/internal/evidence"
	"witnessd/internal/keyhierarchy"
	"witnessd/internal/mmr"
	"witnessd/internal/verify"
	"witnessd/internal/vdf"
)

// TestVerificationPipelineComplete tests the complete verification pipeline.
func TestVerificationPipelineComplete(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.InitAll()

	// Create checkpoints
	for i := 0; i < 5; i++ {
		env.ModifyDocument("\nContent section " + string(rune('A'+i)))
		cp := env.CreateCheckpoint("Section " + string(rune('A'+i)))
		env.SignCheckpoint(cp)
		time.Sleep(10 * time.Millisecond)
	}

	// Build complete evidence packet
	latest := env.Chain.Latest()
	decl := GenerateTestDeclaration(t, latest.ContentHash, latest.Hash, "test_document.md")

	// Get anchor proofs
	proofs, _ := env.AnchorRegistry.Timestamp(env.Ctx, latest.Hash)

	packet, err := evidence.NewBuilder("test_document.md", env.Chain).
		WithDeclaration(decl).
		WithAnchors(proofs).
		Build()

	AssertNoError(t, err, "evidence packet build should succeed")

	// Verify the complete packet
	err = packet.Verify(env.VDFParams)
	AssertNoError(t, err, "complete packet should verify")

	t.Run("verify_chain_integrity", func(t *testing.T) {
		// Verify checkpoint chain
		for i, cp := range packet.Checkpoints {
			if i > 0 {
				AssertEqual(t, packet.Checkpoints[i-1].Hash, cp.PreviousHash,
					"checkpoint %d should link to previous", i)
			}
		}
	})

	t.Run("verify_declaration", func(t *testing.T) {
		// Verify declaration signature
		AssertTrue(t, packet.Declaration != nil, "should have declaration")
		AssertTrue(t, len(packet.Declaration.Signature) > 0, "should have signature")
	})

	t.Run("verify_claims", func(t *testing.T) {
		// Should have chain integrity claim
		hasChainClaim := false
		for _, claim := range packet.Claims {
			if claim.Type == evidence.ClaimChainIntegrity {
				hasChainClaim = true
				break
			}
		}
		AssertTrue(t, hasChainClaim, "should have chain integrity claim")
	})
}

// TestVerificationPipelineWithTampering tests that tampering is detected.
func TestVerificationPipelineWithTampering(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.InitPUF()
	env.InitKeyHierarchy()
	env.InitChain()

	// Create checkpoints
	for i := 0; i < 3; i++ {
		env.ModifyDocument("\nContent " + string(rune('1'+i)))
		env.CreateCheckpoint("Commit " + string(rune('1'+i)))
	}

	latest := env.Chain.Latest()
	decl := GenerateTestDeclaration(t, latest.ContentHash, latest.Hash, "test.md")

	packet, _ := evidence.NewBuilder("test.md", env.Chain).
		WithDeclaration(decl).
		Build()

	t.Run("tamper_checkpoint_hash", func(t *testing.T) {
		// Make a copy to tamper with
		tamperedPacket := *packet
		tamperedPacket.Checkpoints = make([]evidence.CheckpointRecord, len(packet.Checkpoints))
		copy(tamperedPacket.Checkpoints, packet.Checkpoints)

		// Tamper with a checkpoint hash
		if len(tamperedPacket.Checkpoints) > 1 {
			tamperedPacket.Checkpoints[1].Hash = "0000000000000000000000000000000000000000000000000000000000000000"

			err := tamperedPacket.Verify(env.VDFParams)
			AssertError(t, err, "tampered checkpoint hash should fail verification")
		}
	})

	t.Run("tamper_chain_link", func(t *testing.T) {
		tamperedPacket := *packet
		tamperedPacket.Checkpoints = make([]evidence.CheckpointRecord, len(packet.Checkpoints))
		copy(tamperedPacket.Checkpoints, packet.Checkpoints)

		// Break chain link
		if len(tamperedPacket.Checkpoints) > 1 {
			tamperedPacket.Checkpoints[1].PreviousHash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

			err := tamperedPacket.Verify(env.VDFParams)
			AssertError(t, err, "broken chain link should fail verification")
		}
	})

	t.Run("tamper_declaration_signature", func(t *testing.T) {
		tamperedPacket := *packet
		if tamperedPacket.Declaration != nil {
			// Copy declaration and tamper signature
			tamperedDecl := *tamperedPacket.Declaration
			tamperedDecl.Signature = []byte("invalid-signature")
			tamperedPacket.Declaration = &tamperedDecl

			err := tamperedPacket.Verify(env.VDFParams)
			AssertError(t, err, "invalid declaration signature should fail")
		}
	})
}

// TestVerificationPipelineKeyHierarchy tests key hierarchy verification.
func TestVerificationPipelineKeyHierarchy(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.InitPUF()
	env.InitKeyHierarchy()
	env.InitChain()

	// Create and sign checkpoints
	for i := 0; i < 5; i++ {
		env.ModifyDocument("\nParagraph " + string(rune('A'+i)))
		cp := env.CreateCheckpoint("Paragraph " + string(rune('A'+i)))
		env.SignCheckpoint(cp)
	}

	// Export key hierarchy evidence
	keyEvidence := env.Session.Export(env.MasterIdentity)

	t.Run("verify_session_certificate", func(t *testing.T) {
		err := keyhierarchy.VerifySessionCertificate(keyEvidence.SessionCertificate)
		AssertNoError(t, err, "session certificate should verify")
	})

	t.Run("verify_master_identity_match", func(t *testing.T) {
		// Master public key in certificate should match identity
		certMasterKey := keyEvidence.SessionCertificate.MasterPubKey
		identityKey := keyEvidence.MasterIdentity.PublicKey

		AssertEqual(t, string(certMasterKey), string(identityKey),
			"certificate master key should match identity")
	})

	t.Run("verify_checkpoint_signatures", func(t *testing.T) {
		err := keyhierarchy.VerifyCheckpointSignatures(keyEvidence.CheckpointSignatures)
		AssertNoError(t, err, "checkpoint signatures should verify")

		// Verify ordinals are sequential
		for i, sig := range keyEvidence.CheckpointSignatures {
			AssertEqual(t, uint64(i), sig.Ordinal, "ordinal should be sequential")
		}
	})

	t.Run("verify_ratchet_uniqueness", func(t *testing.T) {
		// Each signature should use a unique public key (ratcheting)
		seenKeys := make(map[string]bool)
		for i, sig := range keyEvidence.CheckpointSignatures {
			keyHex := hex.EncodeToString(sig.PublicKey)
			if seenKeys[keyHex] {
				t.Errorf("checkpoint %d reused key from earlier checkpoint", i)
			}
			seenKeys[keyHex] = true
		}
	})

	t.Run("verify_full_hierarchy", func(t *testing.T) {
		err := keyhierarchy.VerifyKeyHierarchy(keyEvidence)
		AssertNoError(t, err, "full key hierarchy should verify")
	})

	t.Run("tampered_certificate_fails", func(t *testing.T) {
		// Copy and tamper with certificate
		tamperedCert := *keyEvidence.SessionCertificate
		tamperedCert.Signature[0] ^= 0xff

		err := keyhierarchy.VerifySessionCertificate(&tamperedCert)
		AssertError(t, err, "tampered certificate should fail")
	})

	t.Run("tampered_checkpoint_signature_fails", func(t *testing.T) {
		if len(keyEvidence.CheckpointSignatures) > 0 {
			// Copy signatures and tamper
			tamperedSigs := make([]keyhierarchy.CheckpointSignature, len(keyEvidence.CheckpointSignatures))
			copy(tamperedSigs, keyEvidence.CheckpointSignatures)
			tamperedSigs[0].Signature[0] ^= 0xff

			err := keyhierarchy.VerifyCheckpointSignatures(tamperedSigs)
			AssertError(t, err, "tampered checkpoint signature should fail")
		}
	})
}

// TestVerificationPipelineVDF tests VDF proof verification.
func TestVerificationPipelineVDF(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.InitChain()

	// Create checkpoints with delays to ensure VDF proofs
	env.CreateCheckpoint("Initial")

	for i := 0; i < 3; i++ {
		time.Sleep(50 * time.Millisecond) // Ensure measurable elapsed time
		env.ModifyDocument("\nContent " + string(rune('1'+i)))
		env.CreateCheckpoint("Commit " + string(rune('1'+i)))
	}

	t.Run("verify_vdf_proofs_present", func(t *testing.T) {
		for i, cp := range env.Chain.Checkpoints {
			if i == 0 {
				AssertTrue(t, cp.VDF == nil, "first checkpoint should not have VDF")
			} else {
				AssertTrue(t, cp.VDF != nil, "checkpoint %d should have VDF", i)
			}
		}
	})

	t.Run("verify_vdf_input_binding", func(t *testing.T) {
		for i, cp := range env.Chain.Checkpoints {
			if cp.VDF != nil {
				// Verify VDF input is correctly derived
				expectedInput := vdf.ChainInput(cp.ContentHash, cp.PreviousHash, cp.Ordinal)
				AssertEqual(t, expectedInput, cp.VDF.Input,
					"checkpoint %d VDF input should match expected", i)
			}
		}
	})

	t.Run("verify_vdf_proofs", func(t *testing.T) {
		for i, cp := range env.Chain.Checkpoints {
			if cp.VDF != nil {
				valid := vdf.Verify(cp.VDF)
				AssertTrue(t, valid, "checkpoint %d VDF should verify", i)
			}
		}
	})

	t.Run("invalid_vdf_fails", func(t *testing.T) {
		// Create an invalid VDF proof
		if len(env.Chain.Checkpoints) > 1 {
			cp := env.Chain.Checkpoints[1]
			originalOutput := cp.VDF.Output

			// Tamper with output
			cp.VDF.Output[0] ^= 0xff
			valid := vdf.Verify(cp.VDF)
			AssertFalse(t, valid, "tampered VDF should not verify")

			// Restore
			cp.VDF.Output = originalOutput
		}
	})

	t.Run("total_elapsed_time", func(t *testing.T) {
		elapsed := env.Chain.TotalElapsedTime()
		t.Logf("Total VDF-proven elapsed time: %v", elapsed)
		AssertTrue(t, elapsed >= 0, "elapsed time should be non-negative")
	})
}

// TestVerificationPipelineMMR tests MMR proof verification.
func TestVerificationPipelineMMR(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/mmr.db"

	// Create MMR and add some entries
	store, err := mmr.OpenFileStore(dbPath)
	AssertNoError(t, err, "should open store")
	defer store.Close()

	m, err := mmr.New(store)
	AssertNoError(t, err, "should create MMR")

	// Add entries
	var positions []uint64
	var hashes [][32]byte

	for i := 0; i < 5; i++ {
		hash := sha256.Sum256([]byte("entry " + string(rune('A'+i))))
		pos, err := m.Append(hash[:])
		AssertNoError(t, err, "should append to MMR")
		positions = append(positions, pos)
		hashes = append(hashes, hash)
	}

	t.Run("verify_proof_for_each_entry", func(t *testing.T) {
		for i, pos := range positions {
			proof, err := m.GetProof(pos)
			AssertNoError(t, err, "should get proof for position %d", pos)

			// Verify proof
			leafHash := mmr.HashLeaf(hashes[i][:])
			valid := m.VerifyProof(leafHash, pos, proof)
			AssertTrue(t, valid, "proof for entry %d should verify", i)
		}
	})

	t.Run("tampered_proof_fails", func(t *testing.T) {
		if len(positions) > 0 {
			proof, _ := m.GetProof(positions[0])

			// Tamper with proof
			if len(proof.Path) > 0 {
				proof.Path[0][0] ^= 0xff

				leafHash := mmr.HashLeaf(hashes[0][:])
				valid := m.VerifyProof(leafHash, positions[0], proof)
				AssertFalse(t, valid, "tampered proof should not verify")
			}
		}
	})

	t.Run("wrong_hash_fails", func(t *testing.T) {
		if len(positions) > 0 {
			proof, _ := m.GetProof(positions[0])

			// Use wrong hash
			wrongHash := sha256.Sum256([]byte("wrong data"))
			wrongLeaf := mmr.HashLeaf(wrongHash[:])

			valid := m.VerifyProof(wrongLeaf, positions[0], proof)
			AssertFalse(t, valid, "wrong hash should not verify")
		}
	})
}

// TestVerificationPipelineDeclaration tests declaration verification.
func TestVerificationPipelineDeclaration(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.InitChain()
	env.CreateCheckpoint("Initial")

	latest := env.Chain.Latest()

	t.Run("valid_declaration_verifies", func(t *testing.T) {
		decl := GenerateTestDeclaration(t, latest.ContentHash, latest.Hash, "test.md")

		// Verify signature
		valid := ed25519.Verify(decl.AuthorKey, decl.SignedData(), decl.Signature)
		AssertTrue(t, valid, "declaration signature should verify")
	})

	t.Run("declaration_with_ai_tools", func(t *testing.T) {
		decl := GenerateTestDeclarationWithAI(t, latest.ContentHash, latest.Hash, "test.md")

		AssertTrue(t, len(decl.AITools) > 0, "should have AI tools declared")
		AssertEqual(t, "Claude", decl.AITools[0].Name, "should have Claude declared")
	})

	t.Run("tampered_declaration_fails", func(t *testing.T) {
		_, priv, _ := ed25519.GenerateKey(nil)

		decl, _ := declaration.NewDeclaration(latest.ContentHash, latest.Hash, "test.md").
			AddModality(declaration.ModalityKeyboard, 100, "").
			WithStatement("Original statement").
			Sign(priv)

		// Tamper with statement after signing
		decl.Statement = "Modified statement"

		// Verification should fail
		valid := ed25519.Verify(decl.AuthorKey, decl.SignedData(), decl.Signature)
		AssertFalse(t, valid, "tampered declaration should not verify")
	})

	t.Run("wrong_key_fails", func(t *testing.T) {
		_, priv, _ := ed25519.GenerateKey(nil)
		wrongPub, _, _ := ed25519.GenerateKey(nil)

		decl, _ := declaration.NewDeclaration(latest.ContentHash, latest.Hash, "test.md").
			AddModality(declaration.ModalityKeyboard, 100, "").
			WithStatement("Test").
			Sign(priv)

		// Try to verify with wrong key
		valid := ed25519.Verify(wrongPub, decl.SignedData(), decl.Signature)
		AssertFalse(t, valid, "wrong key should not verify")
	})
}

// TestVerificationPipelineAnchorProofs tests anchor proof verification.
func TestVerificationPipelineAnchorProofs(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.InitAnchors()

	testHash := sha256.Sum256([]byte("test data"))

	t.Run("create_and_verify_anchor", func(t *testing.T) {
		proofs, err := env.AnchorRegistry.Timestamp(env.Ctx, testHash)
		AssertNoError(t, err, "should create anchor")
		AssertTrue(t, len(proofs) > 0, "should have proof")

		// Verify
		result, err := env.AnchorRegistry.Verify(env.Ctx, proofs[0])
		AssertNoError(t, err, "should verify anchor")
		AssertTrue(t, result.Valid, "anchor should be valid")
		AssertEqual(t, testHash, result.Hash, "hash should match")
	})

	t.Run("anchor_contains_expected_fields", func(t *testing.T) {
		proofs, _ := env.AnchorRegistry.Timestamp(env.Ctx, testHash)

		proof := proofs[0]
		AssertTrue(t, proof.Provider != "", "should have provider")
		AssertTrue(t, !proof.Timestamp.IsZero(), "should have timestamp")
		AssertEqual(t, testHash, proof.Hash, "should have correct hash")
	})
}

// TestVerificationPipelineEvidenceEncoding tests evidence packet encoding/decoding.
func TestVerificationPipelineEvidenceEncoding(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.InitAll()

	// Create packet
	env.CreateCheckpoint("Initial")
	env.ModifyDocument("\nMore content\n")
	env.CreateCheckpoint("Second")

	latest := env.Chain.Latest()
	decl := GenerateTestDeclaration(t, latest.ContentHash, latest.Hash, "test.md")

	original, _ := evidence.NewBuilder("test.md", env.Chain).
		WithDeclaration(decl).
		Build()

	t.Run("encode_decode_roundtrip", func(t *testing.T) {
		// Encode
		data, err := original.Encode()
		AssertNoError(t, err, "encode should succeed")
		AssertTrue(t, len(data) > 0, "encoded data should not be empty")

		// Decode
		decoded, err := evidence.Decode(data)
		AssertNoError(t, err, "decode should succeed")

		// Verify fields match
		AssertEqual(t, original.Version, decoded.Version, "version should match")
		AssertEqual(t, original.Document.Title, decoded.Document.Title, "title should match")
		AssertEqual(t, len(original.Checkpoints), len(decoded.Checkpoints), "checkpoint count should match")
		AssertEqual(t, len(original.Claims), len(decoded.Claims), "claims count should match")
	})

	t.Run("decoded_packet_verifies", func(t *testing.T) {
		data, _ := original.Encode()
		decoded, _ := evidence.Decode(data)

		err := decoded.Verify(env.VDFParams)
		AssertNoError(t, err, "decoded packet should verify")
	})

	t.Run("hash_is_deterministic", func(t *testing.T) {
		hash1 := original.Hash()
		hash2 := original.Hash()

		AssertEqual(t, hash1, hash2, "hash should be deterministic")
		AssertNotEqual(t, [32]byte{}, hash1, "hash should not be zero")
	})
}

// TestVerificationPipelineEdgeCases tests edge cases in verification.
func TestVerificationPipelineEdgeCases(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.InitChain()

	t.Run("empty_chain", func(t *testing.T) {
		err := env.Chain.Verify()
		AssertNoError(t, err, "empty chain should verify")
	})

	t.Run("single_checkpoint", func(t *testing.T) {
		env.CreateCheckpoint("Only checkpoint")

		err := env.Chain.Verify()
		AssertNoError(t, err, "single checkpoint chain should verify")
	})

	t.Run("evidence_without_declaration_fails", func(t *testing.T) {
		env2 := NewTestEnv(t)
		defer env2.Cleanup()
		env2.InitChain()
		env2.CreateCheckpoint("Test")

		_, err := evidence.NewBuilder("test.md", env2.Chain).Build()
		AssertError(t, err, "evidence without declaration should fail")
	})

	t.Run("nil_input_handling", func(t *testing.T) {
		_, err := evidence.Decode(nil)
		AssertError(t, err, "nil input should error")

		_, err = evidence.Decode([]byte{})
		AssertError(t, err, "empty input should error")

		_, err = evidence.Decode([]byte("not json"))
		AssertError(t, err, "invalid json should error")
	})
}

// TestVerificationPipelinePerformance tests verification performance.
func TestVerificationPipelinePerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping performance test in short mode")
	}

	env := NewTestEnv(t)
	defer env.Cleanup()

	env.InitAll()

	// Create many checkpoints
	checkpointCount := 100
	for i := 0; i < checkpointCount; i++ {
		env.ModifyDocument("\nContent " + string(rune('0'+i%10)))
		cp := env.CreateCheckpoint("Commit")
		env.SignCheckpoint(cp)
	}

	latest := env.Chain.Latest()
	decl := GenerateTestDeclaration(t, latest.ContentHash, latest.Hash, "test.md")

	packet, _ := evidence.NewBuilder("test.md", env.Chain).
		WithDeclaration(decl).
		Build()

	t.Run("chain_verification_performance", func(t *testing.T) {
		start := time.Now()
		err := env.Chain.Verify()
		elapsed := time.Since(start)

		AssertNoError(t, err, "chain should verify")
		t.Logf("Chain verification of %d checkpoints took %v", checkpointCount, elapsed)

		// Should complete in reasonable time (< 5 seconds for 100 checkpoints)
		AssertTrue(t, elapsed < 5*time.Second, "verification should be fast")
	})

	t.Run("packet_verification_performance", func(t *testing.T) {
		start := time.Now()
		err := packet.Verify(env.VDFParams)
		elapsed := time.Since(start)

		AssertNoError(t, err, "packet should verify")
		t.Logf("Packet verification took %v", elapsed)
	})

	t.Run("key_signature_verification_performance", func(t *testing.T) {
		signatures := env.Session.Signatures()

		start := time.Now()
		err := keyhierarchy.VerifyCheckpointSignatures(signatures)
		elapsed := time.Since(start)

		AssertNoError(t, err, "signatures should verify")
		t.Logf("Signature verification of %d signatures took %v", len(signatures), elapsed)
	})
}

// TestVerifierIntegration tests the verify package integration.
func TestVerifierIntegration(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test MMR database
	dbPath := tmpDir + "/mmr.db"
	store, err := mmr.OpenFileStore(dbPath)
	AssertNoError(t, err, "should open store")

	m, err := mmr.New(store)
	AssertNoError(t, err, "should create MMR")

	// Add test entry
	testHash := sha256.Sum256([]byte("test content"))
	_, err = m.Append(testHash[:])
	AssertNoError(t, err, "should append")
	store.Close()

	// Create public key file
	pub, _, _ := ed25519.GenerateKey(nil)
	pubKeyPath := tmpDir + "/key.pub"
	err = os.WriteFile(pubKeyPath, pub, 0600)
	AssertNoError(t, err, "should write pub key")

	// Create verifier
	verifier, err := verify.NewVerifier(dbPath, pubKeyPath, "")
	AssertNoError(t, err, "should create verifier")
	defer verifier.Close()
}
