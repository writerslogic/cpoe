package declaration

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"
)

// =============================================================================
// Tests for NewDeclaration and Builder
// =============================================================================

func TestNewDeclaration(t *testing.T) {
	docHash := sha256.Sum256([]byte("document"))
	chainHash := sha256.Sum256([]byte("chain"))

	builder := NewDeclaration(docHash, chainHash, "Test Document")

	if builder == nil {
		t.Fatal("NewDeclaration returned nil")
	}
	if builder.decl.DocumentHash != docHash {
		t.Error("document hash mismatch")
	}
	if builder.decl.ChainHash != chainHash {
		t.Error("chain hash mismatch")
	}
	if builder.decl.Title != "Test Document" {
		t.Errorf("title mismatch: got %q", builder.decl.Title)
	}
	if builder.decl.Version != 1 {
		t.Errorf("expected version 1, got %d", builder.decl.Version)
	}
}

func TestBuilderAddModality(t *testing.T) {
	docHash := sha256.Sum256([]byte("doc"))
	chainHash := sha256.Sum256([]byte("chain"))

	builder := NewDeclaration(docHash, chainHash, "Test").
		AddModality(ModalityKeyboard, 80, "main input").
		AddModality(ModalityPaste, 20, "code snippets")

	if len(builder.decl.InputModalities) != 2 {
		t.Fatalf("expected 2 modalities, got %d", len(builder.decl.InputModalities))
	}

	if builder.decl.InputModalities[0].Type != ModalityKeyboard {
		t.Error("first modality should be keyboard")
	}
	if builder.decl.InputModalities[0].Percentage != 80 {
		t.Errorf("expected 80%%, got %v%%", builder.decl.InputModalities[0].Percentage)
	}
}

func TestBuilderAddAITool(t *testing.T) {
	docHash := sha256.Sum256([]byte("doc"))
	chainHash := sha256.Sum256([]byte("chain"))

	builder := NewDeclaration(docHash, chainHash, "Test").
		AddAITool("Claude", "3.5", PurposeFeedback, "reviewed draft", ExtentMinimal)

	if len(builder.decl.AITools) != 1 {
		t.Fatalf("expected 1 AI tool, got %d", len(builder.decl.AITools))
	}

	ai := builder.decl.AITools[0]
	if ai.Tool != "Claude" {
		t.Errorf("expected tool 'Claude', got %q", ai.Tool)
	}
	if ai.Purpose != PurposeFeedback {
		t.Errorf("expected purpose 'feedback', got %q", ai.Purpose)
	}
	if ai.Extent != ExtentMinimal {
		t.Errorf("expected extent 'minimal', got %q", ai.Extent)
	}
}

func TestBuilderAddCollaborator(t *testing.T) {
	docHash := sha256.Sum256([]byte("doc"))
	chainHash := sha256.Sum256([]byte("chain"))

	builder := NewDeclaration(docHash, chainHash, "Test").
		AddCollaborator("Jane Doe", RoleEditor, []string{"chapter 2"})

	if len(builder.decl.Collaborators) != 1 {
		t.Fatalf("expected 1 collaborator, got %d", len(builder.decl.Collaborators))
	}

	collab := builder.decl.Collaborators[0]
	if collab.Name != "Jane Doe" {
		t.Errorf("expected name 'Jane Doe', got %q", collab.Name)
	}
	if collab.Role != RoleEditor {
		t.Errorf("expected role 'editor', got %q", collab.Role)
	}
}

func TestBuilderWithStatement(t *testing.T) {
	docHash := sha256.Sum256([]byte("doc"))
	chainHash := sha256.Sum256([]byte("chain"))

	builder := NewDeclaration(docHash, chainHash, "Test").
		WithStatement("I wrote this entirely by hand")

	if builder.decl.Statement != "I wrote this entirely by hand" {
		t.Error("statement mismatch")
	}
}

// =============================================================================
// Tests for Sign and Verify
// =============================================================================

func TestSign(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	docHash := sha256.Sum256([]byte("doc"))
	chainHash := sha256.Sum256([]byte("chain"))

	decl, err := NewDeclaration(docHash, chainHash, "Test").
		AddModality(ModalityKeyboard, 100, "").
		WithStatement("Test statement").
		Sign(priv)

	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if decl == nil {
		t.Fatal("Sign returned nil declaration")
	}

	// Verify public key was set
	if len(decl.AuthorPublicKey) != ed25519.PublicKeySize {
		t.Error("public key not set correctly")
	}
	if string(decl.AuthorPublicKey) != string(pub) {
		t.Error("public key mismatch")
	}

	// Verify signature was set
	if len(decl.Signature) != ed25519.SignatureSize {
		t.Error("signature not set correctly")
	}
}

func TestVerify(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	docHash := sha256.Sum256([]byte("doc"))
	chainHash := sha256.Sum256([]byte("chain"))

	decl, _ := NewDeclaration(docHash, chainHash, "Test").
		AddModality(ModalityKeyboard, 100, "").
		WithStatement("Test statement").
		Sign(priv)

	if !decl.Verify() {
		t.Error("valid declaration should verify")
	}
}

func TestVerifyCorruptedSignature(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	docHash := sha256.Sum256([]byte("doc"))
	chainHash := sha256.Sum256([]byte("chain"))

	decl, _ := NewDeclaration(docHash, chainHash, "Test").
		AddModality(ModalityKeyboard, 100, "").
		WithStatement("Test statement").
		Sign(priv)

	// Corrupt signature
	decl.Signature[0] ^= 0xff

	if decl.Verify() {
		t.Error("corrupted signature should not verify")
	}
}

func TestVerifyInvalidPublicKey(t *testing.T) {
	decl := &Declaration{
		AuthorPublicKey: make([]byte, 10), // Wrong size
		Signature:       make([]byte, ed25519.SignatureSize),
	}

	if decl.Verify() {
		t.Error("invalid public key should not verify")
	}
}

func TestVerifyInvalidSignature(t *testing.T) {
	decl := &Declaration{
		AuthorPublicKey: make([]byte, ed25519.PublicKeySize),
		Signature:       make([]byte, 10), // Wrong size
	}

	if decl.Verify() {
		t.Error("invalid signature should not verify")
	}
}

// =============================================================================
// Tests for validation
// =============================================================================

func TestValidateMissingDocumentHash(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	chainHash := sha256.Sum256([]byte("chain"))

	_, err := NewDeclaration([32]byte{}, chainHash, "Test").
		AddModality(ModalityKeyboard, 100, "").
		WithStatement("Test").
		Sign(priv)

	if err == nil {
		t.Error("expected error for missing document hash")
	}
}

func TestValidateMissingTitle(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	docHash := sha256.Sum256([]byte("doc"))
	chainHash := sha256.Sum256([]byte("chain"))

	_, err := NewDeclaration(docHash, chainHash, "").
		AddModality(ModalityKeyboard, 100, "").
		WithStatement("Test").
		Sign(priv)

	if err == nil {
		t.Error("expected error for missing title")
	}
}

func TestValidateMissingModalities(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	docHash := sha256.Sum256([]byte("doc"))
	chainHash := sha256.Sum256([]byte("chain"))

	_, err := NewDeclaration(docHash, chainHash, "Test").
		WithStatement("Test").
		Sign(priv)

	if err == nil {
		t.Error("expected error for missing modalities")
	}
}

func TestValidateMissingStatement(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	docHash := sha256.Sum256([]byte("doc"))
	chainHash := sha256.Sum256([]byte("chain"))

	_, err := NewDeclaration(docHash, chainHash, "Test").
		AddModality(ModalityKeyboard, 100, "").
		Sign(priv)

	if err == nil {
		t.Error("expected error for missing statement")
	}
}

func TestValidateModalityPercentageRange(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	docHash := sha256.Sum256([]byte("doc"))
	chainHash := sha256.Sum256([]byte("chain"))

	_, err := NewDeclaration(docHash, chainHash, "Test").
		AddModality(ModalityKeyboard, 150, ""). // Invalid
		WithStatement("Test").
		Sign(priv)

	if err == nil {
		t.Error("expected error for percentage > 100")
	}
}

func TestValidateModalityPercentageSum(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	docHash := sha256.Sum256([]byte("doc"))
	chainHash := sha256.Sum256([]byte("chain"))

	_, err := NewDeclaration(docHash, chainHash, "Test").
		AddModality(ModalityKeyboard, 50, "").
		AddModality(ModalityPaste, 20, ""). // Sum = 70
		WithStatement("Test").
		Sign(priv)

	if err == nil {
		t.Error("expected error for percentages not summing to ~100")
	}
}

func TestValidateModalityPercentageTolerance(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	docHash := sha256.Sum256([]byte("doc"))
	chainHash := sha256.Sum256([]byte("chain"))

	// 97% should be within tolerance
	decl, err := NewDeclaration(docHash, chainHash, "Test").
		AddModality(ModalityKeyboard, 97, "").
		WithStatement("Test").
		Sign(priv)

	if err != nil {
		t.Errorf("97%% should be within tolerance: %v", err)
	}
	if decl == nil {
		t.Error("expected valid declaration")
	}
}

// =============================================================================
// Tests for HasAIUsage and MaxAIExtent
// =============================================================================

func TestHasAIUsage(t *testing.T) {
	docHash := sha256.Sum256([]byte("doc"))
	chainHash := sha256.Sum256([]byte("chain"))

	decl := &Declaration{
		DocumentHash: docHash,
		ChainHash:    chainHash,
		AITools:      []AIToolUsage{},
	}

	if decl.HasAIUsage() {
		t.Error("empty AI tools should return false")
	}

	decl.AITools = append(decl.AITools, AIToolUsage{Tool: "Claude"})

	if !decl.HasAIUsage() {
		t.Error("non-empty AI tools should return true")
	}
}

func TestMaxAIExtent(t *testing.T) {
	tests := []struct {
		name     string
		tools    []AIToolUsage
		expected AIExtent
	}{
		{
			name:     "no tools",
			tools:    []AIToolUsage{},
			expected: ExtentNone,
		},
		{
			name: "single minimal",
			tools: []AIToolUsage{
				{Extent: ExtentMinimal},
			},
			expected: ExtentMinimal,
		},
		{
			name: "multiple - returns max",
			tools: []AIToolUsage{
				{Extent: ExtentMinimal},
				{Extent: ExtentSubstantial},
				{Extent: ExtentModerate},
			},
			expected: ExtentSubstantial,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decl := &Declaration{AITools: tt.tools}
			result := decl.MaxAIExtent()
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestExtentRank(t *testing.T) {
	if extentRank(ExtentNone) >= extentRank(ExtentMinimal) {
		t.Error("none should rank below minimal")
	}
	if extentRank(ExtentMinimal) >= extentRank(ExtentModerate) {
		t.Error("minimal should rank below moderate")
	}
	if extentRank(ExtentModerate) >= extentRank(ExtentSubstantial) {
		t.Error("moderate should rank below substantial")
	}
}

// =============================================================================
// Tests for Encode and Decode
// =============================================================================

func TestEncodeDecode(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	docHash := sha256.Sum256([]byte("doc"))
	chainHash := sha256.Sum256([]byte("chain"))

	original, _ := NewDeclaration(docHash, chainHash, "Test").
		AddModality(ModalityKeyboard, 80, "main").
		AddModality(ModalityPaste, 20, "snippets").
		AddAITool("Claude", "3.5", PurposeFeedback, "review", ExtentMinimal).
		AddCollaborator("Jane", RoleEditor, nil).
		WithStatement("Test statement").
		Sign(priv)

	encoded, err := original.Encode()
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if decoded.Title != original.Title {
		t.Error("title mismatch")
	}
	if len(decoded.InputModalities) != len(original.InputModalities) {
		t.Error("modalities count mismatch")
	}
	if len(decoded.AITools) != len(original.AITools) {
		t.Error("AI tools count mismatch")
	}
	if len(decoded.Collaborators) != len(original.Collaborators) {
		t.Error("collaborators count mismatch")
	}

	// Verify signature still valid
	if !decoded.Verify() {
		t.Error("decoded declaration should verify")
	}
}

func TestDecodeInvalidJSON(t *testing.T) {
	_, err := Decode([]byte("not valid json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

// =============================================================================
// Tests for Summary
// =============================================================================

func TestSummary(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	docHash := sha256.Sum256([]byte("doc"))
	chainHash := sha256.Sum256([]byte("chain"))

	decl, _ := NewDeclaration(docHash, chainHash, "Test Doc").
		AddModality(ModalityKeyboard, 100, "").
		AddAITool("Claude", "", PurposeFeedback, "", ExtentMinimal).
		AddCollaborator("Jane", RoleEditor, nil).
		WithStatement("Test").
		Sign(priv)

	summary := decl.Summary()

	if summary.Title != "Test Doc" {
		t.Error("title mismatch")
	}
	if !summary.AIUsage {
		t.Error("AIUsage should be true")
	}
	if len(summary.AITools) != 1 {
		t.Error("expected 1 AI tool")
	}
	if summary.MaxAIExtent != "minimal" {
		t.Errorf("expected minimal, got %s", summary.MaxAIExtent)
	}
	if summary.Collaborators != 1 {
		t.Error("expected 1 collaborator")
	}
	if !summary.SignatureValid {
		t.Error("signature should be valid")
	}
}

func TestSummaryNoAI(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	docHash := sha256.Sum256([]byte("doc"))
	chainHash := sha256.Sum256([]byte("chain"))

	decl, _ := NewDeclaration(docHash, chainHash, "Test").
		AddModality(ModalityKeyboard, 100, "").
		WithStatement("Test").
		Sign(priv)

	summary := decl.Summary()

	if summary.AIUsage {
		t.Error("AIUsage should be false")
	}
	if summary.MaxAIExtent != "none" {
		t.Errorf("expected none, got %s", summary.MaxAIExtent)
	}
}

// =============================================================================
// Tests for template functions
// =============================================================================

func TestNoAIDeclaration(t *testing.T) {
	docHash := sha256.Sum256([]byte("doc"))
	chainHash := sha256.Sum256([]byte("chain"))

	builder := NoAIDeclaration(docHash, chainHash, "My Essay", "I wrote this without AI")

	if len(builder.decl.InputModalities) != 1 {
		t.Error("expected 1 modality")
	}
	if builder.decl.InputModalities[0].Type != ModalityKeyboard {
		t.Error("expected keyboard modality")
	}
	if builder.decl.InputModalities[0].Percentage != 100 {
		t.Error("expected 100%")
	}
	if builder.decl.Statement == "" {
		t.Error("statement should be set")
	}
}

func TestAIAssistedDeclaration(t *testing.T) {
	docHash := sha256.Sum256([]byte("doc"))
	chainHash := sha256.Sum256([]byte("chain"))

	builder := AIAssistedDeclaration(docHash, chainHash, "AI Project")

	if builder.decl.Title != "AI Project" {
		t.Error("title mismatch")
	}
}

// =============================================================================
// Tests for constants
// =============================================================================

func TestModalityTypes(t *testing.T) {
	types := []ModalityType{
		ModalityKeyboard,
		ModalityDictation,
		ModalityHandwriting,
		ModalityPaste,
		ModalityImport,
		ModalityMixed,
		ModalityOther,
	}

	for _, m := range types {
		if m == "" {
			t.Error("modality type should not be empty")
		}
	}
}

func TestAIPurposes(t *testing.T) {
	purposes := []AIPurpose{
		PurposeIdeation,
		PurposeOutline,
		PurposeDrafting,
		PurposeFeedback,
		PurposeEditing,
		PurposeResearch,
		PurposeFormatting,
		PurposeOther,
	}

	for _, p := range purposes {
		if p == "" {
			t.Error("AI purpose should not be empty")
		}
	}
}

func TestAIExtents(t *testing.T) {
	extents := []AIExtent{
		ExtentNone,
		ExtentMinimal,
		ExtentModerate,
		ExtentSubstantial,
	}

	for _, e := range extents {
		if e == "" {
			t.Error("AI extent should not be empty")
		}
	}
}

func TestCollaboratorRoles(t *testing.T) {
	roles := []CollaboratorRole{
		RoleCoAuthor,
		RoleEditor,
		RoleResearchAssistant,
		RoleReviewer,
		RoleTranscriber,
		RoleOther,
	}

	for _, r := range roles {
		if r == "" {
			t.Error("collaborator role should not be empty")
		}
	}
}

// =============================================================================
// Tests for JSON serialization of types
// =============================================================================

func TestInputModalityJSON(t *testing.T) {
	m := InputModality{
		Type:       ModalityKeyboard,
		Percentage: 75.5,
		Note:       "main input",
	}

	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded InputModality
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if decoded.Type != m.Type {
		t.Error("type mismatch")
	}
	if decoded.Percentage != m.Percentage {
		t.Error("percentage mismatch")
	}
}

func TestAIToolUsageJSON(t *testing.T) {
	ai := AIToolUsage{
		Tool:        "Claude",
		Version:     "3.5",
		Purpose:     PurposeFeedback,
		Interaction: "reviewed draft",
		Extent:      ExtentModerate,
		Sections:    []string{"chapter 1", "conclusion"},
	}

	data, err := json.Marshal(ai)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded AIToolUsage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if decoded.Tool != ai.Tool {
		t.Error("tool mismatch")
	}
	if len(decoded.Sections) != 2 {
		t.Error("sections count mismatch")
	}
}

func TestDeclarationSummaryJSON(t *testing.T) {
	s := DeclarationSummary{
		Title:          "Test",
		AIUsage:        true,
		AITools:        []string{"Claude", "GPT-4"},
		MaxAIExtent:    "moderate",
		Collaborators:  2,
		SignatureValid: true,
	}

	data, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded DeclarationSummary
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if !decoded.AIUsage {
		t.Error("AIUsage mismatch")
	}
	if len(decoded.AITools) != 2 {
		t.Error("AITools count mismatch")
	}
}

// =============================================================================
// Test signing payload determinism
// =============================================================================

func TestSigningPayloadDeterminism(t *testing.T) {
	docHash := sha256.Sum256([]byte("doc"))
	chainHash := sha256.Sum256([]byte("chain"))
	fixedTime := time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC)

	decl := &Declaration{
		DocumentHash: docHash,
		ChainHash:    chainHash,
		Title:        "Test",
		InputModalities: []InputModality{
			{Type: ModalityKeyboard, Percentage: 100},
		},
		Statement:       "Test statement",
		CreatedAt:       fixedTime,
		AuthorPublicKey: make([]byte, 32),
	}

	payload1 := decl.signingPayload()
	payload2 := decl.signingPayload()

	if string(payload1) != string(payload2) {
		t.Error("signing payload should be deterministic")
	}
}

// Fuzz tests for declaration parsing

func FuzzDecode(f *testing.F) {
	// Add seed corpus with valid declaration JSON
	docHash := sha256.Sum256([]byte("document"))
	chainHash := sha256.Sum256([]byte("chain"))
	pub, priv, _ := ed25519.GenerateKey(nil)

	decl, _ := NewDeclaration(docHash, chainHash, "Test Document").
		AddModality(ModalityKeyboard, 100, "").
		WithStatement("I wrote this").
		Sign(priv)
	validJSON, _ := decl.Encode()
	f.Add(validJSON)

	// Add unsigned declaration
	unsignedDecl := &Declaration{
		DocumentHash: docHash,
		ChainHash:    chainHash,
		Title:        "Test",
		InputModalities: []InputModality{
			{Type: ModalityKeyboard, Percentage: 100},
		},
		Statement:       "Test statement",
		AuthorPublicKey: pub,
	}
	unsignedJSON, _ := json.Marshal(unsignedDecl)
	f.Add(unsignedJSON)

	// Add various malformed JSON
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"title":"test"}`))
	f.Add([]byte(`invalid json`))
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`{"document_hash":"not-base64"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Decode should not panic on any input
		decl, err := Decode(data)
		if err != nil {
			// Errors are expected for invalid input
			return
		}

		// If decoding succeeded, validate basic structure
		if decl == nil {
			t.Error("Decode returned nil declaration without error")
			return
		}

		// Re-encode should not panic
		reencoded, err := decl.Encode()
		if err != nil {
			t.Errorf("Failed to re-encode successfully decoded declaration: %v", err)
			return
		}

		// Re-decode should work
		decl2, err := Decode(reencoded)
		if err != nil {
			t.Errorf("Failed to decode re-encoded declaration: %v", err)
			return
		}

		// Basic field comparison
		if decl.Title != decl2.Title {
			t.Error("Title mismatch after re-encode")
		}
		if decl.Statement != decl2.Statement {
			t.Error("Statement mismatch after re-encode")
		}
	})
}
