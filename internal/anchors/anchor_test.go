package anchors

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

// MockAnchor implements Anchor interface for testing
type MockAnchor struct {
	name      string
	commitErr error
	verifyErr error
	proof     []byte
}

func (m *MockAnchor) Name() string { return m.name }

func (m *MockAnchor) Commit(hash []byte) ([]byte, error) {
	if m.commitErr != nil {
		return nil, m.commitErr
	}
	if m.proof != nil {
		return m.proof, nil
	}
	return append([]byte("proof:"), hash...), nil
}

func (m *MockAnchor) Verify(hash, proof []byte) error {
	return m.verifyErr
}

func TestNewRegistry(t *testing.T) {
	r := NewRegistry("/tmp/test")
	if r == nil {
		t.Fatal("NewRegistry returned nil")
	}
	if r.storagePath != "/tmp/test" {
		t.Errorf("expected storage path /tmp/test, got %s", r.storagePath)
	}
	if len(r.anchors) != 0 {
		t.Errorf("expected empty anchors map, got %d entries", len(r.anchors))
	}
}

func TestRegistryRegister(t *testing.T) {
	r := NewRegistry("")
	mock := &MockAnchor{name: "test"}

	r.Register(mock)

	if len(r.anchors) != 1 {
		t.Errorf("expected 1 anchor, got %d", len(r.anchors))
	}
	if _, ok := r.anchors["test"]; !ok {
		t.Error("anchor not registered with correct name")
	}
}

func TestRegistryGet(t *testing.T) {
	r := NewRegistry("")
	mock := &MockAnchor{name: "test"}
	r.Register(mock)

	// Test found
	a, ok := r.Get("test")
	if !ok {
		t.Error("expected anchor to be found")
	}
	if a.Name() != "test" {
		t.Errorf("expected name 'test', got '%s'", a.Name())
	}

	// Test not found
	_, ok = r.Get("nonexistent")
	if ok {
		t.Error("expected anchor not to be found")
	}
}

func TestRegistryList(t *testing.T) {
	r := NewRegistry("")
	r.Register(&MockAnchor{name: "a"})
	r.Register(&MockAnchor{name: "b"})
	r.Register(&MockAnchor{name: "c"})

	names := r.List()
	if len(names) != 3 {
		t.Errorf("expected 3 names, got %d", len(names))
	}

	// Check all names are present (order may vary due to map iteration)
	nameMap := make(map[string]bool)
	for _, n := range names {
		nameMap[n] = true
	}
	for _, expected := range []string{"a", "b", "c"} {
		if !nameMap[expected] {
			t.Errorf("expected name %s in list", expected)
		}
	}
}

func TestRegistryCommitAll(t *testing.T) {
	tmpDir := t.TempDir()
	r := NewRegistry(tmpDir)
	r.Register(&MockAnchor{name: "ots", proof: []byte("ots-proof")})
	r.Register(&MockAnchor{name: "rfc3161", proof: []byte("rfc-proof")})

	hash := sha256.Sum256([]byte("test data"))
	receipts, err := r.CommitAll(hash[:])
	if err != nil {
		t.Fatalf("CommitAll failed: %v", err)
	}

	if len(receipts) != 2 {
		t.Errorf("expected 2 receipts, got %d", len(receipts))
	}

	for _, receipt := range receipts {
		if receipt.Status != "pending" {
			t.Errorf("expected status 'pending', got '%s'", receipt.Status)
		}
		if receipt.Hash != hex.EncodeToString(hash[:]) {
			t.Error("receipt hash doesn't match input")
		}
	}
}

func TestRegistryCommitAllWithFailure(t *testing.T) {
	r := NewRegistry("")
	r.Register(&MockAnchor{name: "failing", commitErr: errTest})

	hash := sha256.Sum256([]byte("test"))
	receipts, err := r.CommitAll(hash[:])
	if err != nil {
		t.Fatalf("CommitAll should not return error: %v", err)
	}

	if len(receipts) != 1 {
		t.Fatalf("expected 1 receipt, got %d", len(receipts))
	}
	if receipts[0].Status != "failed" {
		t.Errorf("expected status 'failed', got '%s'", receipts[0].Status)
	}
}

func TestRegistrySaveAndLoadReceipts(t *testing.T) {
	tmpDir := t.TempDir()
	r := NewRegistry(tmpDir)

	// Manually save a receipt
	receipt := Receipt{
		Type:      "test",
		Hash:      "abcd1234567890ab",
		Proof:     []byte("test proof data"),
		Timestamp: time.Now().UTC(),
		Status:    "pending",
	}
	if err := r.saveReceipt(receipt); err != nil {
		t.Fatalf("saveReceipt failed: %v", err)
	}

	// Load receipts
	receipts, err := r.LoadReceipts()
	if err != nil {
		t.Fatalf("LoadReceipts failed: %v", err)
	}

	if len(receipts) != 1 {
		t.Errorf("expected 1 receipt, got %d", len(receipts))
	}
	if receipts[0].Type != "test" {
		t.Errorf("expected type 'test', got '%s'", receipts[0].Type)
	}
}

func TestRegistryLoadReceiptsEmpty(t *testing.T) {
	r := NewRegistry("")
	receipts, err := r.LoadReceipts()
	if err != nil {
		t.Fatalf("LoadReceipts failed: %v", err)
	}
	if receipts != nil {
		t.Errorf("expected nil receipts for empty path, got %v", receipts)
	}
}

func TestRegistryLoadReceiptsNonexistent(t *testing.T) {
	r := NewRegistry("/nonexistent/path/12345")
	receipts, err := r.LoadReceipts()
	if err != nil {
		t.Fatalf("LoadReceipts failed: %v", err)
	}
	if receipts != nil {
		t.Errorf("expected nil receipts for nonexistent path")
	}
}

var errTest = errorString("test error")

type errorString string

func (e errorString) Error() string { return string(e) }

// OTS Tests

func TestOTSAnchorName(t *testing.T) {
	ots := NewOTSAnchor()
	if ots.Name() != "ots" {
		t.Errorf("expected name 'ots', got '%s'", ots.Name())
	}
}

func TestOTSAnchorCommitInvalidHash(t *testing.T) {
	ots := NewOTSAnchor()
	_, err := ots.Commit([]byte("short"))
	if err == nil {
		t.Error("expected error for invalid hash length")
	}
}

func TestOTSAnchorCommitWithMockServer(t *testing.T) {
	// Create a mock calendar server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/digest" {
			t.Errorf("expected /digest, got %s", r.URL.Path)
		}
		w.Write([]byte("calendar-response"))
	}))
	defer server.Close()

	ots := &OTSAnchor{
		calendars: []string{server.URL},
		client:    &http.Client{Timeout: 5 * time.Second},
	}

	hash := sha256.Sum256([]byte("test"))
	proof, err := ots.Commit(hash[:])
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	// Verify proof contains OTS header
	if !bytes.HasPrefix(proof, []byte(otsHeaderMagic)) {
		t.Error("proof should start with OTS header magic")
	}
}

func TestOTSAnchorCommitAllCalendarsFail(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	ots := &OTSAnchor{
		calendars: []string{server.URL},
		client:    &http.Client{Timeout: 5 * time.Second},
	}

	hash := sha256.Sum256([]byte("test"))
	_, err := ots.Commit(hash[:])
	if err == nil {
		t.Error("expected error when all calendars fail")
	}
}

func TestOTSAnchorVerify(t *testing.T) {
	ots := NewOTSAnchor()

	// Create a valid OTS proof header
	var buf bytes.Buffer
	buf.WriteString(otsHeaderMagic)
	buf.WriteByte(otsVersion)
	buf.WriteByte(0x08) // SHA256
	buf.Write(make([]byte, 32))

	err := ots.Verify(nil, buf.Bytes())
	if err != nil {
		t.Errorf("Verify failed for valid proof: %v", err)
	}
}

func TestOTSAnchorVerifyTooShort(t *testing.T) {
	ots := NewOTSAnchor()
	err := ots.Verify(nil, []byte("short"))
	if err == nil {
		t.Error("expected error for short proof")
	}
}

func TestOTSAnchorVerifyInvalidMagic(t *testing.T) {
	ots := NewOTSAnchor()
	proof := make([]byte, 100)
	err := ots.Verify(nil, proof)
	if err == nil {
		t.Error("expected error for invalid magic")
	}
}

func TestOTSAnchorVerifyInvalidVersion(t *testing.T) {
	ots := NewOTSAnchor()
	var buf bytes.Buffer
	buf.WriteString(otsHeaderMagic)
	buf.WriteByte(99) // Invalid version
	buf.Write(make([]byte, 50))

	err := ots.Verify(nil, buf.Bytes())
	if err == nil {
		t.Error("expected error for invalid version")
	}
}

func TestOTSWrapProof(t *testing.T) {
	ots := NewOTSAnchor()
	hash := sha256.Sum256([]byte("test"))
	calendar := "https://test.calendar.org"
	calendarProof := []byte("calendar-response")

	proof := ots.wrapProof(hash[:], calendar, calendarProof)

	// Verify structure
	if !bytes.HasPrefix(proof, []byte(otsHeaderMagic)) {
		t.Error("missing OTS header magic")
	}

	offset := len(otsHeaderMagic)
	if proof[offset] != otsVersion {
		t.Errorf("expected version %d, got %d", otsVersion, proof[offset])
	}

	offset++
	if proof[offset] != 0x08 {
		t.Error("expected SHA256 hash type")
	}

	offset++
	if !bytes.Equal(proof[offset:offset+32], hash[:]) {
		t.Error("hash not found in proof")
	}
}

func TestHashForOTS(t *testing.T) {
	data := []byte("test data")
	result := HashForOTS(data)

	if len(result) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(result))
	}

	// Verify double SHA256
	first := sha256.Sum256(data)
	second := sha256.Sum256(first[:])
	if !bytes.Equal(result, second[:]) {
		t.Error("HashForOTS doesn't match expected double SHA256")
	}
}

func TestParseOTS(t *testing.T) {
	// Create a valid OTS proof
	var buf bytes.Buffer
	buf.WriteString(otsHeaderMagic)
	buf.WriteByte(otsVersion)
	buf.WriteByte(0x08) // SHA256

	hash := sha256.Sum256([]byte("test"))
	buf.Write(hash[:])

	info, err := ParseOTS(buf.Bytes())
	if err != nil {
		t.Fatalf("ParseOTS failed: %v", err)
	}

	if info.Version != otsVersion {
		t.Errorf("expected version %d, got %d", otsVersion, info.Version)
	}
	if info.HashType != "sha256" {
		t.Errorf("expected hash type sha256, got %s", info.HashType)
	}
	if !bytes.Equal(info.Hash, hash[:]) {
		t.Error("parsed hash doesn't match")
	}
}

func TestParseOTSTooShort(t *testing.T) {
	_, err := ParseOTS([]byte("short"))
	if err == nil {
		t.Error("expected error for short proof")
	}
}

func TestParseOTSInvalidHeader(t *testing.T) {
	proof := make([]byte, 100)
	_, err := ParseOTS(proof)
	if err == nil {
		t.Error("expected error for invalid header")
	}
}

func TestParseOTSUnsupportedHashType(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString(otsHeaderMagic)
	buf.WriteByte(otsVersion)
	buf.WriteByte(0xFF) // Unknown hash type
	buf.Write(make([]byte, 50))

	_, err := ParseOTS(buf.Bytes())
	if err == nil {
		t.Error("expected error for unsupported hash type")
	}
}

func TestOTSUpgradeProof(t *testing.T) {
	ots := NewOTSAnchor()

	// Create a minimal valid proof
	var buf bytes.Buffer
	buf.WriteString(otsHeaderMagic)
	buf.WriteByte(otsVersion)
	buf.Write(make([]byte, 50))

	upgraded, changed, err := ots.UpgradeProof(buf.Bytes())
	if err != nil {
		t.Errorf("UpgradeProof failed: %v", err)
	}
	if changed {
		t.Error("expected no change in current implementation")
	}
	if !bytes.Equal(upgraded, buf.Bytes()) {
		t.Error("proof should be unchanged")
	}
}

func TestOTSUpgradeProofTooShort(t *testing.T) {
	ots := NewOTSAnchor()
	_, _, err := ots.UpgradeProof([]byte("short"))
	if err == nil {
		t.Error("expected error for short proof")
	}
}

func TestVarInt(t *testing.T) {
	tests := []uint64{0, 1, 127, 128, 255, 256, 16383, 16384, 1<<21 - 1, 1 << 21}

	for _, val := range tests {
		var buf bytes.Buffer
		writeVarInt(&buf, val)

		result, err := readVarInt(&buf)
		if err != nil {
			t.Errorf("readVarInt failed for %d: %v", val, err)
			continue
		}
		if result != val {
			t.Errorf("expected %d, got %d", val, result)
		}
	}
}

// RFC 3161 Tests

func TestRFC3161AnchorName(t *testing.T) {
	rfc := NewRFC3161Anchor()
	if rfc.Name() != "rfc3161" {
		t.Errorf("expected name 'rfc3161', got '%s'", rfc.Name())
	}
}

func TestRFC3161AnchorCommitWithMockServer(t *testing.T) {
	// Create a mock TSA server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/timestamp-query" {
			t.Errorf("unexpected content type: %s", r.Header.Get("Content-Type"))
		}
		// Return a minimal valid ASN.1 response (PKIStatusInfo with status 0)
		// This is a simplified mock response
		response := []byte{0x30, 0x03, 0x30, 0x01, 0x00} // SEQUENCE { SEQUENCE { INTEGER 0 } }
		w.Write(response)
	}))
	defer server.Close()

	rfc := &RFC3161Anchor{
		servers: []string{server.URL},
		client:  &http.Client{Timeout: 5 * time.Second},
	}

	hash := sha256.Sum256([]byte("test"))
	response, err := rfc.Commit(hash[:])
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	if len(response) == 0 {
		t.Error("expected non-empty response")
	}
}

func TestRFC3161AnchorCommitHashesInput(t *testing.T) {
	// Test that non-32-byte input gets hashed
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := []byte{0x30, 0x03, 0x30, 0x01, 0x00}
		w.Write(response)
	}))
	defer server.Close()

	rfc := &RFC3161Anchor{
		servers: []string{server.URL},
		client:  &http.Client{Timeout: 5 * time.Second},
	}

	// Pass non-32-byte data - should be hashed internally
	_, err := rfc.Commit([]byte("short data"))
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}
}

func TestRFC3161AnchorCommitAllServersFail(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	rfc := &RFC3161Anchor{
		servers: []string{server.URL},
		client:  &http.Client{Timeout: 5 * time.Second},
	}

	hash := sha256.Sum256([]byte("test"))
	_, err := rfc.Commit(hash[:])
	if err == nil {
		t.Error("expected error when all servers fail")
	}
}

func TestRFC3161AnchorVerify(t *testing.T) {
	rfc := NewRFC3161Anchor()

	// Create a valid ASN.1 TimeStampResp with status 0
	// SEQUENCE { SEQUENCE { INTEGER 0 } OCTET STRING (with padding) }
	response := []byte{
		0x30, 0x0a, // SEQUENCE, length 10
		0x30, 0x03, // PKIStatusInfo SEQUENCE, length 3
		0x02, 0x01, 0x00, // INTEGER 0 (status = granted)
		0x04, 0x03, 0x00, 0x00, 0x00, // OCTET STRING with padding for TimeStampToken
	}

	err := rfc.Verify(nil, response)
	if err != nil {
		t.Errorf("Verify failed: %v", err)
	}
}

func TestRFC3161AnchorVerifyTooShort(t *testing.T) {
	rfc := NewRFC3161Anchor()
	err := rfc.Verify(nil, []byte("short"))
	if err == nil {
		t.Error("expected error for short response")
	}
}

func TestRFC3161AnchorVerifyInvalidASN1(t *testing.T) {
	rfc := NewRFC3161Anchor()
	// Invalid ASN.1 data
	err := rfc.Verify(nil, []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	if err == nil {
		t.Error("expected error for invalid ASN.1")
	}
}

func TestRFC3161AnchorVerifyFailedStatus(t *testing.T) {
	rfc := NewRFC3161Anchor()
	// Response with status 2 (rejection)
	response := []byte{
		0x30, 0x05, // SEQUENCE, length 5
		0x30, 0x03, // PKIStatusInfo SEQUENCE, length 3
		0x02, 0x01, 0x02, // INTEGER 2 (status = rejection)
	}
	err := rfc.Verify(nil, response)
	if err == nil {
		t.Error("expected error for failed status")
	}
}

func TestBuildTSRequest(t *testing.T) {
	hash := sha256.Sum256([]byte("test"))
	request, err := buildTSRequest(hash[:])
	if err != nil {
		t.Fatalf("buildTSRequest failed: %v", err)
	}

	if len(request) == 0 {
		t.Error("expected non-empty request")
	}

	// Verify it's valid ASN.1 by unmarshaling
	var req tsRequest
	rest, err := asn1Unmarshal(request, &req)
	if err != nil {
		t.Errorf("invalid ASN.1 request: %v", err)
	}
	if len(rest) > 0 {
		t.Error("trailing data in request")
	}

	if req.Version != 1 {
		t.Errorf("expected version 1, got %d", req.Version)
	}
	if !bytes.Equal(req.MessageImprint.HashedMessage, hash[:]) {
		t.Error("hash not included in request")
	}
}

// Helper to unmarshal ASN.1 for testing
func asn1Unmarshal(data []byte, val interface{}) ([]byte, error) {
	return asn1.Unmarshal(data, val)
}

func TestParseTSResponse(t *testing.T) {
	// Create a valid ASN.1 TimeStampResp with status 0
	response := []byte{
		0x30, 0x07, // SEQUENCE, length 7
		0x30, 0x03, // PKIStatusInfo SEQUENCE, length 3
		0x02, 0x01, 0x00, // INTEGER 0 (status = granted)
		0x04, 0x00, // Empty OCTET STRING for TimeStampToken
	}

	info, err := ParseTSResponse(response)
	if err != nil {
		t.Fatalf("ParseTSResponse failed: %v", err)
	}

	if info.HashAlg != "sha256" {
		t.Errorf("expected hash alg sha256, got %s", info.HashAlg)
	}
}

func TestParseTSResponseFailedStatus(t *testing.T) {
	response := []byte{
		0x30, 0x05, // SEQUENCE, length 5
		0x30, 0x03, // PKIStatusInfo SEQUENCE, length 3
		0x02, 0x01, 0x02, // INTEGER 2 (status = rejection)
	}
	_, err := ParseTSResponse(response)
	if err == nil {
		t.Error("expected error for failed status")
	}
}

func TestTimestampFile(t *testing.T) {
	hash := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a}
	path := TimestampFile("/base/path", hash)

	expected := "/base/path/0102030405060708.tsr"
	if path != expected {
		t.Errorf("expected %s, got %s", expected, path)
	}
}

// Integration test
func TestRegistryIntegration(t *testing.T) {
	tmpDir := t.TempDir()
	r := NewRegistry(filepath.Join(tmpDir, "receipts"))

	// Register both anchor types
	r.Register(NewOTSAnchor())
	r.Register(NewRFC3161Anchor())

	// Verify registration
	names := r.List()
	if len(names) != 2 {
		t.Errorf("expected 2 anchors, got %d", len(names))
	}

	// Test Get
	ots, ok := r.Get("ots")
	if !ok {
		t.Error("OTS anchor not found")
	}
	if ots.Name() != "ots" {
		t.Error("OTS anchor name mismatch")
	}

	rfc, ok := r.Get("rfc3161")
	if !ok {
		t.Error("RFC3161 anchor not found")
	}
	if rfc.Name() != "rfc3161" {
		t.Error("RFC3161 anchor name mismatch")
	}
}

// Fuzz tests for OTS proof parsing

func FuzzParseOTS(f *testing.F) {
	// Add seed corpus with valid OTS header
	// OTS header magic: "\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
	header := []byte("\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94")

	// Version 1 with SHA256 hash type (0x08)
	validOTS := make([]byte, len(header)+1+1+32)
	copy(validOTS, header)
	validOTS[len(header)] = 0x01        // Version 1
	validOTS[len(header)+1] = 0x08      // SHA256 hash type
	// Remaining bytes are the hash (zeros for now)

	f.Add(validOTS)

	// Add various malformed inputs
	f.Add([]byte{})                               // Empty
	f.Add(header[:10])                            // Truncated header
	f.Add(header)                                 // Header only, no version/type
	f.Add(append(header, 0x01))                   // Header + version, no hash type
	f.Add(append(append(header, 0x01), 0x08))     // Missing hash
	f.Add(bytes.Repeat([]byte{0x00}, 100))        // All zeros
	f.Add(bytes.Repeat([]byte{0xff}, 100))        // All 0xff

	f.Fuzz(func(t *testing.T, data []byte) {
		// ParseOTS should not panic on any input
		info, err := ParseOTS(data)
		if err != nil {
			// Errors are expected for invalid input
			return
		}

		// If parsing succeeded, validate the result
		if info == nil {
			t.Error("ParseOTS returned nil info without error")
		}
	})
}

func FuzzParseTSResponse(f *testing.F) {
	// Add seed corpus with various ASN.1 structures
	// A minimal valid-ish TSResponse would be complex, so we test robustness

	// Empty and minimal inputs
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x00}) // Empty SEQUENCE
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x00}) // SEQUENCE with INTEGER 0 (granted status)
	f.Add(bytes.Repeat([]byte{0x30}, 100))      // Many nested SEQUENCEs

	f.Fuzz(func(t *testing.T, data []byte) {
		// ParseTSResponse should not panic on any input
		info, err := ParseTSResponse(data)
		if err != nil {
			// Errors are expected for invalid ASN.1
			return
		}

		// If parsing succeeded, validate the result
		if info == nil {
			t.Error("ParseTSResponse returned nil info without error")
		}
	})
}
