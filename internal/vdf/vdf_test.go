package vdf

import (
	"bytes"
	"crypto/sha256"
	"testing"
	"time"
)

func TestDefaultParameters(t *testing.T) {
	params := DefaultParameters()

	if params.IterationsPerSecond == 0 {
		t.Error("IterationsPerSecond should not be 0")
	}
	if params.MinIterations == 0 {
		t.Error("MinIterations should not be 0")
	}
	if params.MaxIterations == 0 {
		t.Error("MaxIterations should not be 0")
	}
	if params.MinIterations >= params.MaxIterations {
		t.Error("MinIterations should be less than MaxIterations")
	}
}

func TestCalibrate(t *testing.T) {
	params, err := Calibrate(100 * time.Millisecond)
	if err != nil {
		t.Fatalf("Calibrate failed: %v", err)
	}

	if params.IterationsPerSecond == 0 {
		t.Error("IterationsPerSecond should not be 0")
	}
	if params.MinIterations == 0 {
		t.Error("MinIterations should not be 0")
	}
	if params.MaxIterations == 0 {
		t.Error("MaxIterations should not be 0")
	}
}

func TestCalibrateTooShort(t *testing.T) {
	_, err := Calibrate(time.Microsecond)
	if err == nil {
		t.Error("expected error for too short calibration")
	}
}

func TestComputeIterations(t *testing.T) {
	input := sha256.Sum256([]byte("test input"))
	iterations := uint64(1000)

	proof := ComputeIterations(input, iterations)

	if proof == nil {
		t.Fatal("ComputeIterations returned nil")
	}
	if proof.Input != input {
		t.Error("input mismatch")
	}
	if proof.Iterations != iterations {
		t.Errorf("expected %d iterations, got %d", iterations, proof.Iterations)
	}
	if proof.Duration <= 0 {
		t.Error("duration should be positive")
	}
	if proof.Output == input {
		t.Error("output should differ from input")
	}
}

func TestCompute(t *testing.T) {
	input := sha256.Sum256([]byte("test"))
	params := Parameters{
		IterationsPerSecond: 100000,
		MinIterations:       100,
		MaxIterations:       1000000,
	}

	proof, err := Compute(input, 10*time.Millisecond, params)
	if err != nil {
		t.Fatalf("Compute failed: %v", err)
	}

	if proof.Iterations < params.MinIterations {
		t.Errorf("iterations below minimum: %d < %d", proof.Iterations, params.MinIterations)
	}
}

func TestComputeMinIterations(t *testing.T) {
	input := sha256.Sum256([]byte("test"))
	params := Parameters{
		IterationsPerSecond: 100000,
		MinIterations:       500,
		MaxIterations:       1000000,
	}

	// Request very short duration
	proof, err := Compute(input, time.Nanosecond, params)
	if err != nil {
		t.Fatalf("Compute failed: %v", err)
	}

	// Should be clamped to minimum
	if proof.Iterations != params.MinIterations {
		t.Errorf("expected min iterations %d, got %d", params.MinIterations, proof.Iterations)
	}
}

func TestComputeExceedsMax(t *testing.T) {
	input := sha256.Sum256([]byte("test"))
	params := Parameters{
		IterationsPerSecond: 1000,
		MinIterations:       100,
		MaxIterations:       1000,
	}

	// Request duration that exceeds max
	_, err := Compute(input, time.Hour, params)
	if err == nil {
		t.Error("expected error when exceeding max iterations")
	}
}

func TestVerify(t *testing.T) {
	input := sha256.Sum256([]byte("test"))
	proof := ComputeIterations(input, 1000)

	if !Verify(proof) {
		t.Error("valid proof should verify")
	}
}

func TestVerifyInvalid(t *testing.T) {
	input := sha256.Sum256([]byte("test"))
	proof := ComputeIterations(input, 1000)

	// Corrupt the output
	proof.Output[0] ^= 0xff

	if Verify(proof) {
		t.Error("corrupted proof should not verify")
	}
}

func TestVerifyWrongIterations(t *testing.T) {
	input := sha256.Sum256([]byte("test"))
	proof := ComputeIterations(input, 1000)

	// Change iteration count
	proof.Iterations = 999

	if Verify(proof) {
		t.Error("proof with wrong iterations should not verify")
	}
}

func TestVerifyWithProgress(t *testing.T) {
	input := sha256.Sum256([]byte("test"))
	proof := ComputeIterations(input, 1000)

	progress := make(chan float64, 200)
	valid := VerifyWithProgress(proof, progress)

	if !valid {
		t.Error("valid proof should verify with progress")
	}

	// Progress channel should be closed
	_, ok := <-progress
	for ok {
		_, ok = <-progress
	}
}

func TestVerifyWithProgressNilChannel(t *testing.T) {
	input := sha256.Sum256([]byte("test"))
	proof := ComputeIterations(input, 1000)

	// Should not panic with nil channel
	valid := VerifyWithProgress(proof, nil)
	if !valid {
		t.Error("valid proof should verify")
	}
}

func TestMinElapsedTime(t *testing.T) {
	proof := &Proof{
		Iterations: 1000000,
	}

	params := Parameters{
		IterationsPerSecond: 1000000,
	}

	elapsed := proof.MinElapsedTime(params)
	if elapsed != time.Second {
		t.Errorf("expected 1 second, got %v", elapsed)
	}
}

func TestEncodeDecodeProof(t *testing.T) {
	input := sha256.Sum256([]byte("test"))
	original := ComputeIterations(input, 1000)

	encoded := original.Encode()
	if len(encoded) != 80 {
		t.Errorf("expected 80 bytes, got %d", len(encoded))
	}

	decoded, err := DecodeProof(encoded)
	if err != nil {
		t.Fatalf("DecodeProof failed: %v", err)
	}

	if decoded.Input != original.Input {
		t.Error("input mismatch")
	}
	if decoded.Output != original.Output {
		t.Error("output mismatch")
	}
	if decoded.Iterations != original.Iterations {
		t.Errorf("iterations mismatch: expected %d, got %d", original.Iterations, decoded.Iterations)
	}
	if decoded.Duration != original.Duration {
		t.Errorf("duration mismatch: expected %v, got %v", original.Duration, decoded.Duration)
	}
}

func TestDecodeProofTooShort(t *testing.T) {
	_, err := DecodeProof([]byte("short"))
	if err == nil {
		t.Error("expected error for short data")
	}
}

func TestBatchVerifier(t *testing.T) {
	bv := NewBatchVerifier(0) // Auto workers
	if bv.workers <= 0 {
		t.Error("workers should be positive")
	}

	bv = NewBatchVerifier(4)
	if bv.workers != 4 {
		t.Errorf("expected 4 workers, got %d", bv.workers)
	}
}

func TestBatchVerifyAll(t *testing.T) {
	bv := NewBatchVerifier(2)

	// Create multiple proofs
	proofs := make([]*Proof, 5)
	for i := 0; i < 5; i++ {
		input := sha256.Sum256([]byte{byte(i)})
		proofs[i] = ComputeIterations(input, 100)
	}

	results := bv.VerifyAll(proofs)

	if len(results) != 5 {
		t.Errorf("expected 5 results, got %d", len(results))
	}

	for i, r := range results {
		if !r.Valid {
			t.Errorf("proof %d should be valid", i)
		}
		if r.Index != i {
			t.Errorf("expected index %d, got %d", i, r.Index)
		}
	}
}

func TestBatchVerifyAllWithInvalid(t *testing.T) {
	bv := NewBatchVerifier(2)

	proofs := make([]*Proof, 3)
	for i := 0; i < 3; i++ {
		input := sha256.Sum256([]byte{byte(i)})
		proofs[i] = ComputeIterations(input, 100)
	}

	// Corrupt one proof
	proofs[1].Output[0] ^= 0xff

	results := bv.VerifyAll(proofs)

	if results[0].Valid != true {
		t.Error("proof 0 should be valid")
	}
	if results[1].Valid != false {
		t.Error("proof 1 should be invalid")
	}
	if results[2].Valid != true {
		t.Error("proof 2 should be valid")
	}
}

func TestBatchVerifyAllWithNil(t *testing.T) {
	bv := NewBatchVerifier(1)

	proofs := []*Proof{
		ComputeIterations(sha256.Sum256([]byte("a")), 100),
		nil,
		ComputeIterations(sha256.Sum256([]byte("c")), 100),
	}

	results := bv.VerifyAll(proofs)

	if results[0].Valid != true {
		t.Error("proof 0 should be valid")
	}
	if results[1].Valid != false || results[1].Error == nil {
		t.Error("nil proof should be invalid with error")
	}
	if results[2].Valid != true {
		t.Error("proof 2 should be valid")
	}
}

func TestChainInput(t *testing.T) {
	contentHash := sha256.Sum256([]byte("content"))
	previousHash := sha256.Sum256([]byte("previous"))
	ordinal := uint64(42)

	input1 := ChainInput(contentHash, previousHash, ordinal)
	input2 := ChainInput(contentHash, previousHash, ordinal)

	// Same inputs should produce same output
	if input1 != input2 {
		t.Error("ChainInput should be deterministic")
	}

	// Different content hash
	differentContent := sha256.Sum256([]byte("different"))
	input3 := ChainInput(differentContent, previousHash, ordinal)
	if input1 == input3 {
		t.Error("different content should produce different input")
	}

	// Different previous hash
	differentPrevious := sha256.Sum256([]byte("other"))
	input4 := ChainInput(contentHash, differentPrevious, ordinal)
	if input1 == input4 {
		t.Error("different previous hash should produce different input")
	}

	// Different ordinal
	input5 := ChainInput(contentHash, previousHash, 43)
	if input1 == input5 {
		t.Error("different ordinal should produce different input")
	}
}

func TestComputeChainDeterminism(t *testing.T) {
	input := sha256.Sum256([]byte("test"))
	iterations := uint64(100)

	output1 := computeChain(input, iterations)
	output2 := computeChain(input, iterations)

	if output1 != output2 {
		t.Error("computeChain should be deterministic")
	}
}

func TestProofEncodingRoundtrip(t *testing.T) {
	original := &Proof{
		Input:      sha256.Sum256([]byte("input")),
		Output:     sha256.Sum256([]byte("output")),
		Iterations: 12345678,
		Duration:   time.Second * 42,
	}

	encoded := original.Encode()
	decoded, err := DecodeProof(encoded)
	if err != nil {
		t.Fatalf("DecodeProof failed: %v", err)
	}

	if !bytes.Equal(decoded.Input[:], original.Input[:]) {
		t.Error("Input mismatch after roundtrip")
	}
	if !bytes.Equal(decoded.Output[:], original.Output[:]) {
		t.Error("Output mismatch after roundtrip")
	}
	if decoded.Iterations != original.Iterations {
		t.Error("Iterations mismatch after roundtrip")
	}
	if decoded.Duration != original.Duration {
		t.Error("Duration mismatch after roundtrip")
	}
}

func TestEmptyProof(t *testing.T) {
	input := sha256.Sum256([]byte("test"))
	proof := ComputeIterations(input, 0)

	// Zero iterations should still work
	if proof.Input != input {
		t.Error("input mismatch")
	}
	if proof.Output != input {
		t.Error("zero iterations should return input as output")
	}
	if proof.Iterations != 0 {
		t.Error("iterations should be 0")
	}
}

func TestVerifyEmptyProof(t *testing.T) {
	input := sha256.Sum256([]byte("test"))
	proof := ComputeIterations(input, 0)

	if !Verify(proof) {
		t.Error("zero-iteration proof should verify")
	}
}

func BenchmarkComputeIterations(b *testing.B) {
	input := sha256.Sum256([]byte("benchmark"))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		ComputeIterations(input, 10000)
	}
}

func BenchmarkVerify(b *testing.B) {
	input := sha256.Sum256([]byte("benchmark"))
	proof := ComputeIterations(input, 10000)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		Verify(proof)
	}
}

// Fuzz tests for proof parsing

func FuzzDecodeProof(f *testing.F) {
	// Add seed corpus with valid proof data
	input := sha256.Sum256([]byte("test"))
	validProof := ComputeIterations(input, 1000)
	validData := validProof.Encode()
	f.Add(validData)

	// Add edge cases
	f.Add(make([]byte, 80))               // Minimum size, all zeros
	f.Add(bytes.Repeat([]byte{0xff}, 80)) // Minimum size, all 0xff
	f.Add(make([]byte, 0))                // Empty
	f.Add(make([]byte, 79))               // Too short by one byte
	f.Add(make([]byte, 81))               // One byte too long (still valid)

	f.Fuzz(func(t *testing.T, data []byte) {
		// DecodeProof should not panic on any input
		proof, err := DecodeProof(data)
		if err != nil {
			// Error expected for invalid data
			if len(data) >= 80 {
				t.Errorf("DecodeProof failed on %d-byte input: %v", len(data), err)
			}
			return
		}

		// If decoding succeeded, verify we can re-encode
		reencoded := proof.Encode()

		// Re-encoded data should be exactly 80 bytes
		if len(reencoded) != 80 {
			t.Errorf("Encoded proof should be 80 bytes, got %d", len(reencoded))
		}

		// Re-decode should produce the same proof
		proof2, err := DecodeProof(reencoded)
		if err != nil {
			t.Errorf("Failed to decode re-encoded proof: %v", err)
		}

		if proof.Input != proof2.Input {
			t.Error("Input mismatch after re-encode")
		}
		if proof.Output != proof2.Output {
			t.Error("Output mismatch after re-encode")
		}
		if proof.Iterations != proof2.Iterations {
			t.Error("Iterations mismatch after re-encode")
		}
		if proof.Duration != proof2.Duration {
			t.Error("Duration mismatch after re-encode")
		}
	})
}
