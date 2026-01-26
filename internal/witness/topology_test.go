package witness

import (
	"testing"
)

func TestExtractTopology_SimpleInsert(t *testing.T) {
	prev := []byte("Hello World")
	curr := []byte("Hello Beautiful World")

	regions := ExtractTopology(prev, curr)

	if len(regions) == 0 {
		t.Fatal("expected at least one edit region")
	}

	// Should have an insertion region for "Beautiful "
	foundInsert := false
	for _, r := range regions {
		if r.DeltaSign == DeltaIncrease {
			foundInsert = true
			// Position should be around 6/11 = 0.545
			if r.StartPct < 0.4 || r.StartPct > 0.7 {
				t.Errorf("insert position %f outside expected range [0.4, 0.7]", r.StartPct)
			}
			if r.ByteCount != 10 {
				t.Errorf("expected ByteCount=10 for 'Beautiful ', got %d", r.ByteCount)
			}
		}
	}

	if !foundInsert {
		t.Error("expected to find an insertion region")
	}
}

func TestExtractTopology_SimpleDelete(t *testing.T) {
	prev := []byte("Hello Beautiful World")
	curr := []byte("Hello World")

	regions := ExtractTopology(prev, curr)

	if len(regions) == 0 {
		t.Fatal("expected at least one edit region")
	}

	// Should have a deletion region for "Beautiful "
	foundDelete := false
	for _, r := range regions {
		if r.DeltaSign == DeltaDecrease {
			foundDelete = true
			if r.ByteCount != 10 {
				t.Errorf("expected ByteCount=10 for 'Beautiful ', got %d", r.ByteCount)
			}
		}
	}

	if !foundDelete {
		t.Error("expected to find a deletion region")
	}
}

func TestExtractTopology_NewFile(t *testing.T) {
	var prev []byte
	curr := []byte("New file content")

	regions := ExtractTopology(prev, curr)

	if len(regions) != 1 {
		t.Fatalf("expected 1 region for new file, got %d", len(regions))
	}

	r := regions[0]
	if r.DeltaSign != DeltaIncrease {
		t.Error("expected insertion for new file")
	}
	if r.StartPct != 0.0 || r.EndPct != 1.0 {
		t.Errorf("expected full coverage [0.0, 1.0], got [%f, %f]", r.StartPct, r.EndPct)
	}
	if r.ByteCount != int32(len(curr)) {
		t.Errorf("expected ByteCount=%d, got %d", len(curr), r.ByteCount)
	}
}

func TestExtractTopology_DeletedFile(t *testing.T) {
	prev := []byte("File content to delete")
	var curr []byte

	regions := ExtractTopology(prev, curr)

	if len(regions) != 1 {
		t.Fatalf("expected 1 region for deleted file, got %d", len(regions))
	}

	r := regions[0]
	if r.DeltaSign != DeltaDecrease {
		t.Error("expected deletion for deleted file")
	}
	if r.StartPct != 0.0 || r.EndPct != 1.0 {
		t.Errorf("expected full coverage [0.0, 1.0], got [%f, %f]", r.StartPct, r.EndPct)
	}
	if r.ByteCount != int32(len(prev)) {
		t.Errorf("expected ByteCount=%d, got %d", len(prev), r.ByteCount)
	}
}

func TestExtractTopology_Identical(t *testing.T) {
	content := []byte("Same content")

	regions := ExtractTopology(content, content)

	if len(regions) != 0 {
		t.Errorf("expected no regions for identical content, got %d", len(regions))
	}
}

func TestExtractTopology_Empty(t *testing.T) {
	regions := ExtractTopology(nil, nil)

	if regions != nil {
		t.Errorf("expected nil for empty content, got %v", regions)
	}
}

func TestMyersDiff_Basic(t *testing.T) {
	tests := []struct {
		name     string
		a, b     []byte
		expectOp OpType
	}{
		{"insert", []byte("ac"), []byte("abc"), OpInsert},
		{"delete", []byte("abc"), []byte("ac"), OpDelete},
		{"equal", []byte("abc"), []byte("abc"), OpEqual},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ops := myersDiff(tt.a, tt.b)
			found := false
			for _, op := range ops {
				if op.Type == tt.expectOp {
					found = true
					break
				}
			}
			if !found && tt.expectOp != OpEqual {
				t.Errorf("expected operation type %d not found", tt.expectOp)
			}
		})
	}
}

func TestMyersDiff_EmptyInputs(t *testing.T) {
	// Empty to content
	ops := myersDiff(nil, []byte("abc"))
	if len(ops) != 1 || ops[0].Type != OpInsert || ops[0].Length != 3 {
		t.Errorf("expected single insert of length 3, got %+v", ops)
	}

	// Content to empty
	ops = myersDiff([]byte("abc"), nil)
	if len(ops) != 1 || ops[0].Type != OpDelete || ops[0].Length != 3 {
		t.Errorf("expected single delete of length 3, got %+v", ops)
	}

	// Empty to empty
	ops = myersDiff(nil, nil)
	if ops != nil {
		t.Errorf("expected nil for empty inputs, got %+v", ops)
	}
}

func TestCoalesceRegions(t *testing.T) {
	regions := []EditRegion{
		{StartPct: 0.1, EndPct: 0.15, DeltaSign: DeltaIncrease, ByteCount: 5},
		{StartPct: 0.18, EndPct: 0.20, DeltaSign: DeltaIncrease, ByteCount: 3}, // Within 5% of previous
		{StartPct: 0.5, EndPct: 0.55, DeltaSign: DeltaIncrease, ByteCount: 10}, // Gap > 5%
	}

	result := coalesceRegions(regions, 0.05)

	if len(result) != 2 {
		t.Fatalf("expected 2 coalesced regions, got %d", len(result))
	}

	// First region should be merged
	if result[0].ByteCount != 8 {
		t.Errorf("expected first region ByteCount=8, got %d", result[0].ByteCount)
	}

	// Second region should be unchanged
	if result[1].ByteCount != 10 {
		t.Errorf("expected second region ByteCount=10, got %d", result[1].ByteCount)
	}
}

func TestCoalesceRegions_DifferentSigns(t *testing.T) {
	regions := []EditRegion{
		{StartPct: 0.1, EndPct: 0.15, DeltaSign: DeltaIncrease, ByteCount: 5},
		{StartPct: 0.18, EndPct: 0.20, DeltaSign: DeltaDecrease, ByteCount: 3}, // Different sign
	}

	result := coalesceRegions(regions, 0.05)

	if len(result) != 2 {
		t.Errorf("regions with different signs should not merge, got %d regions", len(result))
	}
}

func TestComputeSizeDelta(t *testing.T) {
	tests := []struct {
		prev, curr int64
		expected   int32
	}{
		{100, 150, 50},
		{150, 100, -50},
		{100, 100, 0},
		{0, 100, 100},
		{100, 0, -100},
	}

	for _, tt := range tests {
		result := ComputeSizeDelta(tt.prev, tt.curr)
		if result != tt.expected {
			t.Errorf("ComputeSizeDelta(%d, %d) = %d, expected %d",
				tt.prev, tt.curr, result, tt.expected)
		}
	}
}

func TestComputeStats(t *testing.T) {
	regions := []EditRegion{
		{StartPct: 0.1, EndPct: 0.2, DeltaSign: DeltaIncrease, ByteCount: 100},
		{StartPct: 0.3, EndPct: 0.4, DeltaSign: DeltaDecrease, ByteCount: 50},
		{StartPct: 0.5, EndPct: 0.6, DeltaSign: DeltaUnchanged, ByteCount: 30},
	}

	stats := ComputeStats(regions)

	if stats.TotalRegions != 3 {
		t.Errorf("expected TotalRegions=3, got %d", stats.TotalRegions)
	}
	if stats.Insertions != 1 {
		t.Errorf("expected Insertions=1, got %d", stats.Insertions)
	}
	if stats.Deletions != 1 {
		t.Errorf("expected Deletions=1, got %d", stats.Deletions)
	}
	if stats.Replacements != 1 {
		t.Errorf("expected Replacements=1, got %d", stats.Replacements)
	}
	if stats.MaxRegionSize != 100 {
		t.Errorf("expected MaxRegionSize=100, got %d", stats.MaxRegionSize)
	}
	if stats.CoverageStart != 0.1 {
		t.Errorf("expected CoverageStart=0.1, got %f", stats.CoverageStart)
	}
	if stats.CoverageEnd != 0.6 {
		t.Errorf("expected CoverageEnd=0.6, got %f", stats.CoverageEnd)
	}
}

func TestComputeStats_Empty(t *testing.T) {
	stats := ComputeStats(nil)

	if stats.TotalRegions != 0 {
		t.Errorf("expected TotalRegions=0 for empty input, got %d", stats.TotalRegions)
	}
	if stats.CoverageStart != 0 || stats.CoverageEnd != 0 {
		t.Error("expected zero coverage for empty input")
	}
}

func TestChunkedDiff(t *testing.T) {
	// Create content that will produce multiple chunks
	prev := make([]byte, 8192)
	curr := make([]byte, 8192)

	// Fill with different patterns
	for i := range prev {
		prev[i] = byte(i % 256)
	}
	copy(curr, prev)

	// Modify middle section
	for i := 4000; i < 4100; i++ {
		curr[i] = byte((i + 50) % 256)
	}

	prevChunks := computeChunks(prev)
	currChunks := computeChunks(curr)

	regions := chunkedDiff(prev, curr, prevChunks, currChunks)

	// Should detect changes in the modified region
	if len(regions) == 0 {
		t.Error("expected chunked diff to detect changes")
	}
}

func TestComputeChunks(t *testing.T) {
	// Test with content larger than one chunk
	data := make([]byte, 10000)
	for i := range data {
		data[i] = byte(i % 256)
	}

	chunks := computeChunks(data)

	if len(chunks) == 0 {
		t.Error("expected at least one chunk")
	}

	// Verify chunks cover entire content
	var totalLen int64 = 0
	for _, c := range chunks {
		totalLen += c.Length
	}
	if totalLen != int64(len(data)) {
		t.Errorf("chunks should cover entire content: got %d, expected %d", totalLen, len(data))
	}

	// Verify chunks are contiguous
	var offset int64 = 0
	for i, c := range chunks {
		if c.Offset != offset {
			t.Errorf("chunk %d has wrong offset: got %d, expected %d", i, c.Offset, offset)
		}
		offset += c.Length
	}
}

func TestComputeChunks_Empty(t *testing.T) {
	chunks := computeChunks(nil)
	if chunks != nil {
		t.Errorf("expected nil for empty input, got %v", chunks)
	}
}

func BenchmarkMyersDiff_Small(b *testing.B) {
	prev := []byte("The quick brown fox jumps over the lazy dog")
	curr := []byte("The quick brown cat jumps over the lazy dog")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		myersDiff(prev, curr)
	}
}

func BenchmarkMyersDiff_Medium(b *testing.B) {
	prev := make([]byte, 1024)
	curr := make([]byte, 1024)

	for i := range prev {
		prev[i] = byte(i % 256)
	}
	copy(curr, prev)
	// Make some changes
	for i := 500; i < 550; i++ {
		curr[i] = byte((i + 50) % 256)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		myersDiff(prev, curr)
	}
}

func BenchmarkExtractTopology_Small(b *testing.B) {
	prev := []byte("Hello World")
	curr := []byte("Hello Beautiful World")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ExtractTopology(prev, curr)
	}
}

func BenchmarkComputeChunks_Medium(b *testing.B) {
	data := make([]byte, 10000)
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		computeChunks(data)
	}
}
