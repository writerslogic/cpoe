package witness

import (
	"fmt"
	"testing"
)

func TestDebugSimpleInsert(t *testing.T) {
	prev := []byte("Hello World")
	curr := []byte("Hello Beautiful World")
	
	t.Logf("prev: %q (len=%d)", prev, len(prev))
	t.Logf("curr: %q (len=%d)", curr, len(curr))
	
	// First look at raw diff ops
	ops := myersDiff(prev, curr)
	t.Logf("\nDiff ops (%d):", len(ops))
	for i, op := range ops {
		t.Logf("  [%d] Type=%d OldPos=%d NewPos=%d Length=%d", i, op.Type, op.OldPos, op.NewPos, op.Length)
	}
	
	regions := ExtractTopology(prev, curr)
	
	t.Logf("\nRegions (%d):", len(regions))
	for i, r := range regions {
		t.Logf("  [%d] StartPct=%.4f EndPct=%.4f DeltaSign=%d ByteCount=%d",
			i, r.StartPct, r.EndPct, r.DeltaSign, r.ByteCount)
	}
	
	// Expected: "Beautiful " (10 chars) inserted at position 6 out of 11
	// Position 6/11 = 0.545
	fmt.Printf("Expected position: 6/11 = %.4f\n", 6.0/11.0)
}
