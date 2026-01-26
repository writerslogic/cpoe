package forensics

import (
	"errors"
	"math"
	"sort"
)

// ErrInsufficientData is returned when there are not enough events for analysis.
var ErrInsufficientData = errors.New("insufficient data for analysis")

// DefaultAppendThreshold is the position above which an edit is considered an append.
const DefaultAppendThreshold float32 = 0.95

// DefaultHistogramBins is the default number of bins for edit entropy calculation.
const DefaultHistogramBins = 20

// MinEventsForAnalysis is the minimum number of events required for stable estimates.
const MinEventsForAnalysis = 5

// ComputePrimaryMetrics calculates all 5 primary metrics.
// Requires at least 5 events with regions for stable estimates.
func ComputePrimaryMetrics(events []EventData, regions map[int64][]RegionData) (*PrimaryMetrics, error) {
	if len(events) < MinEventsForAnalysis {
		return nil, ErrInsufficientData
	}

	allRegions := flattenRegions(regions)
	if len(allRegions) == 0 {
		return nil, ErrInsufficientData
	}

	return &PrimaryMetrics{
		MonotonicAppendRatio:  MonotonicAppendRatio(allRegions, DefaultAppendThreshold),
		EditEntropy:           EditEntropy(allRegions, DefaultHistogramBins),
		MedianInterval:        MedianInterval(events),
		PositiveNegativeRatio: PositiveNegativeRatio(allRegions),
		DeletionClustering:    DeletionClusteringCoef(allRegions),
	}, nil
}

// MonotonicAppendRatio calculates the fraction of edits at document end.
// threshold: position above which is "append" (default 0.95)
// Formula: |{r : r.StartPct >= threshold}| / |R|
func MonotonicAppendRatio(regions []RegionData, threshold float32) float64 {
	if len(regions) == 0 {
		return 0
	}

	appendCount := 0
	for _, r := range regions {
		if r.StartPct >= threshold {
			appendCount++
		}
	}

	return float64(appendCount) / float64(len(regions))
}

// EditEntropy calculates Shannon entropy of edit position histogram.
// bins: number of histogram buckets (default 20)
// Formula: H = -sum (c_j/n) * log2(c_j/n) for non-zero bins
func EditEntropy(regions []RegionData, bins int) float64 {
	if len(regions) == 0 || bins <= 0 {
		return 0
	}

	// Build histogram of edit positions
	histogram := make([]int, bins)
	for _, r := range regions {
		// Use StartPct to determine bin
		pos := r.StartPct
		if pos < 0 {
			pos = 0
		}
		if pos >= 1 {
			pos = 0.9999 // Clamp to last bin
		}
		binIdx := int(pos * float32(bins))
		if binIdx >= bins {
			binIdx = bins - 1
		}
		histogram[binIdx]++
	}

	return shannonEntropy(histogram)
}

// shannonEntropy calculates Shannon entropy from a histogram.
// Formula: H = -sum (c_j/n) * log2(c_j/n) for non-zero bins
func shannonEntropy(histogram []int) float64 {
	n := 0
	for _, count := range histogram {
		n += count
	}
	if n == 0 {
		return 0
	}

	entropy := 0.0
	nFloat := float64(n)
	for _, count := range histogram {
		if count > 0 {
			p := float64(count) / nFloat
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// MedianInterval calculates the median inter-event interval in seconds.
// Formula: median of {(t_i - t_{i-1}) / 1e9 for i in 2..n}
func MedianInterval(events []EventData) float64 {
	if len(events) < 2 {
		return 0
	}

	// Sort events by timestamp
	sorted := make([]EventData, len(events))
	copy(sorted, events)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].TimestampNs < sorted[j].TimestampNs
	})

	// Calculate intervals
	intervals := make([]float64, len(sorted)-1)
	for i := 1; i < len(sorted); i++ {
		deltaNs := sorted[i].TimestampNs - sorted[i-1].TimestampNs
		intervals[i-1] = float64(deltaNs) / 1e9 // Convert to seconds
	}

	return median(intervals)
}

// median calculates the median of a slice of float64 values.
func median(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}

	sorted := make([]float64, len(values))
	copy(sorted, values)
	sort.Float64s(sorted)

	n := len(sorted)
	if n%2 == 0 {
		return (sorted[n/2-1] + sorted[n/2]) / 2
	}
	return sorted[n/2]
}

// PositiveNegativeRatio calculates insertions / (insertions + deletions).
// Formula: |{r : r.DeltaSign > 0}| / |{r : r.DeltaSign != 0}|
func PositiveNegativeRatio(regions []RegionData) float64 {
	insertions := 0
	total := 0

	for _, r := range regions {
		if r.DeltaSign > 0 {
			insertions++
			total++
		} else if r.DeltaSign < 0 {
			total++
		}
		// DeltaSign == 0 are replacements without size change, excluded
	}

	if total == 0 {
		return 0.5 // Neutral when no insertions or deletions
	}

	return float64(insertions) / float64(total)
}

// DeletionClusteringCoef calculates the nearest-neighbor ratio for deletions.
// Clustered deletions (revision pass) produce < 1.
// Scattered deletions (fake) produce ~ 1.
// No deletions produces 0.
// Formula: meanDist / expectedUniformDist where expectedUniformDist = 1/(n+1)
func DeletionClusteringCoef(regions []RegionData) float64 {
	// Extract deletion positions
	var deletionPositions []float64
	for _, r := range regions {
		if r.DeltaSign < 0 {
			deletionPositions = append(deletionPositions, float64(r.StartPct))
		}
	}

	n := len(deletionPositions)
	if n < 2 {
		return 0 // Not enough deletions to compute clustering
	}

	// Sort positions
	sort.Float64s(deletionPositions)

	// Calculate nearest-neighbor distances
	var totalDist float64
	for i, pos := range deletionPositions {
		minDist := math.MaxFloat64

		// Check left neighbor
		if i > 0 {
			dist := pos - deletionPositions[i-1]
			if dist < minDist {
				minDist = dist
			}
		}

		// Check right neighbor
		if i < n-1 {
			dist := deletionPositions[i+1] - pos
			if dist < minDist {
				minDist = dist
			}
		}

		totalDist += minDist
	}

	meanDist := totalDist / float64(n)

	// Expected uniform distance for n points in [0,1]
	expectedUniformDist := 1.0 / float64(n+1)

	if expectedUniformDist == 0 {
		return 0
	}

	return meanDist / expectedUniformDist
}

// flattenRegions collects all regions from a map into a single slice.
func flattenRegions(regions map[int64][]RegionData) []RegionData {
	var result []RegionData
	for _, rs := range regions {
		result = append(result, rs...)
	}
	return result
}
