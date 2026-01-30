package forensics

import (
	"bytes"
	"math"
	"strings"
	"testing"
	"time"
)

// Helper to create events at given nanosecond timestamps
func makeEvents(timestamps ...int64) []EventData {
	events := make([]EventData, len(timestamps))
	for i, ts := range timestamps {
		events[i] = EventData{
			ID:          int64(i + 1),
			TimestampNs: ts,
			FileSize:    100,
			SizeDelta:   10,
			FilePath:    "/test/file.txt",
		}
	}
	return events
}

// Helper to create regions with given start positions and delta signs
func makeRegions(specs ...struct {
	startPct  float32
	deltaSign int8
}) []RegionData {
	regions := make([]RegionData, len(specs))
	for i, spec := range specs {
		regions[i] = RegionData{
			StartPct:  spec.startPct,
			EndPct:    spec.startPct + 0.01,
			DeltaSign: spec.deltaSign,
			ByteCount: 10,
		}
	}
	return regions
}

// =============================================================================
// Tests for metrics.go
// =============================================================================

func TestComputePrimaryMetrics(t *testing.T) {
	// Create events
	events := makeEvents(0, 1e9, 2e9, 3e9, 4e9) // 5 events, 1 second apart

	// Create regions for each event
	regions := map[int64][]RegionData{
		1: {{StartPct: 0.1, DeltaSign: 1}},
		2: {{StartPct: 0.3, DeltaSign: 1}},
		3: {{StartPct: 0.5, DeltaSign: -1}},
		4: {{StartPct: 0.7, DeltaSign: 1}},
		5: {{StartPct: 0.96, DeltaSign: 1}}, // Append
	}

	metrics, err := ComputePrimaryMetrics(events, regions)
	if err != nil {
		t.Fatalf("ComputePrimaryMetrics failed: %v", err)
	}

	if metrics == nil {
		t.Fatal("expected non-nil metrics")
	}

	// Verify metrics are computed
	if metrics.MonotonicAppendRatio < 0 || metrics.MonotonicAppendRatio > 1 {
		t.Errorf("MonotonicAppendRatio out of range: %v", metrics.MonotonicAppendRatio)
	}
	if metrics.EditEntropy < 0 {
		t.Errorf("EditEntropy should be non-negative: %v", metrics.EditEntropy)
	}
	if metrics.MedianInterval < 0 {
		t.Errorf("MedianInterval should be non-negative: %v", metrics.MedianInterval)
	}
	if metrics.PositiveNegativeRatio < 0 || metrics.PositiveNegativeRatio > 1 {
		t.Errorf("PositiveNegativeRatio out of range: %v", metrics.PositiveNegativeRatio)
	}
}

func TestComputePrimaryMetricsInsufficientEvents(t *testing.T) {
	events := makeEvents(0, 1e9, 2e9, 3e9) // Only 4 events, need 5

	regions := map[int64][]RegionData{
		1: {{StartPct: 0.1, DeltaSign: 1}},
	}

	_, err := ComputePrimaryMetrics(events, regions)
	if err != ErrInsufficientData {
		t.Errorf("expected ErrInsufficientData, got %v", err)
	}
}

func TestComputePrimaryMetricsNoRegions(t *testing.T) {
	events := makeEvents(0, 1e9, 2e9, 3e9, 4e9)
	regions := map[int64][]RegionData{} // Empty

	_, err := ComputePrimaryMetrics(events, regions)
	if err != ErrInsufficientData {
		t.Errorf("expected ErrInsufficientData, got %v", err)
	}
}

func TestMonotonicAppendRatio(t *testing.T) {
	tests := []struct {
		name      string
		regions   []RegionData
		threshold float32
		expected  float64
	}{
		{
			name:      "empty regions",
			regions:   []RegionData{},
			threshold: 0.95,
			expected:  0,
		},
		{
			name: "all appends",
			regions: []RegionData{
				{StartPct: 0.96},
				{StartPct: 0.97},
				{StartPct: 0.98},
			},
			threshold: 0.95,
			expected:  1.0,
		},
		{
			name: "no appends",
			regions: []RegionData{
				{StartPct: 0.1},
				{StartPct: 0.2},
				{StartPct: 0.3},
			},
			threshold: 0.95,
			expected:  0,
		},
		{
			name: "half appends",
			regions: []RegionData{
				{StartPct: 0.1},
				{StartPct: 0.96},
			},
			threshold: 0.95,
			expected:  0.5,
		},
		{
			name: "different threshold",
			regions: []RegionData{
				{StartPct: 0.8},
				{StartPct: 0.9},
			},
			threshold: 0.75,
			expected:  1.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MonotonicAppendRatio(tt.regions, tt.threshold)
			if math.Abs(result-tt.expected) > 0.0001 {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestEditEntropy(t *testing.T) {
	tests := []struct {
		name    string
		regions []RegionData
		bins    int
	}{
		{
			name:    "empty regions",
			regions: []RegionData{},
			bins:    20,
		},
		{
			name:    "zero bins",
			regions: []RegionData{{StartPct: 0.5}},
			bins:    0,
		},
		{
			name: "single position (zero entropy)",
			regions: []RegionData{
				{StartPct: 0.5},
				{StartPct: 0.5},
				{StartPct: 0.5},
			},
			bins: 20,
		},
		{
			name: "uniform distribution (high entropy)",
			regions: []RegionData{
				{StartPct: 0.05},
				{StartPct: 0.15},
				{StartPct: 0.25},
				{StartPct: 0.35},
				{StartPct: 0.45},
				{StartPct: 0.55},
				{StartPct: 0.65},
				{StartPct: 0.75},
				{StartPct: 0.85},
				{StartPct: 0.95},
			},
			bins: 10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := EditEntropy(tt.regions, tt.bins)
			if result < 0 {
				t.Errorf("entropy should be non-negative: %v", result)
			}
		})
	}
}

func TestEditEntropyConcentrated(t *testing.T) {
	// All edits in same position should have low entropy
	concentrated := []RegionData{
		{StartPct: 0.5},
		{StartPct: 0.5},
		{StartPct: 0.5},
	}

	// Edits distributed across bins should have higher entropy
	distributed := []RegionData{
		{StartPct: 0.1},
		{StartPct: 0.3},
		{StartPct: 0.5},
		{StartPct: 0.7},
		{StartPct: 0.9},
	}

	concentratedEntropy := EditEntropy(concentrated, 10)
	distributedEntropy := EditEntropy(distributed, 10)

	if distributedEntropy <= concentratedEntropy {
		t.Errorf("distributed entropy (%v) should be greater than concentrated (%v)",
			distributedEntropy, concentratedEntropy)
	}
}

func TestEditEntropyEdgeCases(t *testing.T) {
	// Position at exactly 1.0 should be clamped
	regions := []RegionData{
		{StartPct: 1.0},
	}
	result := EditEntropy(regions, 10)
	if result < 0 {
		t.Errorf("entropy should be non-negative: %v", result)
	}

	// Negative position should be clamped to 0
	regions = []RegionData{
		{StartPct: -0.1},
	}
	result = EditEntropy(regions, 10)
	if result < 0 {
		t.Errorf("entropy should be non-negative: %v", result)
	}
}

func TestMedianInterval(t *testing.T) {
	tests := []struct {
		name      string
		events    []EventData
		expected  float64
		tolerance float64
	}{
		{
			name:     "empty events",
			events:   []EventData{},
			expected: 0,
		},
		{
			name:     "single event",
			events:   makeEvents(1e9),
			expected: 0,
		},
		{
			name:      "two events 1 second apart",
			events:    makeEvents(0, 1e9),
			expected:  1.0,
			tolerance: 0.001,
		},
		{
			name:      "even count (average of two middle)",
			events:    makeEvents(0, 1e9, 3e9, 6e9), // intervals: 1, 2, 3
			expected:  2.0,
			tolerance: 0.001,
		},
		{
			name:      "odd count",
			events:    makeEvents(0, 1e9, 3e9), // intervals: 1, 2
			expected:  1.5,
			tolerance: 0.001,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MedianInterval(tt.events)
			if math.Abs(result-tt.expected) > tt.tolerance {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestMedianIntervalUnsorted(t *testing.T) {
	// Events out of order should still work
	events := []EventData{
		{TimestampNs: 3e9},
		{TimestampNs: 1e9},
		{TimestampNs: 2e9},
	}

	result := MedianInterval(events)
	if math.Abs(result-1.0) > 0.001 {
		t.Errorf("expected median interval of 1.0, got %v", result)
	}
}

func TestPositiveNegativeRatio(t *testing.T) {
	tests := []struct {
		name     string
		regions  []RegionData
		expected float64
	}{
		{
			name:     "empty regions",
			regions:  []RegionData{},
			expected: 0.5, // neutral
		},
		{
			name: "all insertions",
			regions: []RegionData{
				{DeltaSign: 1},
				{DeltaSign: 1},
			},
			expected: 1.0,
		},
		{
			name: "all deletions",
			regions: []RegionData{
				{DeltaSign: -1},
				{DeltaSign: -1},
			},
			expected: 0,
		},
		{
			name: "equal insertions and deletions",
			regions: []RegionData{
				{DeltaSign: 1},
				{DeltaSign: -1},
			},
			expected: 0.5,
		},
		{
			name: "all replacements (zero delta)",
			regions: []RegionData{
				{DeltaSign: 0},
				{DeltaSign: 0},
			},
			expected: 0.5, // neutral when only replacements
		},
		{
			name: "mixed with replacements",
			regions: []RegionData{
				{DeltaSign: 1},
				{DeltaSign: 0}, // excluded
				{DeltaSign: -1},
			},
			expected: 0.5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := PositiveNegativeRatio(tt.regions)
			if math.Abs(result-tt.expected) > 0.0001 {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestDeletionClusteringCoef(t *testing.T) {
	tests := []struct {
		name     string
		regions  []RegionData
		expected float64
	}{
		{
			name:     "no deletions",
			regions:  []RegionData{{DeltaSign: 1}},
			expected: 0,
		},
		{
			name: "only one deletion",
			regions: []RegionData{
				{StartPct: 0.5, DeltaSign: -1},
			},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DeletionClusteringCoef(tt.regions)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestDeletionClusteringCoefClustered(t *testing.T) {
	// Clustered deletions should have low coefficient
	clustered := []RegionData{
		{StartPct: 0.1, DeltaSign: -1},
		{StartPct: 0.11, DeltaSign: -1},
		{StartPct: 0.12, DeltaSign: -1},
	}

	// Scattered deletions should have higher coefficient
	scattered := []RegionData{
		{StartPct: 0.1, DeltaSign: -1},
		{StartPct: 0.5, DeltaSign: -1},
		{StartPct: 0.9, DeltaSign: -1},
	}

	clusteredCoef := DeletionClusteringCoef(clustered)
	scatteredCoef := DeletionClusteringCoef(scattered)

	if scatteredCoef <= clusteredCoef {
		t.Errorf("scattered coef (%v) should be greater than clustered (%v)",
			scatteredCoef, clusteredCoef)
	}
}

func TestFlattenRegions(t *testing.T) {
	regions := map[int64][]RegionData{
		1: {{StartPct: 0.1}, {StartPct: 0.2}},
		2: {{StartPct: 0.3}},
		3: {},
	}

	result := flattenRegions(regions)
	if len(result) != 3 {
		t.Errorf("expected 3 regions, got %d", len(result))
	}
}

func TestFlattenRegionsEmpty(t *testing.T) {
	result := flattenRegions(nil)
	if len(result) != 0 {
		t.Errorf("expected 0 regions, got %d", len(result))
	}

	result = flattenRegions(map[int64][]RegionData{})
	if len(result) != 0 {
		t.Errorf("expected 0 regions, got %d", len(result))
	}
}

// =============================================================================
// Tests for profile.go
// =============================================================================

func TestBuildProfileInsufficient(t *testing.T) {
	events := makeEvents(0, 1e9, 2e9) // Only 3 events

	profile, err := BuildProfile(events, nil)
	if err != nil {
		t.Fatalf("BuildProfile failed: %v", err)
	}

	if profile.Assessment != AssessmentInsufficient {
		t.Errorf("expected AssessmentInsufficient, got %v", profile.Assessment)
	}
}

func TestBuildProfileWithData(t *testing.T) {
	// Create enough events
	events := make([]EventData, 10)
	for i := 0; i < 10; i++ {
		events[i] = EventData{
			ID:          int64(i + 1),
			TimestampNs: int64(i) * 1e9,
			FileSize:    100,
			SizeDelta:   10,
			FilePath:    "/test/file.txt",
		}
	}

	regions := map[int64][]RegionData{}
	for i := 1; i <= 10; i++ {
		regions[int64(i)] = []RegionData{
			{StartPct: float32(i) * 0.09, DeltaSign: 1},
		}
	}

	profile, err := BuildProfile(events, regions)
	if err != nil {
		t.Fatalf("BuildProfile failed: %v", err)
	}

	if profile.EventCount != 10 {
		t.Errorf("expected EventCount 10, got %d", profile.EventCount)
	}
	if profile.FilePath != "/test/file.txt" {
		t.Errorf("expected FilePath /test/file.txt, got %s", profile.FilePath)
	}
	if profile.Assessment == "" {
		t.Error("expected non-empty assessment")
	}
}

func TestDetectSessions(t *testing.T) {
	// Events with 30+ minute gap between them
	events := []EventData{
		{TimestampNs: 0},
		{TimestampNs: 60 * 1e9},        // 1 minute later
		{TimestampNs: 120 * 1e9},       // 2 minutes total
		{TimestampNs: 2000 * 1e9},      // 33+ minutes later (new session)
		{TimestampNs: 2060 * 1e9},      // 1 minute later
	}

	sessions := DetectSessions(events, DefaultSessionGapSec)

	if len(sessions) != 2 {
		t.Errorf("expected 2 sessions, got %d", len(sessions))
	}

	if len(sessions[0]) != 3 {
		t.Errorf("expected 3 events in first session, got %d", len(sessions[0]))
	}

	if len(sessions[1]) != 2 {
		t.Errorf("expected 2 events in second session, got %d", len(sessions[1]))
	}
}

func TestDetectSessionsEmpty(t *testing.T) {
	sessions := DetectSessions([]EventData{}, DefaultSessionGapSec)
	if sessions != nil {
		t.Errorf("expected nil for empty events, got %v", sessions)
	}
}

func TestDetectSessionsSingle(t *testing.T) {
	events := []EventData{{TimestampNs: 0}}
	sessions := DetectSessions(events, DefaultSessionGapSec)

	if len(sessions) != 1 {
		t.Errorf("expected 1 session, got %d", len(sessions))
	}
	if len(sessions[0]) != 1 {
		t.Errorf("expected 1 event in session, got %d", len(sessions[0]))
	}
}

func TestDetectAnomalies(t *testing.T) {
	events := makeEvents(0, 1e9, 2e9, 3e9, 4e9)
	regions := map[int64][]RegionData{}

	// Metrics that trigger anomalies
	metrics := &PrimaryMetrics{
		MonotonicAppendRatio: 0.9, // High (above threshold)
		EditEntropy:          1.0, // Low (below threshold)
	}

	anomalies := DetectAnomalies(events, regions, metrics)

	// Should detect high monotonic and low entropy
	foundMonotonic := false
	foundEntropy := false
	for _, a := range anomalies {
		if a.Type == AnomalyMonotonic {
			foundMonotonic = true
		}
		if a.Type == AnomalyLowEntropy {
			foundEntropy = true
		}
	}

	if !foundMonotonic {
		t.Error("expected to detect high monotonic append ratio")
	}
	if !foundEntropy {
		t.Error("expected to detect low entropy")
	}
}

func TestDetectAnomaliesNilMetrics(t *testing.T) {
	events := makeEvents(0, 1e9)
	regions := map[int64][]RegionData{}

	anomalies := DetectAnomalies(events, regions, nil)

	if len(anomalies) != 0 {
		t.Errorf("expected no anomalies with nil metrics, got %d", len(anomalies))
	}
}

func TestDetectTemporalAnomaliesGap(t *testing.T) {
	// Create events with a 25+ hour gap
	events := []EventData{
		{TimestampNs: 0, SizeDelta: 10},
		{TimestampNs: 25 * 3600 * 1e9, SizeDelta: 10}, // 25 hours later
	}

	anomalies := detectTemporalAnomalies(events, nil)

	foundGap := false
	for _, a := range anomalies {
		if a.Type == AnomalyGap {
			foundGap = true
			break
		}
	}

	if !foundGap {
		t.Error("expected to detect long gap anomaly")
	}
}

func TestDetectTemporalAnomaliesHighVelocity(t *testing.T) {
	// Create events with high-velocity editing
	events := []EventData{
		{TimestampNs: 0, SizeDelta: 0},
		{TimestampNs: 1e9, SizeDelta: 150}, // 150 bytes/sec
	}

	anomalies := detectTemporalAnomalies(events, nil)

	foundHighVelocity := false
	for _, a := range anomalies {
		if a.Type == AnomalyHighVelocity {
			foundHighVelocity = true
			break
		}
	}

	if !foundHighVelocity {
		t.Error("expected to detect high velocity anomaly")
	}
}

func TestAbs32(t *testing.T) {
	if abs32(5) != 5 {
		t.Error("abs32(5) should be 5")
	}
	if abs32(-5) != 5 {
		t.Error("abs32(-5) should be 5")
	}
	if abs32(0) != 0 {
		t.Error("abs32(0) should be 0")
	}
}

func TestDetermineAssessment(t *testing.T) {
	tests := []struct {
		name       string
		metrics    *PrimaryMetrics
		anomalies  []Anomaly
		eventCount int
		expected   Assessment
	}{
		{
			name:       "insufficient events",
			metrics:    &PrimaryMetrics{},
			anomalies:  []Anomaly{},
			eventCount: 5,
			expected:   AssessmentInsufficient,
		},
		{
			name:       "nil metrics",
			metrics:    nil,
			anomalies:  []Anomaly{},
			eventCount: 20,
			expected:   AssessmentInsufficient,
		},
		{
			name: "consistent - normal metrics",
			metrics: &PrimaryMetrics{
				MonotonicAppendRatio:  0.5,
				EditEntropy:           2.5,
				PositiveNegativeRatio: 0.7,
				DeletionClustering:    0.5,
			},
			anomalies:  []Anomaly{},
			eventCount: 20,
			expected:   AssessmentConsistent,
		},
		{
			name: "suspicious - very high monotonic",
			metrics: &PrimaryMetrics{
				MonotonicAppendRatio:  0.95,
				EditEntropy:           2.5,
				PositiveNegativeRatio: 0.7,
				DeletionClustering:    0.5,
			},
			anomalies:  []Anomaly{},
			eventCount: 20,
			expected:   AssessmentConsistent, // Need multiple indicators
		},
		{
			name: "suspicious - multiple indicators",
			metrics: &PrimaryMetrics{
				MonotonicAppendRatio:  0.95,
				EditEntropy:           0.5,
				PositiveNegativeRatio: 0.98,
				DeletionClustering:    1.0,
			},
			anomalies:  []Anomaly{},
			eventCount: 20,
			expected:   AssessmentSuspicious,
		},
		{
			name:    "suspicious - many alerts",
			metrics: &PrimaryMetrics{},
			anomalies: []Anomaly{
				{Severity: SeverityAlert},
				{Severity: SeverityAlert},
			},
			eventCount: 20,
			expected:   AssessmentSuspicious,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetermineAssessment(tt.metrics, tt.anomalies, tt.eventCount)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// =============================================================================
// Tests for report.go
// =============================================================================

func TestPrintReport(t *testing.T) {
	profile := &AuthorshipProfile{
		FilePath:     "/test/file.txt",
		EventCount:   100,
		SessionCount: 5,
		TimeSpan:     48 * time.Hour,
		FirstEvent:   time.Now().Add(-48 * time.Hour),
		LastEvent:    time.Now(),
		Metrics: PrimaryMetrics{
			MonotonicAppendRatio:  0.3,
			EditEntropy:           2.5,
			MedianInterval:        15.0,
			PositiveNegativeRatio: 0.7,
			DeletionClustering:    0.5,
		},
		Anomalies: []Anomaly{
			{
				Type:        AnomalyGap,
				Description: "Long gap detected",
				Severity:    SeverityInfo,
			},
		},
		Assessment: AssessmentConsistent,
	}

	var buf bytes.Buffer
	PrintReport(&buf, profile)

	output := buf.String()

	// Check for key sections
	if !strings.Contains(output, "FORENSIC AUTHORSHIP ANALYSIS") {
		t.Error("output should contain header")
	}
	if !strings.Contains(output, "/test/file.txt") {
		t.Error("output should contain file path")
	}
	if !strings.Contains(output, "PRIMARY METRICS") {
		t.Error("output should contain metrics section")
	}
	if !strings.Contains(output, "ANOMALIES DETECTED") {
		t.Error("output should contain anomalies section")
	}
	if !strings.Contains(output, "ASSESSMENT") {
		t.Error("output should contain assessment")
	}
}

func TestPrintReportNilProfile(t *testing.T) {
	var buf bytes.Buffer
	PrintReport(&buf, nil)

	output := buf.String()
	if !strings.Contains(output, "No profile data available") {
		t.Error("should indicate no data available")
	}
}

func TestPrintReportNoAnomalies(t *testing.T) {
	profile := &AuthorshipProfile{
		EventCount: 10,
		Assessment: AssessmentConsistent,
	}

	var buf bytes.Buffer
	PrintReport(&buf, profile)

	output := buf.String()
	if strings.Contains(output, "ANOMALIES DETECTED") {
		t.Error("should not show anomalies section when empty")
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		duration time.Duration
		contains string
	}{
		{-1 * time.Second, "0 seconds"},
		{0, "0 seconds"},
		{1 * time.Second, "1 second"},
		{30 * time.Second, "30 seconds"},
		{1 * time.Minute, "1 minute"},
		{5*time.Minute + 30*time.Second, "5 minutes"},
		{1 * time.Hour, "1 hour"},
		{2*time.Hour + 30*time.Minute, "2 hours"},
		{24 * time.Hour, "1 day"},
		{48*time.Hour + 5*time.Hour, "2 days"},
	}

	for _, tt := range tests {
		result := FormatDuration(tt.duration)
		if !strings.Contains(result, tt.contains) {
			t.Errorf("FormatDuration(%v) = %q, should contain %q", tt.duration, result, tt.contains)
		}
	}
}

func TestFormatMetricBar(t *testing.T) {
	tests := []struct {
		name     string
		value    float64
		min      float64
		max      float64
		width    int
		expected string
	}{
		{
			name:     "zero width",
			value:    0.5,
			min:      0,
			max:      1,
			width:    0,
			expected: "",
		},
		{
			name:     "min equals max",
			value:    0.5,
			min:      0,
			max:      0,
			width:    10,
			expected: "----------", // No brackets when invalid range
		},
		{
			name:     "at minimum",
			value:    0,
			min:      0,
			max:      1,
			width:    10,
			expected: "[----------]",
		},
		{
			name:     "at maximum",
			value:    1,
			min:      0,
			max:      1,
			width:    10,
			expected: "[##########]",
		},
		{
			name:     "at midpoint",
			value:    0.5,
			min:      0,
			max:      1,
			width:    10,
			expected: "[#####-----]",
		},
		{
			name:     "below minimum clamped",
			value:    -1,
			min:      0,
			max:      1,
			width:    10,
			expected: "[----------]",
		},
		{
			name:     "above maximum clamped",
			value:    2,
			min:      0,
			max:      1,
			width:    10,
			expected: "[##########]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatMetricBar(tt.value, tt.min, tt.max, tt.width)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestSeverityMarker(t *testing.T) {
	tests := []struct {
		severity Severity
		expected string
	}{
		{SeverityAlert, "!!!"},
		{SeverityWarning, " ! "},
		{SeverityInfo, " i "},
		{Severity("unknown"), "   "},
	}

	for _, tt := range tests {
		result := severityMarker(tt.severity)
		if result != tt.expected {
			t.Errorf("severityMarker(%v) = %q, expected %q", tt.severity, result, tt.expected)
		}
	}
}

func TestInterpretFunctions(t *testing.T) {
	// Just verify they don't panic and return non-empty strings
	funcs := []struct {
		name string
		fn   func() string
	}{
		{"interpretMonotonicAppend high", func() string { return interpretMonotonicAppend(0.95) }},
		{"interpretMonotonicAppend mid", func() string { return interpretMonotonicAppend(0.5) }},
		{"interpretMonotonicAppend low", func() string { return interpretMonotonicAppend(0.2) }},
		{"interpretEditEntropy low", func() string { return interpretEditEntropy(0.5) }},
		{"interpretEditEntropy mid", func() string { return interpretEditEntropy(2.5) }},
		{"interpretEditEntropy high", func() string { return interpretEditEntropy(3.5) }},
		{"interpretMedianInterval fast", func() string { return interpretMedianInterval(0.5) }},
		{"interpretMedianInterval mod", func() string { return interpretMedianInterval(15) }},
		{"interpretMedianInterval slow", func() string { return interpretMedianInterval(600) }},
		{"interpretPosNegRatio high", func() string { return interpretPosNegRatio(0.98) }},
		{"interpretPosNegRatio balanced", func() string { return interpretPosNegRatio(0.5) }},
		{"interpretPosNegRatio low", func() string { return interpretPosNegRatio(0.3) }},
		{"interpretDeletionClustering zero", func() string { return interpretDeletionClustering(0) }},
		{"interpretDeletionClustering low", func() string { return interpretDeletionClustering(0.3) }},
		{"interpretDeletionClustering high", func() string { return interpretDeletionClustering(1.5) }},
	}

	for _, f := range funcs {
		t.Run(f.name, func(t *testing.T) {
			result := f.fn()
			if result == "" {
				t.Error("interpret function returned empty string")
			}
		})
	}
}

// =============================================================================
// Tests for types.go (constants and type definitions)
// =============================================================================

func TestAnomalyTypes(t *testing.T) {
	// Verify anomaly type constants
	types := []AnomalyType{
		AnomalyGap,
		AnomalyHighVelocity,
		AnomalyMonotonic,
		AnomalyLowEntropy,
	}

	for _, at := range types {
		if at == "" {
			t.Error("anomaly type should not be empty")
		}
	}
}

func TestSeverityTypes(t *testing.T) {
	severities := []Severity{
		SeverityInfo,
		SeverityWarning,
		SeverityAlert,
	}

	for _, s := range severities {
		if s == "" {
			t.Error("severity should not be empty")
		}
	}
}

func TestAssessmentTypes(t *testing.T) {
	assessments := []Assessment{
		AssessmentConsistent,
		AssessmentSuspicious,
		AssessmentInsufficient,
	}

	for _, a := range assessments {
		if a == "" {
			t.Error("assessment should not be empty")
		}
	}
}

func TestConstants(t *testing.T) {
	if DefaultAppendThreshold <= 0 || DefaultAppendThreshold >= 1 {
		t.Errorf("DefaultAppendThreshold should be between 0 and 1: %v", DefaultAppendThreshold)
	}

	if DefaultHistogramBins <= 0 {
		t.Errorf("DefaultHistogramBins should be positive: %v", DefaultHistogramBins)
	}

	if MinEventsForAnalysis <= 0 {
		t.Errorf("MinEventsForAnalysis should be positive: %v", MinEventsForAnalysis)
	}
}
