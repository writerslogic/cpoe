//go:build integration

package integration

import (
	"bytes"
	"testing"
	"time"

	"witnessd/internal/forensics"
)

// TestForensicAnalysisBasic tests basic forensic analysis workflow.
func TestForensicAnalysisBasic(t *testing.T) {
	// Generate realistic keystroke events
	startTime := time.Now().Add(-2 * time.Hour)
	events := GenerateKeystrokeEvents(100, startTime)
	regions := GenerateRegionData(events)

	// Build profile
	profile, err := forensics.BuildProfile(events, regions)
	AssertNoError(t, err, "profile build should succeed")
	AssertTrue(t, profile != nil, "profile should not be nil")

	// Verify profile fields
	AssertEqual(t, 100, profile.EventCount, "event count should match")
	AssertTrue(t, profile.TimeSpan > 0, "time span should be positive")
	AssertTrue(t, !profile.FirstEvent.IsZero(), "first event should be set")
	AssertTrue(t, !profile.LastEvent.IsZero(), "last event should be set")

	// Verify assessment is computed
	AssertTrue(t, profile.Assessment != "", "assessment should be set")
}

// TestForensicAnalysisWithRealPatterns tests forensic analysis with human-like patterns.
func TestForensicAnalysisWithRealPatterns(t *testing.T) {
	startTime := time.Now().Add(-4 * time.Hour)

	// Create events that simulate realistic human typing
	// - Mix of fast typing bursts and pauses
	// - Some editing (deletions)
	// - Natural distribution of edit positions
	events := make([]forensics.EventData, 0, 200)
	regions := make(map[int64][]forensics.RegionData)

	currentTime := startTime
	fileSize := int64(0)
	eventID := int64(1)

	// Simulate multiple editing sessions
	for session := 0; session < 3; session++ {
		// Typing burst
		for i := 0; i < 50; i++ {
			// Variable typing speed (100ms to 500ms between keystrokes)
			interval := time.Duration(100+i%40*10) * time.Millisecond
			currentTime = currentTime.Add(interval)

			delta := int32(1)
			position := float32(0.95) // Mostly appending

			// Occasional edit in middle of document
			if i%15 == 0 {
				position = float32(i%80) / 100.0
			}

			// Occasional deletion
			if i%12 == 0 {
				delta = -1
			}

			if delta > 0 {
				fileSize += int64(delta)
			}

			events = append(events, forensics.EventData{
				ID:          eventID,
				TimestampNs: currentTime.UnixNano(),
				FileSize:    fileSize,
				SizeDelta:   delta,
				FilePath:    "/test/document.md",
			})

			regions[eventID] = []forensics.RegionData{
				{
					StartPct:  position,
					EndPct:    position + 0.01,
					DeltaSign: int8(delta),
					ByteCount: 10,
				},
			}

			eventID++
		}

		// Pause between sessions (simulate thinking or break)
		currentTime = currentTime.Add(15 * time.Minute)
	}

	// Build profile
	profile, err := forensics.BuildProfile(events, regions)
	AssertNoError(t, err, "profile should build")

	// Check metrics are reasonable for human behavior
	t.Logf("Metrics: MAR=%.2f, Entropy=%.2f, Median=%.2f, PNR=%.2f, DC=%.2f",
		profile.Metrics.MonotonicAppendRatio,
		profile.Metrics.EditEntropy,
		profile.Metrics.MedianInterval,
		profile.Metrics.PositiveNegativeRatio,
		profile.Metrics.DeletionClustering)

	// Human writing should have:
	// - Moderate to high append ratio (but not too high)
	// - Some entropy in edit positions
	// - Reasonable typing intervals
	AssertTrue(t, profile.Metrics.MonotonicAppendRatio > 0.5, "should have mostly appends")
	AssertTrue(t, profile.Metrics.MonotonicAppendRatio < 0.98, "should not be ALL appends")
	AssertTrue(t, profile.Metrics.EditEntropy > 0, "should have some edit distribution")
	AssertTrue(t, profile.Metrics.MedianInterval > 0, "should have positive intervals")
}

// TestForensicAnalysisSuspiciousPatterns tests detection of suspicious patterns.
func TestForensicAnalysisSuspiciousPatterns(t *testing.T) {
	startTime := time.Now().Add(-1 * time.Hour)

	// Create events that look like paste/bulk insert
	// - Very high append ratio (nearly 100%)
	// - Very low entropy
	// - Very fast "typing" (or instant large inserts)
	events := make([]forensics.EventData, 0, 50)
	regions := make(map[int64][]forensics.RegionData)

	currentTime := startTime
	fileSize := int64(0)

	for i := 0; i < 50; i++ {
		// Very fast typing (10ms between events)
		currentTime = currentTime.Add(10 * time.Millisecond)

		// Large inserts (like paste)
		delta := int32(100)
		fileSize += int64(delta)

		eventID := int64(i + 1)
		events = append(events, forensics.EventData{
			ID:          eventID,
			TimestampNs: currentTime.UnixNano(),
			FileSize:    fileSize,
			SizeDelta:   delta,
			FilePath:    "/test/document.md",
		})

		// All appends at end of document
		regions[eventID] = []forensics.RegionData{
			{
				StartPct:  0.98,
				EndPct:    0.99,
				DeltaSign: 1,
				ByteCount: 100,
			},
		}
	}

	// Build profile
	profile, err := forensics.BuildProfile(events, regions)
	AssertNoError(t, err, "profile should build")

	// Check for suspicious indicators
	t.Logf("Suspicious metrics: MAR=%.2f, Entropy=%.2f, Assessment=%s",
		profile.Metrics.MonotonicAppendRatio,
		profile.Metrics.EditEntropy,
		profile.Assessment)

	// Should have very high append ratio
	AssertTrue(t, profile.Metrics.MonotonicAppendRatio > 0.95, "should have very high append ratio")

	// Should have low entropy (all edits in same place)
	AssertTrue(t, profile.Metrics.EditEntropy < 1.0, "should have low entropy")
}

// TestForensicAnomalyDetection tests anomaly detection.
func TestForensicAnomalyDetection(t *testing.T) {
	t.Run("high_monotonic_anomaly", func(t *testing.T) {
		events := GenerateKeystrokeEvents(20, time.Now().Add(-time.Hour))
		regions := GenerateRegionData(events)

		// Create metrics that trigger high monotonic anomaly
		metrics := &forensics.PrimaryMetrics{
			MonotonicAppendRatio:  0.95, // High
			EditEntropy:           2.5,
			MedianInterval:        1.0,
			PositiveNegativeRatio: 0.8,
			DeletionClustering:    0.5,
		}

		anomalies := forensics.DetectAnomalies(events, regions, metrics)

		// Should detect high monotonic append ratio
		hasMonotonic := false
		for _, a := range anomalies {
			if a.Type == forensics.AnomalyMonotonic {
				hasMonotonic = true
				t.Logf("Detected: %s (severity: %s)", a.Description, a.Severity)
			}
		}
		AssertTrue(t, hasMonotonic, "should detect high monotonic anomaly")
	})

	t.Run("low_entropy_anomaly", func(t *testing.T) {
		events := GenerateKeystrokeEvents(20, time.Now().Add(-time.Hour))
		regions := GenerateRegionData(events)

		// Create metrics that trigger low entropy anomaly
		metrics := &forensics.PrimaryMetrics{
			MonotonicAppendRatio:  0.5,
			EditEntropy:           0.5, // Low
			MedianInterval:        1.0,
			PositiveNegativeRatio: 0.8,
			DeletionClustering:    0.5,
		}

		anomalies := forensics.DetectAnomalies(events, regions, metrics)

		// Should detect low entropy
		hasLowEntropy := false
		for _, a := range anomalies {
			if a.Type == forensics.AnomalyLowEntropy {
				hasLowEntropy = true
				t.Logf("Detected: %s (severity: %s)", a.Description, a.Severity)
			}
		}
		AssertTrue(t, hasLowEntropy, "should detect low entropy anomaly")
	})

	t.Run("long_gap_anomaly", func(t *testing.T) {
		startTime := time.Now().Add(-30 * time.Hour)

		// Create events with a very long gap (>24 hours)
		events := []forensics.EventData{
			{
				ID:          1,
				TimestampNs: startTime.UnixNano(),
				SizeDelta:   10,
				FileSize:    10,
			},
			{
				ID:          2,
				TimestampNs: startTime.Add(26 * time.Hour).UnixNano(), // 26 hour gap
				SizeDelta:   10,
				FileSize:    20,
			},
		}

		regions := map[int64][]forensics.RegionData{
			1: {{StartPct: 0.9, DeltaSign: 1}},
			2: {{StartPct: 0.95, DeltaSign: 1}},
		}

		anomalies := forensics.DetectAnomalies(events, regions, nil)

		// Should detect long gap
		hasGap := false
		for _, a := range anomalies {
			if a.Type == forensics.AnomalyGap {
				hasGap = true
				t.Logf("Detected: %s (severity: %s)", a.Description, a.Severity)
			}
		}
		AssertTrue(t, hasGap, "should detect long gap anomaly")
	})

	t.Run("high_velocity_anomaly", func(t *testing.T) {
		startTime := time.Now().Add(-time.Hour)

		// Create events with impossibly high velocity
		events := []forensics.EventData{
			{
				ID:          1,
				TimestampNs: startTime.UnixNano(),
				SizeDelta:   0,
				FileSize:    0,
			},
			{
				ID:          2,
				TimestampNs: startTime.Add(1 * time.Second).UnixNano(),
				SizeDelta:   200, // 200 bytes in 1 second = very fast
				FileSize:    200,
			},
		}

		regions := map[int64][]forensics.RegionData{
			1: {{StartPct: 0.0, DeltaSign: 0}},
			2: {{StartPct: 0.95, DeltaSign: 1}},
		}

		anomalies := forensics.DetectAnomalies(events, regions, nil)

		// Should detect high velocity
		hasHighVelocity := false
		for _, a := range anomalies {
			if a.Type == forensics.AnomalyHighVelocity {
				hasHighVelocity = true
				t.Logf("Detected: %s (severity: %s)", a.Description, a.Severity)
			}
		}
		AssertTrue(t, hasHighVelocity, "should detect high velocity anomaly")
	})
}

// TestForensicSessionDetection tests detection of editing sessions.
func TestForensicSessionDetection(t *testing.T) {
	startTime := time.Now().Add(-5 * time.Hour)

	// Create events with clear session breaks (30+ minute gaps)
	events := []forensics.EventData{}
	currentTime := startTime
	eventID := int64(1)

	// Session 1: 20 events over ~10 minutes
	for i := 0; i < 20; i++ {
		currentTime = currentTime.Add(30 * time.Second)
		events = append(events, forensics.EventData{
			ID:          eventID,
			TimestampNs: currentTime.UnixNano(),
		})
		eventID++
	}

	// Gap: 45 minutes
	currentTime = currentTime.Add(45 * time.Minute)

	// Session 2: 15 events
	for i := 0; i < 15; i++ {
		currentTime = currentTime.Add(30 * time.Second)
		events = append(events, forensics.EventData{
			ID:          eventID,
			TimestampNs: currentTime.UnixNano(),
		})
		eventID++
	}

	// Gap: 2 hours
	currentTime = currentTime.Add(2 * time.Hour)

	// Session 3: 10 events
	for i := 0; i < 10; i++ {
		currentTime = currentTime.Add(30 * time.Second)
		events = append(events, forensics.EventData{
			ID:          eventID,
			TimestampNs: currentTime.UnixNano(),
		})
		eventID++
	}

	// Detect sessions
	sessions := forensics.DetectSessions(events, forensics.DefaultSessionGapSec)

	AssertEqual(t, 3, len(sessions), "should detect 3 sessions")
	AssertEqual(t, 20, len(sessions[0]), "session 1 should have 20 events")
	AssertEqual(t, 15, len(sessions[1]), "session 2 should have 15 events")
	AssertEqual(t, 10, len(sessions[2]), "session 3 should have 10 events")
}

// TestForensicAssessmentDetermination tests assessment determination logic.
func TestForensicAssessmentDetermination(t *testing.T) {
	t.Run("insufficient_data", func(t *testing.T) {
		// Too few events
		assessment := forensics.DetermineAssessment(nil, nil, 5)
		AssertEqual(t, forensics.AssessmentInsufficient, assessment, "should be insufficient")
	})

	t.Run("consistent_human_metrics", func(t *testing.T) {
		metrics := &forensics.PrimaryMetrics{
			MonotonicAppendRatio:  0.6, // Normal
			EditEntropy:           2.5, // Normal
			PositiveNegativeRatio: 0.7, // Normal
			DeletionClustering:    0.5, // Normal
		}

		assessment := forensics.DetermineAssessment(metrics, nil, 100)
		AssertEqual(t, forensics.AssessmentConsistent, assessment, "should be consistent")
	})

	t.Run("suspicious_metrics", func(t *testing.T) {
		// Multiple suspicious indicators
		metrics := &forensics.PrimaryMetrics{
			MonotonicAppendRatio:  0.98, // Very high
			EditEntropy:           0.3,  // Very low
			PositiveNegativeRatio: 0.99, // Almost all additions
			DeletionClustering:    1.5,  // Unusual
		}

		assessment := forensics.DetermineAssessment(metrics, nil, 100)
		AssertEqual(t, forensics.AssessmentSuspicious, assessment, "should be suspicious")
	})

	t.Run("suspicious_due_to_alerts", func(t *testing.T) {
		metrics := &forensics.PrimaryMetrics{
			MonotonicAppendRatio:  0.7,
			EditEntropy:           2.0,
			PositiveNegativeRatio: 0.8,
			DeletionClustering:    0.5,
		}

		// Multiple alerts
		anomalies := []forensics.Anomaly{
			{Type: forensics.AnomalyGap, Severity: forensics.SeverityAlert},
			{Type: forensics.AnomalyHighVelocity, Severity: forensics.SeverityAlert},
		}

		assessment := forensics.DetermineAssessment(metrics, anomalies, 100)
		AssertEqual(t, forensics.AssessmentSuspicious, assessment, "should be suspicious due to alerts")
	})
}

// TestForensicReportGeneration tests report generation.
func TestForensicReportGeneration(t *testing.T) {
	startTime := time.Now().Add(-4 * time.Hour)
	events := GenerateKeystrokeEvents(100, startTime)
	regions := GenerateRegionData(events)

	profile, err := forensics.BuildProfile(events, regions)
	AssertNoError(t, err, "profile should build")

	// Generate report
	var buf bytes.Buffer
	forensics.PrintReport(&buf, profile)

	report := buf.String()

	// Verify report contains expected sections
	AssertTrue(t, len(report) > 0, "report should not be empty")

	// Check for key sections
	sections := []string{
		"FORENSIC AUTHORSHIP ANALYSIS",
		"PRIMARY METRICS",
		"ASSESSMENT",
	}

	for _, section := range sections {
		if !bytes.Contains([]byte(report), []byte(section)) {
			t.Errorf("report should contain '%s'", section)
		}
	}

	t.Logf("Generated report:\n%s", report)
}

// TestForensicReportWithAnomalies tests report with anomalies.
func TestForensicReportWithAnomalies(t *testing.T) {
	profile := &forensics.AuthorshipProfile{
		FilePath:     "/test/document.md",
		EventCount:   100,
		SessionCount: 3,
		TimeSpan:     4 * time.Hour,
		FirstEvent:   time.Now().Add(-4 * time.Hour),
		LastEvent:    time.Now(),
		Metrics: forensics.PrimaryMetrics{
			MonotonicAppendRatio:  0.85,
			EditEntropy:           1.5,
			MedianInterval:        1.0,
			PositiveNegativeRatio: 0.9,
			DeletionClustering:    0.3,
		},
		Anomalies: []forensics.Anomaly{
			{
				Type:        forensics.AnomalyGap,
				Description: "Long gap of 3 hours detected",
				Severity:    forensics.SeverityInfo,
				EventRange:  [2]int64{25, 26},
			},
			{
				Type:        forensics.AnomalyHighVelocity,
				Description: "High editing velocity detected",
				Severity:    forensics.SeverityWarning,
				EventRange:  [2]int64{50, 55},
			},
		},
		Assessment: forensics.AssessmentConsistent,
	}

	var buf bytes.Buffer
	forensics.PrintReport(&buf, profile)

	report := buf.String()

	// Should contain anomalies section
	AssertTrue(t, bytes.Contains([]byte(report), []byte("ANOMALIES DETECTED")),
		"report should contain anomalies section")
	AssertTrue(t, bytes.Contains([]byte(report), []byte("Long gap")),
		"report should mention gap anomaly")
	AssertTrue(t, bytes.Contains([]byte(report), []byte("High editing velocity")),
		"report should mention velocity anomaly")
}

// TestForensicMetricsComputation tests individual metric computations.
func TestForensicMetricsComputation(t *testing.T) {
	t.Run("monotonic_append_ratio", func(t *testing.T) {
		// All appends
		allAppends := []forensics.RegionData{
			{StartPct: 0.96},
			{StartPct: 0.97},
			{StartPct: 0.98},
		}
		ratio := forensics.MonotonicAppendRatio(allAppends, 0.95)
		AssertEqual(t, 1.0, ratio, "all appends should give ratio of 1.0")

		// No appends
		noAppends := []forensics.RegionData{
			{StartPct: 0.1},
			{StartPct: 0.2},
			{StartPct: 0.3},
		}
		ratio = forensics.MonotonicAppendRatio(noAppends, 0.95)
		AssertEqual(t, 0.0, ratio, "no appends should give ratio of 0.0")

		// Mixed
		mixed := []forensics.RegionData{
			{StartPct: 0.1},
			{StartPct: 0.96},
		}
		ratio = forensics.MonotonicAppendRatio(mixed, 0.95)
		AssertEqual(t, 0.5, ratio, "half appends should give ratio of 0.5")
	})

	t.Run("edit_entropy", func(t *testing.T) {
		// All edits in same position (zero entropy)
		concentrated := []forensics.RegionData{
			{StartPct: 0.5},
			{StartPct: 0.5},
			{StartPct: 0.5},
		}
		entropyConc := forensics.EditEntropy(concentrated, 10)

		// Edits spread across document (higher entropy)
		distributed := []forensics.RegionData{
			{StartPct: 0.1},
			{StartPct: 0.3},
			{StartPct: 0.5},
			{StartPct: 0.7},
			{StartPct: 0.9},
		}
		entropyDist := forensics.EditEntropy(distributed, 10)

		AssertTrue(t, entropyDist > entropyConc, "distributed should have higher entropy")
	})

	t.Run("median_interval", func(t *testing.T) {
		// Events 1 second apart
		events := []forensics.EventData{
			{TimestampNs: 0},
			{TimestampNs: 1e9}, // 1 second
			{TimestampNs: 2e9}, // 2 seconds
		}
		median := forensics.MedianInterval(events)
		AssertEqual(t, 1.0, median, "should have median interval of 1 second")
	})

	t.Run("positive_negative_ratio", func(t *testing.T) {
		// All insertions
		allInsertions := []forensics.RegionData{
			{DeltaSign: 1},
			{DeltaSign: 1},
		}
		ratio := forensics.PositiveNegativeRatio(allInsertions)
		AssertEqual(t, 1.0, ratio, "all insertions should give ratio of 1.0")

		// All deletions
		allDeletions := []forensics.RegionData{
			{DeltaSign: -1},
			{DeltaSign: -1},
		}
		ratio = forensics.PositiveNegativeRatio(allDeletions)
		AssertEqual(t, 0.0, ratio, "all deletions should give ratio of 0.0")

		// Equal mix
		equal := []forensics.RegionData{
			{DeltaSign: 1},
			{DeltaSign: -1},
		}
		ratio = forensics.PositiveNegativeRatio(equal)
		AssertEqual(t, 0.5, ratio, "equal mix should give ratio of 0.5")
	})

	t.Run("deletion_clustering", func(t *testing.T) {
		// Clustered deletions (low coefficient)
		clustered := []forensics.RegionData{
			{StartPct: 0.1, DeltaSign: -1},
			{StartPct: 0.11, DeltaSign: -1},
			{StartPct: 0.12, DeltaSign: -1},
		}
		clusteredCoef := forensics.DeletionClusteringCoef(clustered)

		// Scattered deletions (higher coefficient)
		scattered := []forensics.RegionData{
			{StartPct: 0.1, DeltaSign: -1},
			{StartPct: 0.5, DeltaSign: -1},
			{StartPct: 0.9, DeltaSign: -1},
		}
		scatteredCoef := forensics.DeletionClusteringCoef(scattered)

		AssertTrue(t, scatteredCoef > clusteredCoef, "scattered should have higher coefficient")
	})
}

// TestForensicProfileWithInsufficientData tests handling of insufficient data.
func TestForensicProfileWithInsufficientData(t *testing.T) {
	// Too few events
	events := GenerateKeystrokeEvents(3, time.Now())
	regions := GenerateRegionData(events)

	profile, err := forensics.BuildProfile(events, regions)
	AssertNoError(t, err, "should handle insufficient data gracefully")

	// Should return profile with insufficient assessment
	AssertEqual(t, forensics.AssessmentInsufficient, profile.Assessment,
		"should be marked as insufficient data")
}

// TestForensicIntegrationWithEvidence tests forensic integration with evidence packets.
func TestForensicIntegrationWithEvidence(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	env.InitPUF()
	env.InitKeyHierarchy()
	env.InitChain()

	// Create checkpoints
	env.CreateCheckpoint("Initial")
	env.ModifyDocument("\nMore content\n")
	env.CreateCheckpoint("Second")

	// Generate forensic data
	events := GenerateKeystrokeEvents(50, time.Now().Add(-time.Hour))
	regions := GenerateRegionData(events)

	profile, err := forensics.BuildProfile(events, regions)
	AssertNoError(t, err, "profile should build")

	// Create forensic metrics for evidence
	metrics := &ForensicMetricsForEvidence{
		MonotonicAppendRatio:  profile.Metrics.MonotonicAppendRatio,
		EditEntropy:           profile.Metrics.EditEntropy,
		MedianInterval:        profile.Metrics.MedianInterval,
		PositiveNegativeRatio: profile.Metrics.PositiveNegativeRatio,
		DeletionClustering:    profile.Metrics.DeletionClustering,
		Assessment:            string(profile.Assessment),
	}

	t.Logf("Forensic metrics for evidence: %+v", metrics)

	// Verify metrics are reasonable
	AssertTrue(t, metrics.MonotonicAppendRatio >= 0 && metrics.MonotonicAppendRatio <= 1,
		"MAR should be in [0,1]")
	AssertTrue(t, metrics.EditEntropy >= 0, "entropy should be non-negative")
	AssertTrue(t, metrics.Assessment != "", "assessment should be set")
}

// ForensicMetricsForEvidence is a simplified version for evidence packets.
type ForensicMetricsForEvidence struct {
	MonotonicAppendRatio  float64 `json:"monotonic_append_ratio"`
	EditEntropy           float64 `json:"edit_entropy"`
	MedianInterval        float64 `json:"median_interval"`
	PositiveNegativeRatio float64 `json:"positive_negative_ratio"`
	DeletionClustering    float64 `json:"deletion_clustering"`
	Assessment            string  `json:"assessment"`
}
