package forensics

import (
	"sort"
	"time"
)

// Default thresholds for anomaly detection.
// These are empirically-derived placeholders until Phase 0 data is available.
const (
	// DefaultSessionGapSec is the gap threshold for session detection (30 minutes).
	DefaultSessionGapSec = 1800.0

	// Thresholds for anomaly detection
	ThresholdMonotonicAppend  = 0.85 // High append ratio suggests AI generation
	ThresholdLowEntropy       = 1.5  // Low entropy suggests non-human editing
	ThresholdHighVelocityBps  = 100  // Bytes per second threshold
	ThresholdGapHours         = 24.0 // Long gap worth noting

	// Assessment thresholds
	MinEventsForAssessment = 10
	AlertThreshold         = 2 // Number of alerts to trigger suspicious assessment
)

// BuildProfile constructs a complete AuthorshipProfile from events and regions.
func BuildProfile(events []EventData, regionsByEvent map[int64][]RegionData) (*AuthorshipProfile, error) {
	if len(events) < MinEventsForAnalysis {
		return &AuthorshipProfile{
			EventCount: len(events),
			Assessment: AssessmentInsufficient,
		}, nil
	}

	// Sort events by timestamp
	sorted := make([]EventData, len(events))
	copy(sorted, events)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].TimestampNs < sorted[j].TimestampNs
	})

	// Determine file path (use first event's path)
	filePath := ""
	if len(sorted) > 0 {
		filePath = sorted[0].FilePath
	}

	// Calculate time span
	firstTs := time.Unix(0, sorted[0].TimestampNs)
	lastTs := time.Unix(0, sorted[len(sorted)-1].TimestampNs)
	timeSpan := lastTs.Sub(firstTs)

	// Detect sessions
	sessions := DetectSessions(sorted, DefaultSessionGapSec)

	// Compute primary metrics
	metrics, err := ComputePrimaryMetrics(sorted, regionsByEvent)
	if err != nil {
		return &AuthorshipProfile{
			FilePath:     filePath,
			EventCount:   len(events),
			TimeSpan:     timeSpan,
			SessionCount: len(sessions),
			FirstEvent:   firstTs,
			LastEvent:    lastTs,
			Assessment:   AssessmentInsufficient,
		}, nil
	}

	// Detect anomalies
	anomalies := DetectAnomalies(sorted, regionsByEvent, metrics)

	// Determine overall assessment
	assessment := DetermineAssessment(metrics, anomalies, len(events))

	return &AuthorshipProfile{
		FilePath:     filePath,
		EventCount:   len(events),
		TimeSpan:     timeSpan,
		SessionCount: len(sessions),
		FirstEvent:   firstTs,
		LastEvent:    lastTs,
		Metrics:      *metrics,
		Anomalies:    anomalies,
		Assessment:   assessment,
	}, nil
}

// DetectSessions clusters events into sessions based on gap threshold.
// Default gap: 30 minutes of inactivity.
func DetectSessions(events []EventData, gapThresholdSec float64) [][]EventData {
	if len(events) == 0 {
		return nil
	}

	// Sort events by timestamp
	sorted := make([]EventData, len(events))
	copy(sorted, events)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].TimestampNs < sorted[j].TimestampNs
	})

	var sessions [][]EventData
	currentSession := []EventData{sorted[0]}

	for i := 1; i < len(sorted); i++ {
		deltaNs := sorted[i].TimestampNs - sorted[i-1].TimestampNs
		deltaSec := float64(deltaNs) / 1e9

		if deltaSec > gapThresholdSec {
			// Start new session
			sessions = append(sessions, currentSession)
			currentSession = []EventData{sorted[i]}
		} else {
			currentSession = append(currentSession, sorted[i])
		}
	}

	// Add final session
	if len(currentSession) > 0 {
		sessions = append(sessions, currentSession)
	}

	return sessions
}

// DetectAnomalies identifies suspicious patterns.
// Uses empirically-derived thresholds (placeholders until Phase 0 data).
func DetectAnomalies(events []EventData, regions map[int64][]RegionData, metrics *PrimaryMetrics) []Anomaly {
	var anomalies []Anomaly

	if metrics == nil {
		return anomalies
	}

	// Check for high monotonic append ratio
	if metrics.MonotonicAppendRatio > ThresholdMonotonicAppend {
		anomalies = append(anomalies, Anomaly{
			Type:        AnomalyMonotonic,
			Description: "High monotonic append ratio suggests sequential content generation",
			Severity:    SeverityWarning,
		})
	}

	// Check for low edit entropy
	if metrics.EditEntropy < ThresholdLowEntropy && metrics.EditEntropy > 0 {
		anomalies = append(anomalies, Anomaly{
			Type:        AnomalyLowEntropy,
			Description: "Low edit entropy indicates concentrated editing patterns",
			Severity:    SeverityWarning,
		})
	}

	// Detect gaps and high-velocity bursts
	anomalies = append(anomalies, detectTemporalAnomalies(events, regions)...)

	return anomalies
}

// detectTemporalAnomalies identifies gaps and high-velocity editing periods.
func detectTemporalAnomalies(events []EventData, regions map[int64][]RegionData) []Anomaly {
	var anomalies []Anomaly

	if len(events) < 2 {
		return anomalies
	}

	// Sort events by timestamp
	sorted := make([]EventData, len(events))
	copy(sorted, events)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].TimestampNs < sorted[j].TimestampNs
	})

	for i := 1; i < len(sorted); i++ {
		prev := sorted[i-1]
		curr := sorted[i]

		deltaNs := curr.TimestampNs - prev.TimestampNs
		deltaSec := float64(deltaNs) / 1e9
		deltaHours := deltaSec / 3600

		// Check for long gaps
		if deltaHours > ThresholdGapHours {
			anomalies = append(anomalies, Anomaly{
				Timestamp:   time.Unix(0, curr.TimestampNs),
				Type:        AnomalyGap,
				Description: "Long editing gap detected",
				Severity:    SeverityInfo,
			})
		}

		// Check for high-velocity editing
		if deltaSec > 0 && deltaSec < 60 { // Within a minute window
			bytesDelta := abs32(curr.SizeDelta)
			bytesPerSec := float64(bytesDelta) / deltaSec
			if bytesPerSec > ThresholdHighVelocityBps {
				anomalies = append(anomalies, Anomaly{
					Timestamp:   time.Unix(0, curr.TimestampNs),
					Type:        AnomalyHighVelocity,
					Description: "High-velocity content addition detected",
					Severity:    SeverityWarning,
				})
			}
		}
	}

	return anomalies
}

// abs32 returns the absolute value of an int32.
// Handles the special case of math.MinInt32 (-2147483648) which cannot be negated
// without overflow in two's complement, returning math.MaxInt32 instead.
func abs32(x int32) int32 {
	if x == -2147483648 { // math.MinInt32
		return 2147483647 // math.MaxInt32
	}
	if x < 0 {
		return -x
	}
	return x
}

// DetermineAssessment produces overall verdict based on metrics and anomalies.
func DetermineAssessment(metrics *PrimaryMetrics, anomalies []Anomaly, eventCount int) Assessment {
	if eventCount < MinEventsForAssessment {
		return AssessmentInsufficient
	}

	if metrics == nil {
		return AssessmentInsufficient
	}

	// Count alerts
	alertCount := 0
	warningCount := 0
	for _, a := range anomalies {
		switch a.Severity {
		case SeverityAlert:
			alertCount++
		case SeverityWarning:
			warningCount++
		}
	}

	// Multiple concerning patterns
	suspiciousIndicators := 0

	// Very high monotonic append ratio
	if metrics.MonotonicAppendRatio > 0.90 {
		suspiciousIndicators++
	}

	// Very low entropy
	if metrics.EditEntropy < 1.0 && metrics.EditEntropy > 0 {
		suspiciousIndicators++
	}

	// Extreme positive/negative ratio (almost all insertions)
	if metrics.PositiveNegativeRatio > 0.95 {
		suspiciousIndicators++
	}

	// No clustering in deletions (scattered, suggests fake revision)
	if metrics.DeletionClustering > 0.9 && metrics.DeletionClustering < 1.1 {
		suspiciousIndicators++
	}

	// Determine verdict
	if alertCount >= AlertThreshold || suspiciousIndicators >= 3 {
		return AssessmentSuspicious
	}

	if warningCount >= 3 || suspiciousIndicators >= 2 {
		return AssessmentSuspicious
	}

	return AssessmentConsistent
}
