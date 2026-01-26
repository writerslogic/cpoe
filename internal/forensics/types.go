// Package forensics provides metrics and analysis for forensic authorship detection.
package forensics

import "time"

// EventData is the minimal event info needed for forensic analysis.
type EventData struct {
	ID          int64
	TimestampNs int64
	FileSize    int64
	SizeDelta   int32
	FilePath    string
}

// RegionData is edit region info for topology analysis.
type RegionData struct {
	StartPct  float32
	EndPct    float32
	DeltaSign int8
	ByteCount int32
}

// PrimaryMetrics are the 5 core detection metrics.
type PrimaryMetrics struct {
	MonotonicAppendRatio  float64 // Fraction of edits at EOF (>0.95 position)
	EditEntropy           float64 // Shannon entropy of position histogram (20 bins)
	MedianInterval        float64 // Median inter-event interval in seconds
	PositiveNegativeRatio float64 // Insertions / (insertions + deletions)
	DeletionClustering    float64 // Nearest-neighbor ratio for deletions
}

// AuthorshipProfile is the complete analysis output.
type AuthorshipProfile struct {
	FilePath     string
	EventCount   int
	TimeSpan     time.Duration
	SessionCount int
	FirstEvent   time.Time
	LastEvent    time.Time

	Metrics PrimaryMetrics

	Anomalies  []Anomaly
	Assessment Assessment
}

// Anomaly represents a detected suspicious pattern.
type Anomaly struct {
	Timestamp   time.Time
	Type        AnomalyType
	Description string
	Severity    Severity
	Context     string // Declared context if any
}

// AnomalyType categorizes the kind of anomaly detected.
type AnomalyType string

const (
	AnomalyGap          AnomalyType = "gap"
	AnomalyHighVelocity AnomalyType = "high_velocity"
	AnomalyMonotonic    AnomalyType = "monotonic_append"
	AnomalyLowEntropy   AnomalyType = "low_entropy"
)

// Severity indicates the importance level of an anomaly.
type Severity string

const (
	SeverityInfo    Severity = "info"
	SeverityWarning Severity = "warning"
	SeverityAlert   Severity = "alert"
)

// Assessment is the overall verdict for authorship analysis.
type Assessment string

const (
	AssessmentConsistent   Assessment = "CONSISTENT WITH HUMAN AUTHORSHIP"
	AssessmentSuspicious   Assessment = "SUSPICIOUS PATTERNS DETECTED"
	AssessmentInsufficient Assessment = "INSUFFICIENT DATA"
)
