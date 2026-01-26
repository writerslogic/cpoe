package forensics

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// PrintReport writes formatted authorship analysis to w.
func PrintReport(w io.Writer, profile *AuthorshipProfile) {
	if profile == nil {
		fmt.Fprintln(w, "No profile data available")
		return
	}

	// Header
	fmt.Fprintln(w, strings.Repeat("=", 72))
	fmt.Fprintln(w, "                    FORENSIC AUTHORSHIP ANALYSIS")
	fmt.Fprintln(w, strings.Repeat("=", 72))
	fmt.Fprintln(w)

	// File info
	if profile.FilePath != "" {
		fmt.Fprintf(w, "File:           %s\n", profile.FilePath)
	}
	fmt.Fprintf(w, "Events:         %d\n", profile.EventCount)
	fmt.Fprintf(w, "Sessions:       %d\n", profile.SessionCount)
	fmt.Fprintf(w, "Time Span:      %s\n", FormatDuration(profile.TimeSpan))
	if !profile.FirstEvent.IsZero() {
		fmt.Fprintf(w, "First Event:    %s\n", profile.FirstEvent.Format(time.RFC3339))
		fmt.Fprintf(w, "Last Event:     %s\n", profile.LastEvent.Format(time.RFC3339))
	}
	fmt.Fprintln(w)

	// Primary Metrics
	fmt.Fprintln(w, strings.Repeat("-", 72))
	fmt.Fprintln(w, "PRIMARY METRICS")
	fmt.Fprintln(w, strings.Repeat("-", 72))
	fmt.Fprintln(w)

	m := profile.Metrics

	// Monotonic Append Ratio
	fmt.Fprintf(w, "Monotonic Append Ratio:   %.3f  %s\n",
		m.MonotonicAppendRatio,
		FormatMetricBar(m.MonotonicAppendRatio, 0, 1, 20))
	fmt.Fprintf(w, "  -> %s\n\n", interpretMonotonicAppend(m.MonotonicAppendRatio))

	// Edit Entropy
	maxEntropy := 4.32 // log2(20) for 20 bins
	fmt.Fprintf(w, "Edit Entropy:             %.3f  %s\n",
		m.EditEntropy,
		FormatMetricBar(m.EditEntropy, 0, maxEntropy, 20))
	fmt.Fprintf(w, "  -> %s\n\n", interpretEditEntropy(m.EditEntropy))

	// Median Interval
	fmt.Fprintf(w, "Median Interval:          %.2f sec\n", m.MedianInterval)
	fmt.Fprintf(w, "  -> %s\n\n", interpretMedianInterval(m.MedianInterval))

	// Positive/Negative Ratio
	fmt.Fprintf(w, "Positive/Negative Ratio:  %.3f  %s\n",
		m.PositiveNegativeRatio,
		FormatMetricBar(m.PositiveNegativeRatio, 0, 1, 20))
	fmt.Fprintf(w, "  -> %s\n\n", interpretPosNegRatio(m.PositiveNegativeRatio))

	// Deletion Clustering
	fmt.Fprintf(w, "Deletion Clustering:      %.3f\n", m.DeletionClustering)
	fmt.Fprintf(w, "  -> %s\n\n", interpretDeletionClustering(m.DeletionClustering))

	// Anomalies
	if len(profile.Anomalies) > 0 {
		fmt.Fprintln(w, strings.Repeat("-", 72))
		fmt.Fprintln(w, "ANOMALIES DETECTED")
		fmt.Fprintln(w, strings.Repeat("-", 72))
		fmt.Fprintln(w)

		for i, a := range profile.Anomalies {
			severityMarker := severityMarker(a.Severity)
			fmt.Fprintf(w, "%d. [%s] %s: %s\n", i+1, severityMarker, a.Type, a.Description)
			if !a.Timestamp.IsZero() {
				fmt.Fprintf(w, "   At: %s\n", a.Timestamp.Format(time.RFC3339))
			}
			if a.Context != "" {
				fmt.Fprintf(w, "   Context: %s\n", a.Context)
			}
		}
		fmt.Fprintln(w)
	}

	// Assessment
	fmt.Fprintln(w, strings.Repeat("=", 72))
	fmt.Fprintf(w, "ASSESSMENT: %s\n", profile.Assessment)
	fmt.Fprintln(w, strings.Repeat("=", 72))
}

// FormatDuration produces human-readable duration (e.g., "132 days").
func FormatDuration(d time.Duration) string {
	if d < 0 {
		return "0 seconds"
	}

	days := int(d.Hours() / 24)
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	if days > 0 {
		if days == 1 {
			return fmt.Sprintf("%d day, %d hours", days, hours)
		}
		return fmt.Sprintf("%d days, %d hours", days, hours)
	}
	if hours > 0 {
		if hours == 1 {
			return fmt.Sprintf("%d hour, %d minutes", hours, minutes)
		}
		return fmt.Sprintf("%d hours, %d minutes", hours, minutes)
	}
	if minutes > 0 {
		if minutes == 1 {
			return fmt.Sprintf("%d minute, %d seconds", minutes, seconds)
		}
		return fmt.Sprintf("%d minutes, %d seconds", minutes, seconds)
	}
	if seconds == 1 {
		return fmt.Sprintf("%d second", seconds)
	}
	return fmt.Sprintf("%d seconds", seconds)
}

// FormatMetricBar produces ASCII progress bar for metric visualization.
func FormatMetricBar(value, min, max float64, width int) string {
	if width <= 0 {
		return ""
	}
	if max <= min {
		return strings.Repeat("-", width)
	}

	// Normalize value to 0-1 range
	normalized := (value - min) / (max - min)
	if normalized < 0 {
		normalized = 0
	}
	if normalized > 1 {
		normalized = 1
	}

	filled := int(normalized * float64(width))
	if filled > width {
		filled = width
	}

	bar := strings.Repeat("#", filled) + strings.Repeat("-", width-filled)
	return "[" + bar + "]"
}

// interpretMonotonicAppend provides human-readable interpretation.
func interpretMonotonicAppend(ratio float64) string {
	switch {
	case ratio > 0.90:
		return "Very high: Nearly all edits at end of document (AI-like pattern)"
	case ratio > 0.70:
		return "High: Most edits at end of document"
	case ratio > 0.40:
		return "Moderate: Mixed editing patterns (typical human behavior)"
	default:
		return "Low: Distributed editing throughout document"
	}
}

// interpretEditEntropy provides human-readable interpretation.
func interpretEditEntropy(entropy float64) string {
	switch {
	case entropy < 1.0:
		return "Very low: Highly concentrated editing (suspicious)"
	case entropy < 2.0:
		return "Low: Somewhat focused editing patterns"
	case entropy < 3.0:
		return "Moderate: Typical editing distribution"
	default:
		return "High: Well-distributed editing (normal revision behavior)"
	}
}

// interpretMedianInterval provides human-readable interpretation.
func interpretMedianInterval(interval float64) string {
	switch {
	case interval < 1:
		return "Very fast: Sub-second editing pace (automated?)"
	case interval < 5:
		return "Fast: Rapid editing pace"
	case interval < 30:
		return "Moderate: Typical typing/thinking pace"
	case interval < 300:
		return "Slow: Thoughtful/deliberate editing"
	default:
		return "Very slow: Extended pauses between edits"
	}
}

// interpretPosNegRatio provides human-readable interpretation.
func interpretPosNegRatio(ratio float64) string {
	switch {
	case ratio > 0.95:
		return "Almost all insertions: No revision behavior (suspicious)"
	case ratio > 0.80:
		return "Mostly insertions: Limited revision"
	case ratio > 0.60:
		return "Balanced toward insertions: Typical drafting pattern"
	case ratio > 0.40:
		return "Balanced: Active revision behavior"
	default:
		return "Mostly deletions: Heavy revision/editing mode"
	}
}

// interpretDeletionClustering provides human-readable interpretation.
func interpretDeletionClustering(coef float64) string {
	switch {
	case coef == 0:
		return "No deletions or insufficient data"
	case coef < 0.5:
		return "Highly clustered: Systematic revision passes (human-like)"
	case coef < 0.8:
		return "Moderately clustered: Natural editing pattern"
	case coef < 1.2:
		return "Scattered: Random deletion distribution (suspicious)"
	default:
		return "Very scattered: Possibly artificial deletion pattern"
	}
}

// severityMarker returns a visual marker for severity levels.
func severityMarker(s Severity) string {
	switch s {
	case SeverityAlert:
		return "!!!"
	case SeverityWarning:
		return " ! "
	case SeverityInfo:
		return " i "
	default:
		return "   "
	}
}
