

//! Multi-phase verification pipeline: forensic analysis on packet behavioral data.

use std::collections::HashMap;

use crate::evidence::Packet;
use crate::forensics::{
    analyze_forensics_ext, per_checkpoint_flags, AnalysisContext, EventData, ForensicMetrics,
    PerCheckpointResult, RegionData, PER_CHECKPOINT_SUSPICIOUS_THRESHOLD,
};
use crate::jitter::SimpleJitterSample;

/
pub(super) fn run_forensics(
    packet: &Packet,
    warnings: &mut Vec<String>,
) -> (Option<ForensicMetrics>, Option<PerCheckpointResult>) {
    
    let events: Vec<EventData> = if let Some(ref behavioral) = packet.behavioral {
        behavioral
            .edit_topology
            .iter()
            .enumerate()
            .map(|(i, _region)| EventData {
                id: i as i64,
                timestamp_ns: 0,
                file_size: packet.document.final_size as i64,
                size_delta: 0,
                file_path: packet.document.path.clone(),
            })
            .collect()
    } else {
        Vec::new()
    };

    
    
    let jitter_samples: Vec<SimpleJitterSample> = if let Some(ref ks) = packet.keystroke {
        let mut simple = Vec::with_capacity(ks.samples.len());
        let mut prev_ns: Option<i64> = None;
        for s in &ks.samples {
            let ts_ns = s.timestamp.timestamp_nanos_opt().unwrap_or_else(|| {
                log::warn!("timestamp_nanos_opt overflow for sample; falling back to 0");
                0
            });
            let duration = if let Some(prev) = prev_ns {
                (ts_ns - prev).max(0) as u64
            } else {
                0
            };
            simple.push(SimpleJitterSample {
                timestamp_ns: ts_ns,
                duration_since_last_ns: duration,
                zone: 0,
                dwell_time_ns: None,
                flight_time_ns: None,
            });
            prev_ns = Some(ts_ns);
        }
        simple
    } else {
        Vec::new()
    };

    
    
    let regions: HashMap<i64, Vec<RegionData>> = HashMap::new();

    let context = AnalysisContext {
        document_length: packet.document.final_size as i64,
        total_keystrokes: packet
            .keystroke
            .as_ref()
            .map(|k| k.total_keystrokes as i64)
            .unwrap_or(0),
        checkpoint_count: packet.checkpoints.len() as u64,
    };

    let has_data = !jitter_samples.is_empty() || !events.is_empty();
    if !has_data {
        warnings.push("No behavioral/keystroke data available for forensic analysis".to_string());
        return (None, None);
    }

    
    
    let all_zero_timestamps = !events.is_empty() && events.iter().all(|e| e.timestamp_ns == 0);
    if all_zero_timestamps && jitter_samples.is_empty() {
        warnings.push(
            "All events have timestamp_ns=0 (synthetic); skipping forensic analysis".to_string(),
        );
        return (None, None);
    }
    if all_zero_timestamps && !jitter_samples.is_empty() {
        warnings.push(
            "Forensic analysis used jitter samples only; edit topology timestamps were all zero."
                .to_string(),
        );
    }

    let forensics = analyze_forensics_ext(
        &events,
        &regions,
        if jitter_samples.is_empty() {
            None
        } else {
            Some(&jitter_samples)
        },
        None, 
        None, 
        &context,
    );

    
    
    
    
    let events_have_timestamps = events.iter().any(|e| e.timestamp_ns > 0);
    let per_cp = if packet.checkpoints.len() >= 2 && events_have_timestamps {
        let result = per_checkpoint_flags(&events, &packet.checkpoints);
        if result.suspicious {
            warnings.push(format!(
                "Per-checkpoint analysis: {:.0}% of checkpoints flagged (threshold: {:.0}%)",
                result.pct_flagged * 100.0,
                PER_CHECKPOINT_SUSPICIOUS_THRESHOLD * 100.0,
            ));
        }
        Some(result)
    } else {
        None
    };

    (Some(forensics), per_cp)
}
