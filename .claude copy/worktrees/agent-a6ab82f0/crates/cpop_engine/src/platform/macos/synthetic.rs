

//! Synthetic event detection and dual-layer HID validation.

use super::ffi::*;
use super::EventVerificationResult;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::RwLock;

use crate::RwLockRecover;

#[cfg(test)]
use super::DualLayerValidation;
#[cfg(test)]
use std::sync::atomic::AtomicU64;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyntheticEventStats {
    pub total_events: u64,
    pub verified_hardware: u64,
    pub rejected_synthetic: u64,
    pub suspicious_accepted: u64,
    pub rejected_bad_source_state: u64,
    pub rejected_bad_keyboard_type: u64,
    pub rejected_non_kernel_pid: u64,
    pub rejected_zero_timestamp: u64,
}

static SYNTHETIC_STATS: RwLock<SyntheticEventStats> = RwLock::new(SyntheticEventStats {
    total_events: 0,
    verified_hardware: 0,
    rejected_synthetic: 0,
    suspicious_accepted: 0,
    rejected_bad_source_state: 0,
    rejected_bad_keyboard_type: 0,
    rejected_non_kernel_pid: 0,
    rejected_zero_timestamp: 0,
});

static STRICT_MODE: AtomicBool = AtomicBool::new(true);

/
pub fn set_strict_mode(strict: bool) {
    STRICT_MODE.store(strict, Ordering::SeqCst);
}

pub fn get_strict_mode() -> bool {
    STRICT_MODE.load(Ordering::SeqCst)
}

pub fn get_synthetic_stats() -> SyntheticEventStats {
    SYNTHETIC_STATS.read_recover().clone()
}

pub fn reset_synthetic_stats() {
    let mut stats = SYNTHETIC_STATS.write_recover();
    *stats = SyntheticEventStats::default();
}

/
pub fn verify_event_source(event: &core_graphics::event::CGEvent) -> EventVerificationResult {
    let strict = STRICT_MODE.load(Ordering::SeqCst);

    let source_state_id = event.get_integer_value_field(K_CG_EVENT_SOURCE_STATE_ID);
    let keyboard_type = event.get_integer_value_field(K_CG_KEYBOARD_EVENT_KEYBOARD_TYPE);
    let source_pid = event.get_integer_value_field(K_CG_EVENT_SOURCE_UNIX_PROCESS_ID);

    let mut suspicious = false;

    
    if source_state_id == K_CG_EVENT_SOURCE_STATE_PRIVATE {
        let mut stats = SYNTHETIC_STATS.write_recover();
        stats.total_events += 1;
        stats.rejected_synthetic += 1;
        stats.rejected_bad_source_state += 1;
        return EventVerificationResult::Synthetic;
    }

    if source_state_id != K_CG_EVENT_SOURCE_STATE_HID_SYSTEM {
        suspicious = true;
    }

    
    if keyboard_type == 0 {
        if strict {
            let mut stats = SYNTHETIC_STATS.write_recover();
            stats.total_events += 1;
            stats.rejected_synthetic += 1;
            stats.rejected_bad_keyboard_type += 1;
            return EventVerificationResult::Synthetic;
        }
        suspicious = true;
    }

    if keyboard_type > 100 {
        let mut stats = SYNTHETIC_STATS.write_recover();
        stats.total_events += 1;
        stats.rejected_synthetic += 1;
        stats.rejected_bad_keyboard_type += 1;
        return EventVerificationResult::Synthetic;
    }

    
    if source_pid != 0 {
        if strict {
            let mut stats = SYNTHETIC_STATS.write_recover();
            stats.total_events += 1;
            stats.rejected_synthetic += 1;
            stats.rejected_non_kernel_pid += 1;
            return EventVerificationResult::Synthetic;
        }
        suspicious = true;
    }

    let mut stats = SYNTHETIC_STATS.write_recover();
    stats.total_events += 1;
    if suspicious {
        stats.suspicious_accepted += 1;
        EventVerificationResult::Suspicious
    } else {
        stats.verified_hardware += 1;
        EventVerificationResult::Hardware
    }
}







#[cfg(test)]
static HID_KEYSTROKE_COUNT: AtomicU64 = AtomicU64::new(0);
#[cfg(test)]
static HID_MONITOR_RUNNING: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
pub fn get_hid_keystroke_count() -> u64 {
    HID_KEYSTROKE_COUNT.load(Ordering::SeqCst)
}

#[cfg(test)]
pub fn reset_hid_keystroke_count() {
    HID_KEYSTROKE_COUNT.store(0, Ordering::SeqCst)
}

#[cfg(test)]
pub fn is_hid_monitoring_running() -> bool {
    HID_MONITOR_RUNNING.load(Ordering::SeqCst)
}

/
/
/
/
/
#[cfg(test)]
pub fn validate_dual_layer(cg_count: u64) -> DualLayerValidation {
    let hid_count = get_hid_keystroke_count();
    let cg_i64 = i64::try_from(cg_count).unwrap_or(i64::MAX);
    let hid_i64 = i64::try_from(hid_count).unwrap_or(i64::MAX);
    let discrepancy = cg_i64.saturating_sub(hid_i64);

    
    let synthetic_detected =
        discrepancy > 5 && (discrepancy as f64 / hid_count.max(1) as f64) > 0.1;

    DualLayerValidation {
        high_level_count: cg_count,
        low_level_count: hid_count,
        synthetic_detected,
        discrepancy,
    }
}
