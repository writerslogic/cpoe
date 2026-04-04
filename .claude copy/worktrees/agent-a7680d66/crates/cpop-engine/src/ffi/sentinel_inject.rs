

//! FFI functions for keystroke/paste injection from host apps.

use super::sentinel::get_sentinel;
use crate::RwLockRecover;

/
/
/
/
/
/
/
/
/
/
/
/
/
const MAX_INJECT_RATE_PER_SEC: u64 = 50;

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_inject_keystroke(
    timestamp_ns: i64,
    keycode: u16,
    zone: u8,
    source_state_id: i64,
    keyboard_type: i64,
    source_pid: i64,
    char_value: String,
) -> bool {
    let is_key_up = char_value == "UP";

    let sentinel_opt = get_sentinel();
    let sentinel = match sentinel_opt.as_ref() {
        Some(s) if s.is_running() => s,
        _ => return false,
    };

    
    
    if is_key_up {
        let _event = crate::platform::KeystrokeEvent {
            timestamp_ns,
            keycode,
            zone,
            event_type: crate::platform::KeyEventType::Up,
            char_value: None,
            is_hardware: true,
            device_id: None,
            transport_type: None,
        };
        
        
        return true;
    }

    
    
    {
        use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
        static WINDOW_START_NS: AtomicI64 = AtomicI64::new(0);
        static WINDOW_COUNT: AtomicU64 = AtomicU64::new(0);

        let window_start = WINDOW_START_NS.load(Ordering::Relaxed);
        let elapsed_ns = timestamp_ns.saturating_sub(window_start);
        if elapsed_ns > 1_000_000_000 {
            
            WINDOW_START_NS.store(timestamp_ns, Ordering::Relaxed);
            WINDOW_COUNT.store(1, Ordering::Relaxed);
        } else {
            let count = WINDOW_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
            if count > MAX_INJECT_RATE_PER_SEC {
                log::warn!("FFI keystroke injection rate exceeded ({count}/s); rejecting");
                return false;
            }
        }
    }

    
    
    
    let char_opt = char_value.chars().next();
    if let Some(ref mut collector) = *sentinel.voice_collector.write_recover() {
        collector.record_keystroke(keycode, char_opt);
    }

    
    
    const SOURCE_STATE_PRIVATE: i64 = -1;
    const SOURCE_STATE_HID_SYSTEM: i64 = 1;

    
    #[cfg(debug_assertions)]
    {
        use std::sync::atomic::{AtomicU64, Ordering as AO};
        static INJECT_COUNT: AtomicU64 = AtomicU64::new(0);
        static REJECT_COUNT: AtomicU64 = AtomicU64::new(0);
        let n = INJECT_COUNT.fetch_add(1, AO::Relaxed);
        if source_state_id == SOURCE_STATE_PRIVATE || keyboard_type == 0 || source_pid != 0 {
            REJECT_COUNT.fetch_add(1, AO::Relaxed);
        }
        if n < 5 || n % 50 == 0 {
            use std::io::Write;
            let debug_path = std::env::var("CPOP_DATA_DIR")
                .map(|d| format!("{}/inject_debug.txt", d))
                .unwrap_or_else(|_| "/tmp/cpop_inject_debug.txt".to_string());
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&debug_path)
            {
                let _ = writeln!(
                    f,
                    "inject #{}: state={} kbd_type={} pid={} rejected_so_far={}",
                    n,
                    source_state_id,
                    keyboard_type,
                    source_pid,
                    REJECT_COUNT.load(AO::Relaxed)
                );
            }
        }
    }
    if source_state_id == SOURCE_STATE_PRIVATE {
        return false;
    }
    
    
    
    
    let is_unverified_ffi = source_state_id == 0 && keyboard_type == 0 && source_pid == 0;
    if !is_unverified_ffi {
        
        
        if keyboard_type == 0 {
            return false;
        }
        if source_pid != 0 {
            return false;
        }
        if source_state_id != SOURCE_STATE_HID_SYSTEM {
            log::debug!(
                "inject_keystroke: suspicious source_state_id={source_state_id} — accepted"
            );
        }
    }

    
    
    
    
    
    
    
    
    
    
    
    static LAST_INJECT_TS: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);
    let prev_ts = LAST_INJECT_TS.swap(timestamp_ns, std::sync::atomic::Ordering::Relaxed);
    let duration_since_last_ns = if prev_ts > 0 && timestamp_ns > prev_ts {
        (timestamp_ns - prev_ts) as u64
    } else {
        0
    };

    let sample = crate::jitter::SimpleJitterSample {
        timestamp_ns,
        duration_since_last_ns,
        zone,
        dwell_time_ns: None,
        flight_time_ns: None,
    };
    sentinel
        .activity_accumulator
        .write_recover()
        .add_sample(&sample);

    
    let focus = sentinel.current_focus();
    crate::sentinel::trace!("[FFI_INJECT] focus={:?} keycode={}", focus, keycode);
    if let Some(ref path) = focus {
        if let Some(session) = sentinel.sessions.write_recover().get_mut(path) {
            session.keystroke_count += 1;
            crate::sentinel::trace!(
                "[FFI_INJECT] COUNTED {:?} total={}",
                path,
                session.keystroke_count
            );
            let pushed =
                session.jitter_samples.len() < crate::sentinel::types::MAX_DOCUMENT_JITTER_SAMPLES;
            if pushed {
                session.jitter_samples.push(sample.clone());
            }

            let validation = crate::forensics::validate_keystroke_event(
                timestamp_ns,
                keycode,
                zone,
                source_pid,
                None,
                session.has_focus,
                &mut session.event_validation,
            );
            if validation.confidence < 0.1 {
                session.keystroke_count -= 1;
                if pushed {
                    session.jitter_samples.pop();
                }
            }
        }
    }
    true
}

/
/
/
/
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_notify_paste(char_count: i64) -> bool {
    let sentinel_opt = get_sentinel();
    let sentinel = match sentinel_opt.as_ref() {
        Some(s) if s.is_running() => s,
        _ => return false,
    };

    let sessions = sentinel.sessions();
    if sessions.is_empty() {
        return false;
    }

    
    sentinel.set_last_paste_chars(char_count);
    true
}
