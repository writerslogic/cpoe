

//! Sentinel FFI — in-process sentinel lifecycle for GUI apps.
//!
//! Eliminates the CLI dependency by running the sentinel directly via FFI.
//! Uses a global `OnceLock<Arc<Sentinel>>` matching the `ephemeral.rs` pattern
//! and a lazy Tokio runtime for async operations.

use crate::config::SentinelConfig;
use crate::ffi::helpers::{get_data_dir, load_hmac_key};
use crate::ffi::types::FfiResult;
use crate::sentinel::Sentinel;
use std::sync::{Arc, Mutex};

static SENTINEL: Mutex<Option<Arc<Sentinel>>> = Mutex::new(None);
static FFI_RUNTIME: Mutex<Option<Arc<tokio::runtime::Runtime>>> = Mutex::new(None);

pub(crate) fn get_sentinel() -> Option<Arc<Sentinel>> {
    SENTINEL
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .as_ref()
        .map(Arc::clone)
}

fn ffi_runtime() -> Result<Arc<tokio::runtime::Runtime>, String> {
    let mut guard = FFI_RUNTIME.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(rt) = guard.as_ref() {
        return Ok(Arc::clone(rt));
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .thread_name("cpop-ffi")
        .build()
        .map_err(|e| format!("Failed to create FFI tokio runtime: {e}"))?;
    let rt = Arc::new(rt);
    *guard = Some(Arc::clone(&rt));
    Ok(rt)
}

/
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_start() -> FfiResult {
    
    #[cfg(debug_assertions)]
    {
        use std::io::Write;
        let debug_path = std::env::var("CPOP_DATA_DIR")
            .map(|d| format!("{}/sentinel_debug.txt", d))
            .unwrap_or_else(|_| "/tmp/cpop_sentinel_debug.txt".to_string());
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&debug_path)
        {
            let _ = writeln!(f, "ffi_sentinel_start called");
        }
    }
    
    let existing = get_sentinel();
    if existing.as_ref().is_some_and(|s| s.is_running()) {
        return FfiResult {
            success: true,
            message: Some("Sentinel already running".to_string()),
            error_message: None,
        };
    }

    let data_dir = match get_data_dir() {
        Some(d) => d,
        None => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some("Cannot determine data directory".to_string()),
            };
        }
    };

    if !data_dir.exists() {
        if let Err(e) = std::fs::create_dir_all(&data_dir) {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!(
                    "Cannot create data directory {}: {e}",
                    data_dir.display()
                )),
            };
        }
    }

    #[cfg(target_os = "macos")]
    let accessibility_granted = crate::sentinel::macos_focus::check_accessibility_permissions();
    #[cfg(target_os = "macos")]
    let input_monitoring_granted = crate::platform::macos::check_input_monitoring_permissions();

    #[cfg(target_os = "macos")]
    if !accessibility_granted {
        return FfiResult {
            success: false,
            message: None,
            error_message: Some(
                "Accessibility permission required — grant access in System \
                 Settings > Privacy & Security > Accessibility"
                    .to_string(),
            ),
        };
    }

    #[cfg(target_os = "macos")]
    if !input_monitoring_granted {
        return FfiResult {
            success: false,
            message: None,
            error_message: Some(
                "Input Monitoring permission required — grant access in System \
                 Settings > Privacy & Security > Input Monitoring"
                    .to_string(),
            ),
        };
    }

    
    let is_new_sentinel = existing.is_none();
    let sentinel = if let Some(s) = existing {
        s
    } else {
        let config = SentinelConfig::default().with_writersproof_dir(&data_dir);
        let s = match Sentinel::new(config) {
            Ok(s) => Arc::new(s),
            Err(e) => {
                return FfiResult {
                    success: false,
                    message: None,
                    error_message: Some(format!("Failed to create sentinel: {e}")),
                };
            }
        };
        if let Some(mut key) = load_hmac_key() {
            s.set_hmac_key(std::mem::take(&mut *key));
        }
        
        if let Ok(mut guard) = SENTINEL.lock() {
            *guard = Some(Arc::clone(&s));
        }
        s
    };

    let rt = match ffi_runtime() {
        Ok(rt) => rt,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(e),
            };
        }
    };
    crate::sentinel::trace!("[FFI] ffi_sentinel_start calling sentinel.start()");
    let start_result = rt.block_on(async {
        tokio::time::timeout(std::time::Duration::from_secs(10), sentinel.start()).await
    });
    match start_result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            if is_new_sentinel {
                if let Ok(mut guard) = SENTINEL.lock() {
                    *guard = None;
                }
            }
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Failed to start sentinel: {e}")),
            };
        }
        Err(_) => {
            if is_new_sentinel {
                if let Ok(mut guard) = SENTINEL.lock() {
                    *guard = None;
                }
            }
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(
                    "Sentinel start timed out — check accessibility permissions".to_string(),
                ),
            };
        }
    }

    let capture_active = sentinel.is_keystroke_capture_active();

    let msg = if capture_active {
        "Sentinel started".to_string()
    } else {
        "Sentinel started in degraded mode — keystroke capture unavailable. \
         Check Input Monitoring permission in System Settings > Privacy & Security"
            .to_string()
    };

    #[cfg(debug_assertions)]
    {
        use std::io::Write;
        let debug_path = std::env::var("CPOP_DATA_DIR")
            .map(|d| format!("{}/sentinel_debug.txt", d))
            .unwrap_or_else(|_| "/tmp/cpop_sentinel_debug.txt".to_string());
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&debug_path)
        {
            let _ = writeln!(
                f,
                "sentinel started: capture_active={capture_active} msg={msg}"
            );
        }
    }
    FfiResult {
        success: true,
        message: Some(msg),
        error_message: None,
    }
}

/
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_stop() -> FfiResult {
    let sentinel = match get_sentinel() {
        Some(s) => s,
        None => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some("Sentinel not initialized".to_string()),
            };
        }
    };

    if !sentinel.is_running() {
        return FfiResult {
            success: true,
            message: Some("Sentinel already stopped".to_string()),
            error_message: None,
        };
    }

    let rt = match ffi_runtime() {
        Ok(rt) => rt,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(e),
            };
        }
    };
    let stop_result = rt.block_on(async {
        tokio::time::timeout(std::time::Duration::from_secs(5), sentinel.stop()).await
    });
    match stop_result {
        Err(_) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some("Sentinel stop timed out after 5s".to_string()),
            };
        }
        Ok(Err(e)) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Failed to stop sentinel: {e}")),
            };
        }
        Ok(Ok(())) => {}
    }

    
    
    

    FfiResult {
        success: true,
        message: Some("Sentinel stopped".to_string()),
        error_message: None,
    }
}

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_is_running() -> bool {
    get_sentinel().is_some_and(|s| s.is_running())
}

/
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_restart_keystroke_capture() -> FfiResult {
    let sentinel = match get_sentinel() {
        Some(s) => s,
        None => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some("Sentinel not initialized".to_string()),
            };
        }
    };

    if !sentinel.is_running() {
        return FfiResult {
            success: false,
            message: None,
            error_message: Some("Sentinel not running".to_string()),
        };
    }

    if sentinel.restart_keystroke_capture() {
        FfiResult {
            success: true,
            message: Some("Keystroke capture restarted".to_string()),
            error_message: None,
        }
    } else {
        FfiResult {
            success: false,
            message: None,
            error_message: Some(
                "Failed to restart keystroke capture. \
                 Check Input Monitoring permission in System Settings > Privacy & Security"
                    .to_string(),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::sentinel_witnessing::*;

    #[test]
    fn test_sentinel_not_initialized() {
        assert!(!ffi_sentinel_is_running());
    }

    #[test]
    fn test_sentinel_status_not_initialized() {
        let status = ffi_sentinel_status();
        assert!(!status.running);
        assert_eq!(status.tracked_file_count, 0);
        assert!(status.tracked_files.is_empty());
        assert_eq!(status.keystroke_count, 0);
    }

    #[test]
    fn test_sentinel_start_witnessing_not_initialized() {
        let result = ffi_sentinel_start_witnessing("/tmp/test.txt".to_string());
        assert!(!result.success);
        assert!(result
            .error_message
            .unwrap_or_default()
            .contains("not initialized"));
    }

    #[test]
    fn test_witnessing_status_not_initialized() {
        let status = ffi_sentinel_witnessing_status();
        assert!(!status.is_tracking);
        assert!(status.document_path.is_none());
        assert_eq!(status.keystroke_count, 0);
        assert_eq!(status.event_count, 0);
        assert!(!status.keystroke_capture_active);
    }

    #[test]
    fn test_sentinel_stop_not_initialized() {
        let result = ffi_sentinel_stop();
        assert!(!result.success);
        assert!(result
            .error_message
            .unwrap_or_default()
            .contains("not initialized"));
    }

    #[test]
    fn test_stop_witnessing_not_initialized() {
        let result = ffi_sentinel_stop_witnessing("/tmp/nonexistent.txt".to_string());
        assert!(!result.success);
        let err = result.error_message.unwrap_or_default();
        assert!(err.contains("not initialized"), "unexpected error: {err}");
    }

    #[test]
    fn test_start_witnessing_empty_path() {
        let result = ffi_sentinel_start_witnessing(String::new());
        assert!(!result.success);
        
        assert!(result.error_message.is_some());
    }

    #[test]
    fn test_start_witnessing_traversal_path() {
        let result = ffi_sentinel_start_witnessing("/../../../etc/passwd".to_string());
        assert!(!result.success);
        assert!(result.error_message.is_some());
    }

    #[test]
    fn test_sentinel_oncelock_returns_consistent_state() {
        
        
        let r1 = ffi_sentinel_is_running();
        let r2 = ffi_sentinel_is_running();
        assert_eq!(r1, r2);
        assert!(!r1);
    }

    #[test]
    fn test_permission_error_message_format() {
        
        let accessibility_msg = "Accessibility permission required — grant access in System \
                 Settings > Privacy & Security > Accessibility";
        let input_msg = "Input Monitoring permission required — grant access in System \
                 Settings > Privacy & Security > Input Monitoring";

        
        assert!(accessibility_msg.contains("Accessibility permission required"));
        assert!(accessibility_msg.contains("Privacy & Security"));
        assert!(input_msg.contains("Input Monitoring permission required"));
        assert!(input_msg.contains("Privacy & Security"));
    }

    #[test]
    fn test_data_dir_resolves() {
        
        let _lock = crate::ffi::helpers::lock_ffi_env();
        let prev = std::env::var("CPOP_DATA_DIR").ok();
        std::env::remove_var("CPOP_DATA_DIR");

        let dir = crate::ffi::helpers::get_data_dir();
        assert!(dir.is_some(), "get_data_dir() returned None");
        let dir = dir.unwrap();
        assert!(
            dir.ends_with("CPOP") || dir.ends_with("WritersProof"),
            "data dir should end with CPOP or WritersProof, got: {}",
            dir.display()
        );

        
        if let Some(v) = prev {
            std::env::set_var("CPOP_DATA_DIR", v);
        }
    }

    #[test]
    fn test_validate_path_rejects_empty() {
        let result = crate::sentinel::helpers::validate_path("");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_path_rejects_traversal() {
        let result = crate::sentinel::helpers::validate_path("/tmp/../../../etc/shadow");
        
        
        
        if let Ok(p) = &result {
            
            let s = p.to_string_lossy();
            assert!(
                !s.starts_with("/etc/"),
                "traversal escaped to system path: {s}"
            );
        }
    }

    #[test]
    fn test_validate_path_accepts_tmp_file() {
        
        let tmp = std::env::temp_dir().join("cpop_test_validate_path.txt");
        std::fs::write(&tmp, b"test").expect("write temp file");
        let result = crate::sentinel::helpers::validate_path(&tmp);
        assert!(result.is_ok(), "validate_path failed: {result:?}");
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_ffi_result_error_has_no_message() {
        
        let result = ffi_sentinel_stop();
        assert!(!result.success);
        assert!(result.message.is_none());
        assert!(result.error_message.is_some());
    }

    #[test]
    fn test_sentinel_status_defaults_when_not_running() {
        let status = ffi_sentinel_status();
        assert!(!status.running);
        assert_eq!(status.tracked_file_count, 0);
        assert_eq!(status.uptime_secs, 0);
        assert!(status.focus_duration.is_empty());
    }
}
