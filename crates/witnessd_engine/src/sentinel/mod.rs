// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Active Document Sentinel - Background document tracking daemon
//!
//! The Active Document Sentinel monitors which documents have user focus and
//! manages tracking sessions automatically. It operates invisibly during
//! normal writing, only surfacing when the user explicitly requests status.
//!
//! Key features:
//!   - Automatic detection of focused documents across applications
//!   - Debounced focus change handling (500ms default)
//!   - Multi-document session management
//!   - Shadow buffers for unsaved documents
//!   - Platform-specific focus detection (macOS, Linux, Windows)

pub mod core;
pub mod daemon;
pub mod error;
pub mod focus;
pub mod helpers;
pub mod ipc_handler;
pub mod shadow;
pub mod types;

#[cfg(target_os = "macos")]
pub mod macos_focus;

#[cfg(not(target_os = "macos"))]
pub mod stub_focus;

#[cfg(target_os = "windows")]
pub mod windows_focus;

#[cfg(test)]
mod tests;

// Re-export everything that was previously public from the monolithic sentinel.rs
pub use self::core::Sentinel;
pub use self::daemon::{
    cmd_start, cmd_start_foreground, cmd_status, cmd_stop, cmd_track, cmd_untrack, DaemonManager,
    DaemonState, DaemonStatus,
};
pub use self::error::{Result, SentinelError};
pub use self::focus::{FocusMonitor, PollingFocusMonitor, WindowProvider};
pub use self::helpers::{
    check_idle_sessions_sync, compute_file_hash, create_document_hash_payload,
    create_session_start_payload, end_all_sessions_sync, end_session_sync, focus_document_sync,
    handle_change_event_sync, handle_focus_event_sync, unfocus_document_sync,
};
pub use self::ipc_handler::SentinelIpcHandler;
pub use self::shadow::ShadowManager;
pub use self::types::{
    generate_session_id, hash_string, infer_document_path_from_title, normalize_document_path,
    parse_url_parts, ChangeEvent, ChangeEventType, DocumentSession, FocusEvent, FocusEventType,
    SessionBinding, SessionEvent, SessionEventType, WindowInfo,
};
