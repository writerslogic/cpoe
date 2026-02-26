// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::error::{Result, SentinelError};
use super::focus::{FocusMonitor, PollingFocusMonitor, WindowProvider};
use super::types::*;
use crate::config::SentinelConfig;
use crate::crypto::ObfuscatedString;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tokio::sync::mpsc;

/// Focus monitor for Linux and other non-macOS, non-Windows platforms.
///
/// On Linux without X11, precise window focus tracking is not available.
/// This monitor provides a degraded-but-functional experience:
/// - Reports the terminal/session as the active "window"
/// - Uses environment variables and process info for context
/// - Allows witnessing to proceed without precise focus tracking
pub struct StubFocusMonitor {
    #[allow(dead_code)]
    config: Arc<SentinelConfig>,
    focus_rx: Arc<Mutex<Option<mpsc::Receiver<FocusEvent>>>>,
    change_rx: Arc<Mutex<Option<mpsc::Receiver<ChangeEvent>>>>,
}

impl StubFocusMonitor {
    pub fn new(config: Arc<SentinelConfig>) -> Self {
        let (_focus_tx, focus_rx) = mpsc::channel(1);
        let (_change_tx, change_rx) = mpsc::channel(1);
        Self {
            config,
            focus_rx: Arc::new(Mutex::new(Some(focus_rx))),
            change_rx: Arc::new(Mutex::new(Some(change_rx))),
        }
    }

    /// Create a polling-based monitor using process/env heuristics
    pub fn new_monitor(config: Arc<SentinelConfig>) -> Box<dyn FocusMonitor> {
        let provider = Arc::new(LinuxWindowProvider);
        Box::new(PollingFocusMonitor::new(provider, config))
    }
}

/// Window provider using Linux process heuristics.
///
/// Without X11/Wayland integration, this uses environment variables
/// and /proc to provide basic session context.
struct LinuxWindowProvider;

impl LinuxWindowProvider {
    /// Try to detect the terminal emulator or parent application
    fn detect_terminal_app() -> String {
        // Check common environment variables
        if let Ok(term_program) = std::env::var("TERM_PROGRAM") {
            return term_program;
        }
        if let Ok(term) = std::env::var("TERM") {
            return term;
        }
        // Fall back to reading parent process name from /proc
        if let Ok(ppid_status) = std::fs::read_to_string("/proc/self/status") {
            for line in ppid_status.lines() {
                if let Some(ppid) = line.strip_prefix("PPid:\t") {
                    let ppid = ppid.trim();
                    let comm_path = format!("/proc/{}/comm", ppid);
                    if let Ok(comm) = std::fs::read_to_string(comm_path) {
                        return comm.trim().to_string();
                    }
                }
            }
        }
        "unknown".to_string()
    }
}

impl WindowProvider for LinuxWindowProvider {
    fn get_active_window(&self) -> Option<WindowInfo> {
        let app_name = Self::detect_terminal_app();

        // Try to get the current working directory as a basic "document" hint
        let cwd = std::env::current_dir()
            .ok()
            .map(|p| p.to_string_lossy().into_owned());

        Some(WindowInfo {
            path: None,
            application: app_name.clone(),
            title: ObfuscatedString::new(&app_name),
            pid: Some(std::process::id()),
            timestamp: SystemTime::now(),
            is_document: false,
            is_unsaved: false,
            project_root: cwd,
        })
    }
}

impl FocusMonitor for StubFocusMonitor {
    fn start(&self) -> Result<()> {
        // On Linux without X11, we use degraded mode that still allows witnessing
        log::info!("Starting degraded focus monitor (no X11/Wayland integration)");
        log::info!("Witnessing will work but without precise window focus tracking");
        Ok(())
    }

    fn stop(&self) -> Result<()> {
        Ok(())
    }

    fn active_window(&self) -> Option<WindowInfo> {
        LinuxWindowProvider.get_active_window()
    }

    fn available(&self) -> (bool, String) {
        (
            true,
            "Degraded focus monitoring (no X11/Wayland). Witnessing works without precise focus tracking.".to_string(),
        )
    }

    fn focus_events(&self) -> mpsc::Receiver<FocusEvent> {
        self.focus_rx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .unwrap_or_else(|| {
                log::error!("Focus receiver already consumed - returning dummy receiver");
                let (_tx, rx) = mpsc::channel(1);
                rx
            })
    }

    fn change_events(&self) -> mpsc::Receiver<ChangeEvent> {
        self.change_rx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .unwrap_or_else(|| {
                log::error!("Change receiver already consumed - returning dummy receiver");
                let (_tx, rx) = mpsc::channel(1);
                rx
            })
    }
}
