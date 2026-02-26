// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::error::{Result, SentinelError};
use super::types::*;
use crate::config::SentinelConfig;
use crate::crypto::ObfuscatedString;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc;
use tokio::time::interval;

// ============================================================================
// Focus Monitor Trait
// ============================================================================

/// Platform-specific focus monitoring
pub trait FocusMonitor: Send + Sync {
    /// Start monitoring for focus changes
    fn start(&self) -> Result<()>;

    /// Stop monitoring
    fn stop(&self) -> Result<()>;

    /// Get the current window info
    fn active_window(&self) -> Option<WindowInfo>;

    /// Check if monitoring is available on this platform
    fn available(&self) -> (bool, String);

    /// Get focus events receiver
    fn focus_events(&self) -> mpsc::Receiver<FocusEvent>;

    /// Get change events receiver
    fn change_events(&self) -> mpsc::Receiver<ChangeEvent>;
}

/// Provider for active window information (platform-specific)
pub trait WindowProvider: Send + Sync + 'static {
    fn get_active_window(&self) -> Option<WindowInfo>;
}

/// Generic polling focus monitor that uses a WindowProvider
pub struct PollingFocusMonitor<P: WindowProvider + ?Sized> {
    provider: Arc<P>,
    config: Arc<SentinelConfig>,
    running: Arc<RwLock<bool>>,
    focus_tx: mpsc::Sender<FocusEvent>,
    focus_rx: Arc<Mutex<Option<mpsc::Receiver<FocusEvent>>>>,
    #[allow(dead_code)]
    change_tx: mpsc::Sender<ChangeEvent>,
    change_rx: Arc<Mutex<Option<mpsc::Receiver<ChangeEvent>>>>,
    poll_handle: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

impl<P: WindowProvider + ?Sized> PollingFocusMonitor<P> {
    pub fn new(provider: Arc<P>, config: Arc<SentinelConfig>) -> Self {
        let (focus_tx, focus_rx) = mpsc::channel(100);
        let (change_tx, change_rx) = mpsc::channel(100);

        Self {
            provider,
            config,
            running: Arc::new(RwLock::new(false)),
            focus_tx,
            focus_rx: Arc::new(Mutex::new(Some(focus_rx))),
            change_tx,
            change_rx: Arc::new(Mutex::new(Some(change_rx))),
            poll_handle: Arc::new(Mutex::new(None)),
        }
    }
}

impl<P: WindowProvider + ?Sized> FocusMonitor for PollingFocusMonitor<P> {
    fn start(&self) -> Result<()> {
        let mut running = self.running.write().unwrap();
        if *running {
            return Err(SentinelError::AlreadyRunning);
        }
        *running = true;
        drop(running);

        let running_clone = Arc::clone(&self.running);
        let focus_tx = self.focus_tx.clone();
        let config = self.config.clone();
        let provider = Arc::clone(&self.provider);
        let poll_interval = Duration::from_millis(self.config.poll_interval_ms);

        // Start polling loop
        let handle = tokio::spawn(async move {
            let mut last_app = String::new();
            let mut interval_timer = interval(poll_interval);

            loop {
                interval_timer.tick().await;

                if !*running_clone.read().unwrap() {
                    break;
                }

                if let Some(info) = provider.get_active_window() {
                    let current_app = if !info.application.is_empty() {
                        info.application.clone()
                    } else {
                        "unknown".to_string()
                    };

                    // Check if focus changed
                    if current_app != last_app {
                        // Send focus lost for previous app
                        if !last_app.is_empty() {
                            let _ = focus_tx
                                .send(FocusEvent {
                                    event_type: FocusEventType::FocusLost,
                                    path: String::new(),
                                    shadow_id: String::new(),
                                    app_bundle_id: last_app.clone(),
                                    app_name: String::new(),
                                    window_title: ObfuscatedString::default(),
                                    timestamp: SystemTime::now(),
                                })
                                .await;
                        }

                        // Check if new app should be tracked
                        let app_name = info.application.clone();
                        if config.is_app_allowed(&info.application, &app_name) {
                            let _ = focus_tx
                                .send(FocusEvent {
                                    event_type: FocusEventType::FocusGained,
                                    path: info.path.clone().unwrap_or_default(),
                                    shadow_id: String::new(),
                                    app_bundle_id: info.application.clone(),
                                    app_name: info.application.clone(),
                                    window_title: info.title.clone(),
                                    timestamp: SystemTime::now(),
                                })
                                .await;
                        }

                        last_app = current_app;
                    }
                }
            }
        });

        *self.poll_handle.lock().unwrap_or_else(|p| p.into_inner()) = Some(handle);
        Ok(())
    }

    fn stop(&self) -> Result<()> {
        let mut running = self.running.write().unwrap_or_else(|p| p.into_inner());
        if !*running {
            return Ok(());
        }
        *running = false;
        drop(running);

        if let Some(handle) = self
            .poll_handle
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
        {
            handle.abort();
        }

        Ok(())
    }

    fn active_window(&self) -> Option<WindowInfo> {
        self.provider.get_active_window()
    }

    fn available(&self) -> (bool, String) {
        (true, "Polling monitor available".to_string())
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
