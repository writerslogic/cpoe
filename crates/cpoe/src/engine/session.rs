// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Engine session management: pause, resume, status, report, config update.

use super::{Engine, EngineStatus, ReportFile};
use crate::MutexRecover;
use anyhow::Result;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;

#[cfg(target_os = "macos")]
use crate::platform;

impl Engine {
    /// Stop the engine (alias for `pause`).
    pub fn stop(&self) -> Result<()> {
        self.pause()
    }

    /// Pause monitoring: stop file watcher and keystroke capture.
    pub fn pause(&self) -> Result<()> {
        self.inner.running.store(false, Ordering::SeqCst);
        // Drop the watcher first so the channel closes and the thread unblocks.
        *self.inner.watcher.lock_recover() = None;
        if let Some(handle) = self.inner.watcher_thread.lock_recover().take() {
            if let Err(e) = handle.join() {
                log::warn!("watcher thread panicked: {e:?}");
            }
        }
        #[cfg(target_os = "macos")]
        {
            *self.inner.keystroke_monitor.lock_recover() = None;
        }

        let mut status = self.inner.status.lock_recover();
        status.running = false;
        Ok(())
    }

    /// Resume monitoring after a pause, restarting watchers and capture.
    pub fn resume(&self) -> Result<()> {
        // Atomic swap prevents two concurrent resume() calls from both proceeding.
        if self.inner.running.swap(true, Ordering::SeqCst) {
            return Ok(()); // Was already running
        }

        // Keystroke monitor is best-effort; failure should not prevent file watching.
        #[cfg(target_os = "macos")]
        if std::env::var("CPOE_SKIP_PERMISSIONS").is_err() {
            match platform::macos::KeystrokeMonitor::start(Arc::clone(&self.inner.jitter_session)) {
                Ok(monitor) => *self.inner.keystroke_monitor.lock_recover() = Some(monitor),
                Err(e) => log::warn!("keystroke monitor unavailable: {e}; continuing with file watching only"),
            }
        }

        let dirs = self.inner.watch_dirs.lock_recover().clone();
        if let Err(e) = super::start_file_watcher(&self.inner, dirs) {
            // File watcher failed — roll back running state so caller knows resume failed.
            self.inner.running.store(false, Ordering::SeqCst);
            return Err(e);
        }

        self.inner.status.lock_recover().running = true;
        Ok(())
    }

    /// Return a snapshot of the engine's current status.
    pub fn status(&self) -> EngineStatus {
        let mut status = self.inner.status.lock_recover().clone();
        status.jitter_samples = self.inner.jitter_session.lock_recover().samples.len() as u64;
        status
    }

    /// List all monitored files with their event counts and timestamps.
    pub fn report_files(&self) -> Result<Vec<ReportFile>> {
        let rows = self.inner.store.lock_recover().list_files()?;
        Ok(rows
            .into_iter()
            .map(|(file_path, last_ts, count)| ReportFile {
                file_path,
                last_event_timestamp_ns: last_ts,
                event_count: count.max(0) as u64,
            })
            .collect())
    }

    /// Return the engine's data directory path.
    pub fn data_dir(&self) -> PathBuf {
        self.inner.data_dir.clone()
    }

    /// Apply a new configuration, restarting watchers if currently running.
    pub fn update_config(&self, mut config: crate::config::CpopConfig) -> Result<()> {
        config.data_dir = self.inner.data_dir.clone();
        config.persist()?;

        *self.inner.watch_dirs.lock_recover() = config.watch_dirs.clone();
        let mut status = self.inner.status.lock_recover();
        status.watch_dirs = config.watch_dirs.clone();
        drop(status);

        if self.inner.running.load(Ordering::SeqCst) {
            self.pause()?;
            self.resume()?;
        }
        Ok(())
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.inner.running.store(false, Ordering::SeqCst);
        // Use try_lock to avoid deadlock if another thread holds these locks.
        // If we can't acquire, the Arc refcount drop will clean up anyway.
        if let Ok(mut watcher) = self.inner.watcher.try_lock() {
            *watcher = None; // closes the channel, unblocking the thread
        }
        if let Ok(mut handle) = self.inner.watcher_thread.try_lock() {
            if let Some(h) = handle.take() {
                if let Err(e) = h.join() {
                    log::warn!("watcher thread panicked during drop: {e:?}");
                }
            }
        }
    }
}
