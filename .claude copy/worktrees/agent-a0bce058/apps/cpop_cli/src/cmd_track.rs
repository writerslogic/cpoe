// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! `cpop track` — Background monitoring and behavioral evidence collection.

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use glob::Pattern;
use notify::{Config as NotifyConfig, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;

use cpop_engine::jitter::{default_parameters as jitter_params, Session as JitterSession};
use cpop_engine::{vdf, SecureEvent, SecureStore};
use crate::cli::TrackAction;
use crate::output::OutputMode;
use crate::util::{self, BLOCKED_EXTENSIONS, MAX_FILE_SIZE};

const DEBOUNCE: Duration = Duration::from_secs(5);
const SAVE_INTERVAL: Duration = Duration::from_secs(5);

enum TrackTarget {
    File(PathBuf),
    Directory(PathBuf),
    Scrivener(PathBuf),
    TextBundle(PathBuf),
}

impl TrackTarget {
    fn root(&self) -> &Path {
        match self {
            Self::File(p) | Self::Directory(p) | Self::Scrivener(p) | Self::TextBundle(p) => p,
        }
    }

    fn mode_label(&self) -> &'static str {
        match self {
            Self::File(_) => "file",
            Self::Directory(_) => "directory",
            Self::Scrivener(_) => "scrivener",
            Self::TextBundle(_) => "textbundle",
        }
    }
}

struct TrackingEngine {
    db: Box<dyn crate::util::SecureStoreInterface>,
    vdf_params: vdf::Parameters,
    session: Arc<Mutex<JitterSession>>,
    device_id: [u8; 16],
    machine_id: String,
    checkpoint_counts: HashMap<PathBuf, u32>,
    last_checkpoint: HashMap<PathBuf, Instant>,
}

impl TrackingEngine {
    fn new(target_root: &Path, db: Box<dyn crate::util::SecureStoreInterface>) -> Result<Self> {
        let config = util::ensure_dirs()?;
        let vdf_params = util::load_vdf_params(&config);
        let session = JitterSession::new(target_root, jitter_params())
            .map_err(|e| anyhow!("Session init failed: {e}"))?;

        Ok(Self {
            db,
            vdf_params,
            session: Arc::new(Mutex::new(session)),
            device_id: util::get_device_id()?,
            machine_id: util::get_machine_id(),
            checkpoint_counts: HashMap::new(),
            last_checkpoint: HashMap::new(),
        })
    }

    fn handle_fs_event(&mut self, path: &Path) -> Result<()> {
        let canonical = fs::canonicalize(path)?;
        
        if let Some(last) = self.last_checkpoint.get(&canonical) {
            if last.elapsed() < DEBOUNCE { return Ok(()); }
        }

        if self.perform_checkpoint(&canonical)? {
            let count = self.checkpoint_counts.entry(canonical.clone()).or_insert(0);
            *count += 1;
            self.last_checkpoint.insert(canonical, Instant::now());
            
            self.log_checkpoint_created(&path, *count);
        }

        Ok(())
    }

    fn perform_checkpoint(&mut self, path: &Path) -> Result<bool> {
        let content = fs::read(path)?;
        if content.is_empty() || content.len() as u64 > MAX_FILE_SIZE {
            return Ok(false);
        }

        let content_hash: [u8; 32] = Sha256::digest(&content).into();
        let path_str = path.to_string_lossy().to_string();
        let events = self.db.get_events_for_file(&path_str)?;

        // Skip if hash hasn't changed
        if let Some(last) = events.last() {
            if bool::from(last.content_hash.ct_eq(&content_hash)) {
                return Ok(false);
            }
        }

        let vdf_input = events.last().map(|e| e.event_hash).unwrap_or(content_hash);
        let vdf_proof = vdf::compute(vdf_input, Duration::from_millis(500), self.vdf_params)?;
        let mut event = SecureEvent {
            id: None,
            device_id: self.device_id,
            machine_id: self.machine_id.clone(),
            timestamp_ns: Utc::now().timestamp_nanos_opt().unwrap_or(0),
            file_path: path_str,
            content_hash,
            file_size: content.len() as i64,
            size_delta: self.calculate_delta(content.len(), events.last()),
            previous_hash: vdf_input,
            event_hash: [0u8; 32],
            context_type: Some("auto".into()),
            vdf_input: Some(vdf_input),
            vdf_output: Some(vdf_proof.output),
            vdf_iterations: vdf_proof.iterations,
            forensic_score: 1.0,
            ..Default::default()
        };

        self.db.add_secure_event(&mut event)?;
        Ok(true)
    }

    fn calculate_delta(&self, new_size: usize, last: Option<&SecureEvent>) -> i32 {
        match last {
            Some(e) => (new_size as i64 - e.file_size).clamp(i32::MIN as i64, i32::MAX as i64) as i32,
            None => (new_size as i64).clamp(0, i32::MAX as i64) as i32,
        }
    }

    fn log_checkpoint_created(&self, path: &Path, count: u32) {
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        let ks = self.session.lock().map(|s| s.keystroke_count()).unwrap_or(0);
        println!("[{}] 🛡️ Checkpoint #{} | {} | {} keystrokes", 
            Utc::now().format("%H:%M:%S"), count, name, ks);
    }
}

pub(crate) async fn cmd_track_start(path: &Path, out: &OutputMode) -> Result<()> {
    let target = classify_target(path)?;
    let mut engine = TrackingEngine::new(target.root(), Box::new(util::open_secure_store()?))?;
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        println!("\n🛑 Stopping tracking session. Finalizing evidence...");
        r.store(false, Ordering::SeqCst);
    }).context("Error setting Ctrl-C handler")?;

    let (_capture, _thread) = setup_keystroke_capture(&engine.session);
    let (tx, rx) = mpsc::channel();
    let mut watcher = RecommendedWatcher::new(
        move |res| { if let Ok(e) = res { let _ = tx.send(e); } },
        NotifyConfig::default().with_poll_interval(Duration::from_secs(2)),
    )?;
    watcher.watch(target.root(), RecursiveMode::Recursive)?;

    println!("🔎 Monitoring: {}", target.root().display());
    println!("Type naturally. Checkpoints will be created automatically on save.");

    let mut last_save = Instant::now();
    while running.load(Ordering::SeqCst) {
        if let Ok(event) = rx.recv_timeout(Duration::from_millis(250)) {
            if is_relevant_event(&event) {
                for path in event.paths {
                    if should_track_file(&path) {
                        let _ = engine.handle_fs_event(&path);
                    }
                }
            }
        }

        if last_save.elapsed() >= SAVE_INTERVAL {
            if let Ok(mut s) = engine.session.lock() {
                let _ = s.save_to_disk(); // Simplified persistence
            }
            last_save = Instant::now();
        }
    }

    finalize_tracking_session(&engine, target.root())?;
    
    Ok(())
}

fn is_relevant_event(e: &Event) -> bool {
    matches!(e.kind, EventKind::Modify(_) | EventKind::Create(_))
}

fn should_track_file(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if name.starts_with('.') || name.ends_with('~') || name.ends_with(".tmp") {
        return false;
    }
    
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        if BLOCKED_EXTENSIONS.contains(&ext.to_lowercase().as_str()) {
            return false;
        }
    }
    true
}

fn classify_target(path: &Path) -> Result<TrackTarget> {
    let abs = fs::canonicalize(path)?;
    if abs.is_file() { return Ok(TrackTarget::File(abs)); }
    
    let ext = abs.extension().and_then(|e| e.to_str()).unwrap_or("");
    match ext {
        "scriv" => Ok(TrackTarget::Scrivener(abs)),
        "textbundle" => Ok(TrackTarget::TextBundle(abs)),
        _ => Ok(TrackTarget::Directory(abs)),
    }
}

fn finalize_tracking_session(engine: &TrackingEngine, root: &Path) -> Result<()> {
    let mut s = engine.session.lock().unwrap();
    s.end();
    
    println!("\n=== 📜 Session Summary ===");
    println!("Duration:    {:?}", s.duration());
    println!("Keystrokes:  {}", s.keystroke_count());
    println!("Jitter Pts:  {}", s.sample_count());
    println!("Checkpoints: {}", engine.checkpoint_counts.values().sum::<u32>());
    
    Ok(())
}