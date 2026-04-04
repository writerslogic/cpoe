// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! `cpop presence` — Proof-of-Presence challenge/response logic.
//!
//! Manages ephemeral sessions that verify a human user is physically 
//! present and responsive during the forensic recording period.

use anyhow::{anyhow, Context, Result};
use fs2::FileExt;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::cli::PresenceAction;
use crate::output::OutputMode;
use crate::util::ensure_dirs;
use cpop_engine::presence::{
    ChallengeStatus, Config as PresenceConfig, Session as PresenceSession, Verifier,
};

const LOCK_TIMEOUT: Duration = Duration::from_secs(10);
const LOCK_POLL: Duration = Duration::from_millis(100);

struct PresenceGuard {
    file: fs::File,
    path: PathBuf,
    pub session: PresenceSession,
}

impl PresenceGuard {
    fn lock_and_load(path: PathBuf) -> Result<Self> {
        let lock_path = path.with_extension("lock");
        let lock_file = fs::OpenOptions::new()
            .create(true).read(true).write(true).open(&lock_path)?;

        let start = Instant::now();
        while lock_file.try_lock_exclusive().is_err() {
            if start.elapsed() > LOCK_TIMEOUT {
                return Err(anyhow!("Session is locked by another process (Sentinel or CLI)."));
            }
            std::thread::sleep(LOCK_POLL);
        }

        let data = fs::read(&path)
            .map_err(|_| anyhow!("No active session found. Run 'cpop presence start'."))?;
        
        let session = PresenceSession::decode(&data)
            .map_err(|e| anyhow!("Corrupt session data: {e}"))?;

        Ok(Self { file: lock_file, path, session })
    }

    fn commit(&self) -> Result<()> {
        let data = self.session.encode()
            .map_err(|e| anyhow!("Serialization error: {e}"))?;
        
        let tmp = self.path.with_extension("tmp");
        fs::write(&tmp, &data)?;
        fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

pub(crate) fn cmd_presence(action: PresenceAction, out: &OutputMode) -> Result<()> {
    let config = ensure_dirs()?;
    let session_dir = config.data_dir.join("sessions");
    let current_path = session_dir.join("current.json");
    
    if !session_dir.exists() { fs::create_dir_all(&session_dir)?; }

    match action {
        PresenceAction::Start => start_session(current_path, out),
        PresenceAction::Stop => stop_session(current_path, session_dir, out),
        PresenceAction::Status => show_status(current_path, out),
        PresenceAction::Challenge => handle_challenge(current_path, out),
    }
}

fn start_session(path: PathBuf, out: &OutputMode) -> Result<()> {
    if path.exists() {
        return Err(anyhow!("A presence session is already running. Stop it first."));
    }

    let mut verifier = Verifier::new(PresenceConfig::default());
    let session = verifier.start_session()
        .map_err(|e| anyhow!("Engine failed to start session: {e}"))?;

    let data = session.encode().map_err(|e| anyhow!("{e}"))?;
    fs::write(&path, &data)?;

    if out.json {
        println!("{}", serde_json::json!({"status": "started", "id": session.id}));
    } else if !out.quiet {
        println!("✅ Presence verification session started (ID: {})", &session.id[..8]);
    }
    Ok(())
}

fn stop_session(path: PathBuf, archive_dir: PathBuf, out: &OutputMode) -> Result<()> {
    let mut guard = PresenceGuard::lock_and_load(path.clone())?;
    
    guard.session.active = false;
    guard.session.end_time = Some(chrono::Utc::now());
    update_session_metrics(&mut guard.session);

    let archive_path = archive_dir.join(format!("{}.json", guard.session.id));
    guard.commit()?; // Save current state first
    fs::copy(&path, &archive_path)?;
    fs::remove_file(&path)?;

    if out.json {
        println!("{}", serde_json::json!({
            "status": "stopped",
            "passed": guard.session.challenges_passed,
            "rate": guard.session.verification_rate
        }));
    } else if !out.quiet {
        println!("🛑 Session ended. Passed {} challenges ({:.0}%).", 
            guard.session.challenges_passed, guard.session.verification_rate * 100.0);
    }
    Ok(())
}

fn handle_challenge(path: PathBuf, out: &OutputMode) -> Result<()> {
    let (challenge, mut session) = {
        let guard = PresenceGuard::lock_and_load(path.clone())?;
        let mut verifier = Verifier::new(PresenceConfig::default());
        verifier.restore_session(guard.session.clone())?;
        
        let challenge = verifier.issue_challenge()?;
        (challenge, verifier.active_session().unwrap().clone())
    }; // Guard drops here, unlocking for Stdin

    if !out.quiet && !out.json {
        println!("\n=== 🧩 Presence Challenge ===\n");
        println!("{}\n", challenge.prompt);
        print!("Your response (Window: {:?}): ", challenge.window);
        io::stdout().flush()?;
    }

    let mut response = String::new();
    io::stdin().lock().read_line(&mut response)?;
    let response = response.trim();
    let mut guard = PresenceGuard::lock_and_load(path)?;
    let mut verifier = Verifier::new(PresenceConfig::default());
    verifier.restore_session(session)?;

    let passed = verifier.respond_to_challenge(&challenge.id, response)?;
    
    guard.session = verifier.active_session().unwrap().clone();
    guard.commit()?;

    if out.json {
        println!("{}", serde_json::json!({"id": challenge.id, "passed": passed}));
    } else {
        let msg = if passed { "✅ Challenge PASSED" } else { "❌ Challenge FAILED" };
        println!("{}", msg);
    }

    Ok(())
}

fn update_session_metrics(s: &mut PresenceSession) {
    let total = s.challenges.len();
    s.challenges_issued = total as i32;
    s.challenges_passed = s.challenges.iter().filter(|c| matches!(c.status, ChallengeStatus::Passed)).count() as i32;
    if total > 0 {
        s.verification_rate = s.challenges_passed as f64 / total as f64;
    }
}

fn show_status(path: PathBuf, out: &OutputMode) -> Result<()> {
    if !path.exists() {
        if out.json { println!(r#"{"active":false}"#); } else { println!("No active session."); }
        return Ok(());
    }

    let data = fs::read(path)?;
    let session = PresenceSession::decode(&data)?;
    let duration = chrono::Utc::now().signed_duration_since(session.start_time);

    if out.json {
        println!("{}", serde_json::json!({"active": true, "id": session.id, "duration": duration.num_seconds()}));
    } else {
        println!("Active Session: {}\nStarted: {} ago\nChallenges: {}", 
            &session.id[..8], format_duration(duration), session.challenges.len());
    }
    Ok(())
}

fn format_duration(d: chrono::Duration) -> String {
    if d.num_minutes() > 60 { format!("{}h {}m", d.num_hours(), d.num_minutes() % 60) }
    else { format!("{}m {}s", d.num_minutes(), d.num_seconds() % 60) }
}