// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! `cpop commit` — The forensic commitment engine.
//!
//! This module handles the ingestion of text documents, the computation of
//! Verifiable Delay Functions (VDFs) for temporal binding, and the
//! persistence of secure events into the local forensic chain.

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use thiserror::Error;

use cpop_engine::{vdf, SecureEvent, SecureStore};
use crate::output::OutputMode;
use crate::util::{
    self, ensure_dirs, BLOCKED_EXTENSIONS, LARGE_FILE_WARNING_THRESHOLD, MAX_FILE_SIZE,
};

#[derive(Debug, Error)]
pub enum CommitError {
    #[error("File not found at path: {0}")]
    NotFound(PathBuf),
    #[error("File type '.{0}' is not supported for forensic attestation")]
    UnsupportedFileType(String),
    #[error("File size ({0} bytes) exceeds the forensic maximum")]
    FileTooLarge(u64),
    #[error("Database integrity error: {0}")]
    PersistenceFailure(String),
    #[error("VDF Proof of Work failed: {0}")]
    VdfError(#[from] vdf::VdfError),
}

pub struct ForensicService<'a, S: SecureStore> {
    db: S,
    vdf_params: vdf::Parameters,
    out: &'a OutputMode,
}

impl<'a, S: SecureStore> ForensicService<'a, S> {
    pub fn new(db: S, vdf_params: vdf::Parameters, out: &'a OutputMode) -> Self {
        Self { db, vdf_params, out }
    }

    pub fn execute(&mut self, file_path: &Path, message: Option<String>) -> Result<SecureEvent> {
        let (content, abs_path_str) = self.validate_target(file_path)?;
        let content_hash: [u8; 32] = Sha256::digest(&content).into();
        let file_size = content.len() as i64;

        if !self.out.quiet && content.is_empty() {
            eprintln!("Warning: Recording an empty snapshot.");
        }

        let last_event = self.db.get_latest_event_for_file(&abs_path_str)?;
        let (vdf_input, size_delta, previous_hash) = match last_event {
            Some(ref last) => {
                let delta = (file_size - last.file_size).clamp(i32::MIN as i64, i32::MAX as i64);
                (last.event_hash, delta as i32, last.event_hash)
            }
            None => (content_hash, file_size.clamp(i32::MIN as i64, i32::MAX as i64) as i32, [0u8; 32]),
        };

        if !self.out.quiet && !self.out.json {
            print!("Computing temporal proof (VDF)...");
            io::stdout().flush()?;
        }

        let start = Instant::now();
        let vdf_proof = vdf::compute(vdf_input, Duration::from_secs(1), self.vdf_params)
            .map_err(CommitError::VdfError)?;
        let elapsed = start.elapsed();

        let mut event = SecureEvent {
            id: None,
            device_id: util::get_device_id()?,
            machine_id: util::get_machine_id(),
            timestamp_ns: Utc::now().timestamp_nanos_opt().unwrap_or_else(|| 0),
            file_path: abs_path_str.clone(),
            content_hash,
            file_size,
            size_delta,
            previous_hash,
            event_hash: [0u8; 32], // Populated by DB logic
            context_type: Some("manual".to_string()),
            context_note: message.clone(),
            vdf_input: Some(vdf_input),
            vdf_output: Some(vdf_proof.output),
            vdf_iterations: vdf_proof.iterations,
            forensic_score: 1.0, // Future: Input from MinnesotaNLP models
            is_paste: false,
            hardware_counter: None,
            input_method: None,
        };

        self.db.add_secure_event(&mut event)
            .map_err(|e| CommitError::PersistenceFailure(e.to_string()))?;

        let count = self.db.get_event_count_for_file(&abs_path_str)?;
        self.render_result(&event, count, elapsed, &vdf_proof);

        Ok(event)
    }

    fn validate_target(&self, path: &Path) -> Result<(Vec<u8>, String), CommitError> {
        if !path.exists() {
            return Err(CommitError::NotFound(path.to_path_buf()));
        }

        let abs_path = fs::canonicalize(path).map_err(|e| CommitError::PersistenceFailure(e.to_string()))?;
        let abs_path_str = abs_path.to_string_lossy().to_string();

        if let Some(ext) = abs_path.extension().and_then(|e| e.to_str()) {
            if BLOCKED_EXTENSIONS.contains(&ext.to_lowercase().as_str()) {
                return Err(CommitError::UnsupportedFileType(ext.to_string()));
            }
        }

        let content = fs::read(&abs_path).map_err(|e| CommitError::Io(e))?;
        
        if content.len() as u64 > MAX_FILE_SIZE {
            return Err(CommitError::FileTooLarge(content.len() as u64));
        }

        if !self.out.quiet && content.len() as u64 > LARGE_FILE_WARNING_THRESHOLD {
            eprintln!("Notice: Processing large document. This will occupy more forensic bandwidth.");
        }

        Ok((content, abs_path_str))
    }

    fn render_result(&self, event: &SecureEvent, count: usize, elapsed: Duration, vdf: &vdf::VdfProof) {
        if self.out.json {
            println!("{}", serde_json::json!({
                "checkpoint": count,
                "content_hash": hex::encode(event.content_hash),
                "event_hash": hex::encode(event.event_hash),
                "vdf_iterations": vdf.iterations,
                "elapsed_ms": elapsed.as_millis(),
            }));
        } else if !self.out.quiet {
            println!(" done ({:.2?})", elapsed);
            println!("\nCheckpoint #{} Created", count);
            println!("  Content Hash: {}...", hex::encode(&event.content_hash[..8]));
            println!("  Event Hash:   {}...", hex::encode(&event.event_hash[..8]));
            println!("  VDF Iterations: {}", vdf.iterations);
            if let Some(msg) = &event.context_note {
                println!("  Note:         {}", msg);
            }
        }
    }
}

pub(crate) async fn cmd_commit_smart(
    file: Option<PathBuf>,
    message: Option<String>,
    anchor: bool,
    out: &OutputMode,
) -> Result<()> {
    let config_dir = util::writersproof_dir()?;
    if !crate::smart_defaults::is_initialized(&config_dir) {
        return Err(anyhow!("CPOP not initialized. Run 'cpop init' to begin."));
    }

    let file_path = match file {
        Some(p) if p.to_string_lossy() == "." || p.to_string_lossy() == "./" => select_active_file()?,
        Some(p) => p,
        None => select_active_file()?,
    };

    let msg = message.or_else(|| Some(crate::smart_defaults::default_commit_message()));
    let mut service = ForensicService::new(
        util::open_secure_store()?,
        util::load_vdf_params(&ensure_dirs()?),
        out
    );

    service.execute(&file_path, msg)?;

    if anchor {
        anchor_to_transparency_log(&file_path).await?;
    }

    Ok(())
}

async fn anchor_to_transparency_log(file_path: &Path) -> Result<()> {
    use cpop_engine::writersproof::{AnchorMetadata, AnchorRequest, WritersProofClient};

    let abs_path = fs::canonicalize(file_path)?;
    let abs_path_str = abs_path.to_string_lossy().to_string();
    let db = util::open_secure_store()?;
    let latest = db.get_latest_event_for_file(&abs_path_str)?
        .ok_or_else(|| anyhow!("Nothing to anchor: No events found for this file."))?;

    let config = ensure_dirs()?;
    let signing_key = util::load_signing_key(&config.data_dir)?;
    let signature = {
        use ed25519_dalek::Signer;
        hex::encode(signing_key.sign(&latest.event_hash).to_bytes())
    };

    let client = WritersProofClient::new("https://api.writerslogic.com");
    
    if !util::is_quiet() { print!("Anchoring to Writerslogic Transparency Log..."); io::stdout().flush()?; }

    let resp = client.anchor(AnchorRequest {
        evidence_hash: hex::encode(latest.event_hash),
        author_did: util::load_did(&config.data_dir).unwrap_or_else(|_| "did:cpop:anon".into()),
        signature,
        metadata: Some(AnchorMetadata {
            document_name: abs_path.file_name().map(|n| n.to_string_lossy().into_owned()),
            tier: Some("anchored".into()),
        }),
    }).await.context("Anchor request failed")?;

    println!(" done.\n  Verification URL: https://verify.writerslogic.com/{}", resp.anchor_id);

    Ok(())
}

fn select_active_file() -> Result<PathBuf> {
    let db = util::open_secure_store()?;
    let tracked = db.list_files()?;
    let cwd = std::env::current_dir()?;
    let cwd_str = cwd.to_string_lossy();

    let matches: Vec<PathBuf> = tracked.iter()
        .filter(|(p, _, _)| p.starts_with(cwd_str.as_ref()))
        .map(|(p, _, _)| PathBuf::from(p))
        .collect();

    if matches.len() == 1 {
        Ok(matches[0].clone())
    } else {
        let recent = crate::smart_defaults::get_recently_modified_files(&cwd, 10);
        crate::smart_defaults::select_file_from_list(&recent, "Select a file to record:")
            .and_then(|opt| opt.ok_or_else(|| anyhow!("No selection made.")))
    }
}