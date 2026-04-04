// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! `cpop export` — Forensic evidence packaging and attestation.
//!
//! Generates cryptographically signed evidence packets (CPOP/WAR) 
//! including VDF-backed temporal proofs and hardware-attested identity.

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use std::fs;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;
use zeroize::Zeroize;

use cpop_engine::cpop_protocol::crypto::EvidenceSigner;
use cpop_engine::cpop_protocol::rfc::{CBOR_TAG_ATTESTATION_RESULT, CBOR_TAG_EVIDENCE_PACKET};
use cpop_engine::declaration::{self, AiExtent, AiPurpose, ModalityType};
use cpop_engine::{evidence, tpm, war, report, SecureEvent, vdf};

use crate::output::OutputMode;
use crate::spec::{
    attestation_tier_value, content_tier_from_cli, profile_uri_from_cli, MIN_CHECKPOINTS_PER_PACKET,
};
use crate::util::{
    self, ensure_dirs, load_signing_key, load_vdf_params, open_secure_store, 
    retry_on_busy, validate_session_id,
};

pub struct ExportPipeline<'a> {
    file_path: &'a Path,
    abs_path_str: String,
    out_mode: &'a OutputMode,
    db: Box<dyn crate::util::SecureStoreInterface>, // Assuming a trait for the DB
}

impl<'a> ExportPipeline<'a> {
    pub fn new(file_path: &'a Path, out_mode: &'a OutputMode) -> Result<Self> {
        let abs_path = fs::canonicalize(file_path)
            .with_context(|| format!("Unresolved path: {}", file_path.display()))?;
            
        Ok(Self {
            file_path,
            abs_path_str: abs_path.to_string_lossy().into_owned(),
            out_mode,
            db: Box::new(open_secure_store()?),
        })
    }

    pub async fn run(
        &self,
        tier: &str,
        output: Option<PathBuf>,
        format: &str,
        stego: bool,
    ) -> Result<()> {
        let events = retry_on_busy(|| self.db.get_events_for_file(&self.abs_path_str))?;
        self.validate_events(&events)?;
        let config = ensure_dirs()?;
        let (signer, caps, device_id) = self.resolve_security_context(&config)?;
        let latest = events.last().unwrap();
        let tier_lower = tier.to_lowercase();
        let decl = self.acquire_declaration(&tier_lower, latest, signer.as_ref())?;
        let packet_ctx = self.prepare_packet_context(
            &events, 
            &tier_lower, 
            &decl, 
            &caps, 
            &config
        )?;
        
        let packet_json = self.assemble_json_packet(&packet_ctx)?;
        let format_lower = format.to_lowercase();
        let out_path = output.unwrap_or_else(|| self.default_path(&format_lower));
        
        self.write_output(
            &format_lower, 
            &out_path, 
            &packet_json, 
            &events, 
            signer.as_ref(),
            &caps,
            &device_id
        )?;

        // 6. Optional Steganographic Binding
        if stego {
            self.embed_watermark(&events, &config.data_dir).await?;
        }

        self.report_completion(&out_path, &events, &tier_lower, &format_lower)?;

        Ok(())
    }

    fn resolve_security_context(&self, config: &util::Config) -> Result<(Box<dyn EvidenceSigner>, tpm::Capabilities, String)> {
        let tpm_provider = tpm::detect_provider();
        let caps = tpm_provider.capabilities();
        let device_id = tpm_provider.device_id();

        let signer: Box<dyn EvidenceSigner> = if caps.hardware_backed {
            if self.out_mode.is_verbose() {
                println!("🔐 Using TPM-backed identity: {}", device_id);
            }
            Box::new(tpm::TpmSigner::new(tpm_provider))
        } else {
            Box::new(load_signing_key(&config.data_dir)?)
        };

        Ok((signer, caps, device_id))
    }

    fn validate_events(&self, events: &[SecureEvent]) -> Result<()> {
        if events.len() < MIN_CHECKPOINTS_PER_PACKET {
            bail!("Forensic requirement: {} checkpoints needed (found {}).", 
                MIN_CHECKPOINTS_PER_PACKET, events.len());
        }
        Ok(())
    }
}

fn format_proof_output(format: &str, result: &ffi::FfiFinalizeResult) -> Result<String> {
    match format.to_lowercase().as_str() {
        "json" => Ok(serde_json::to_string_pretty(&serde_json::json!({
            "war_block": result.war_block,
            "compact_ref": result.compact_ref,
            "verification_url": format!("https://verify.writerslogic.com/{}", result.compact_ref)
        }))?),
        "compact" => Ok(result.compact_ref.clone()),
        _ => Ok(result.war_block.clone()),
    }
}

async fn embed_watermark(path: &Path, events: &[SecureEvent], data_dir: &Path) -> Result<()> {
    use cpop_engine::steganography::{ZwcEmbedder, ZwcParams};

    let content = fs::read_to_string(path).context("Stego requires a UTF-8 text source.")?;
    let latest = events.last().ok_or_else(|| anyhow!("No events for stego"))?;
    let signing_key = crate::util::load_signing_key(data_dir)?;
    let embedder = ZwcEmbedder::new(ZwcParams::default());
    let mut hmac_key = Sha256::new()
        .chain_update(b"writerslogic-stego-v1")
        .chain_update(signing_key.to_bytes())
        .finalize();

    let (watermarked, binding) = embedder.embed(&content, &latest.event_hash, hmac_key.as_slice())?;
    hmac_key.zeroize();

    let stego_path = path.with_extension("stego.txt");
    fs::write(&stego_path, watermarked)?;
    
    println!("🎨 Steganographic watermark embedded in: {}", stego_path.display());
    Ok(())
}

fn collect_declaration(
    doc_hash: [u8; 32],
    chain_hash: [u8; 32],
    title: String,
    signer: &dyn EvidenceSigner,
) -> Result<declaration::Declaration> {
    let mut input = String::new();
    let mut stdout = io::stdout().lock();
    let mut stdin = io::stdin().lock();

    writeln!(stdout, "\n=== Forensic Declaration ===")?;
    write!(stdout, "Did you use AI tools to assist in this document? (y/N): ")?;
    stdout.flush()?;
    
    stdin.read_line(&mut input)?;
    let used_ai = input.trim().to_lowercase().starts_with('y');
    input.clear();

    let mut decl = if used_ai {
        write!(stdout, "Which AI tool (e.g. Claude 3.5, GPT-4o)? ")?;
        stdout.flush()?;
        stdin.read_line(&mut input)?;
        let tool = input.trim().to_string();
        input.clear();

        declaration::ai_assisted_declaration(doc_hash, chain_hash, &title)
            .add_ai_tool(&tool, None, AiPurpose::Drafting, None, AiExtent::Moderate)
    } else {
        declaration::no_ai_declaration(doc_hash, chain_hash, &title, "I authored this document.")
    };

    decl.sign(signer).map_err(|e| anyhow!("Signing failed: {e}"))
}