// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! `cpop verify` — Forensic validation of evidence packets and databases.
//!
//! Provides structural, cryptographic, and behavioral validation of 
//! WritersProof evidence to determine the likelihood of human authorship.

#![allow(clippy::ptr_arg)]

use anyhow::{anyhow, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use cpop_engine::cpop_protocol::forensics::ForensicVerdict;
use cpop_engine::cpop_protocol::rfc::{CBOR_TAG_ATTESTATION_RESULT, CBOR_TAG_EVIDENCE_PACKET};
use cpop_engine::evidence;
use cpop_engine::verify::{self, FullVerificationResult, VerifyOptions};
use cpop_engine::war;
use crate::output::OutputMode;
use crate::spec::{EAT_PROFILE_URI, MIN_CHECKPOINTS_PER_PACKET, PROFILE_URI};
use cpop_engine::{derive_hmac_key, SecureStore};
use zeroize::Zeroizing;

use crate::util::{ensure_dirs, load_vdf_params, writersproof_dir};

pub(crate) fn cmd_verify(
    file_path: &PathBuf,
    key: Option<PathBuf>,
    output_war: Option<PathBuf>,
    out: &OutputMode,
) -> Result<()> {
    let ext = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");

    match ext.to_lowercase().as_str() {
        "json" => verify_json(file_path, output_war, out),
        "cpop" | "cbor" => verify_cpop(file_path, out),
        "cwar" | "war" => verify_cwar(file_path, out),
        "db" | "sqlite" => verify_db(file_path, key, out),
        _ => Err(anyhow!(
            "Unsupported format: .{} (Expected .json, .cpop, .cwar, or .db)",
            ext
        )),
    }
}

fn verify_json(file_path: &Path, output_war: Option<PathBuf>, out: &OutputMode) -> Result<()> {
    let data = fs::read(file_path).context("Failed to read evidence file")?;
    let raw_json: serde_json::Value = serde_json::from_slice(&data).context("Malformed JSON")?;
    let spec_warnings = check_spec_compliance(&raw_json);
    let packet: evidence::Packet = serde_json::from_slice(&data)?;
    let config = ensure_dirs()?;
    let opts = VerifyOptions {
        vdf_params: load_vdf_params(&config),
        expected_nonce: None,
        run_forensics: true,
    };

    let result = verify::full_verify(&packet, &opts);

    if let Some(war_path) = output_war {
        write_war_appraisal(&packet, &war_path)?;
    }

    let is_valid = result.structural && result.signature != Some(false);

    if out.json {
        render_json_report(file_path, &packet, &raw_json, &result, &spec_warnings);
    } else if !out.quiet {
        render_human_report(file_path, &packet, &raw_json, &result, &spec_warnings);
    }

    if !is_valid {
        return Err(anyhow!("Forensic verification failed: packet is invalid or tampered."));
    }

    Ok(())
}

fn check_spec_compliance(raw_json: &serde_json::Value) -> Vec<String> {
    let mut warnings = Vec::new();

    if let Some(spec) = raw_json.get("spec") {
        if let Some(tag) = spec.get("cbor_tag").and_then(|v| v.as_u64()) {
            if tag != CBOR_TAG_EVIDENCE_PACKET {
                warnings.push(format!("CBOR tag mismatch (Found {}, expected {})", tag, CBOR_TAG_EVIDENCE_PACKET));
            }
        }
        if let Some(uri) = spec.get("profile_uri").and_then(|v| v.as_str()) {
            if uri != PROFILE_URI && uri != EAT_PROFILE_URI {
                warnings.push(format!("Non-standard profile URI: {}", uri));
            }
        }
    }

    if let Some(cps) = raw_json.get("checkpoints").and_then(|v| v.as_array()) {
        if cps.len() < MIN_CHECKPOINTS_PER_PACKET {
            warnings.push(format!("Sparse evidence: only {} checkpoints present", cps.len()));
        }
    }

    warnings
}

fn render_human_report(
    path: &Path,
    packet: &evidence::Packet,
    raw_json: &serde_json::Value,
    result: &FullVerificationResult,
    spec_warnings: &[String],
) {
    let valid = result.structural && result.signature != Some(false);
    let status = if valid { "✅ VERIFIED" } else { "❌ INVALID" };

    println!("\n{} Evidence Packet: {}", status, path.display());
    println!("  Document:  {}", packet.document.title);
    println!("  History:   {} checkpoints", packet.checkpoints.len());
    println!("  Temporal:  {:?} proven composition time", packet.total_elapsed_time());
    println!("  Verdict:   {}\n", verdict_label(&result.verdict));
    println!("Integrity Checks:");
    println!("  {} Structural (Hash Chain & VDF)", icon(result.structural));
    println!("  {} Digital Signature", icon(result.signature.unwrap_or(false)));
    println!("  {} Presence Seals (Jitter/Entanglement)", icon(result.seals.jitter_tag_valid.unwrap_or(false)));
    println!("  {} Chronological Plausibility ({:.2}x)", icon(result.duration.plausible), result.duration.ratio);

    if let Some(ref f) = result.forensics {
        println!("\nBehavioral Analysis:");
        println!("  Forensic Score:  {:.2}", f.assessment_score);
        println!("  Anomaly Count:   {}", f.anomaly_count);
        println!("  Cadence Consistency: {}", if f.cadence.is_robotic { "ROBOTIC" } else { "NATURAL" });
    }

    if !spec_warnings.is_empty() {
        println!("\nWarnings:");
        for w in spec_warnings { println!("  [!] {}", w); }
    }
}

fn render_json_report(
    path: &Path,
    packet: &evidence::Packet,
    _raw: &serde_json::Value,
    result: &FullVerificationResult,
    spec_warnings: &[String],
) {
    let mut report = serde_json::json!({
        "valid": result.structural && result.signature != Some(false),
        "file": path.to_string_lossy(),
        "verdict": verdict_label(&result.verdict),
        "metrics": {
            "checkpoints": packet.checkpoints.len(),
            "proven_time_ms": packet.total_elapsed_time().as_millis(),
            "structural_ok": result.structural,
        },
        "warnings": spec_warnings
    });

    if let Some(ref f) = result.forensics {
        report["forensics"] = serde_json::json!({
            "score": f.assessment_score,
            "robotic_signal": f.cadence.is_robotic,
            "anomaly_count": f.anomaly_count
        });
    }

    println!("{}", report);
}

fn verify_cpop(file_path: &Path, out: &OutputMode) -> Result<()> {
    let data = fs::read(file_path).context("Read failed")?;
    use cpop_engine::cpop_protocol::rfc::wire_types::packet::EvidencePacketWire;
    let packet = EvidencePacketWire::decode_cbor(&data)
        .map_err(|e| anyhow!("CBOR decode failed: {e}"))?;
    
    let validation = packet.validate();
    
    if out.json {
        println!("{}", serde_json::json!({
            "valid": validation.is_ok(),
            "format": "cpop",
            "checkpoints": packet.checkpoints.len(),
            "error": validation.err().map(|e| e.to_string())
        }));
    } else {
        match validation {
            Ok(_) => println!("[OK] Binary CPOP packet verified."),
            Err(e) => println!("[FAIL] CPOP validation error: {}", e),
        }
    }
    Ok(())
}

fn verify_cwar(file_path: &Path, out: &OutputMode) -> Result<()> {
    let data = fs::read_to_string(file_path).context("Read failed")?;
    let war_block = war::Block::decode_ascii(&data)
        .map_err(|e| anyhow!("WAR parse error: {e}"))?;
    
    let report = war_block.verify();

    if out.json {
        println!("{}", serde_json::to_string(&report)?);
    } else {
        println!("{} WAR block verification.", if report.valid { "[OK]" } else { "[FAIL]" });
        for check in &report.checks {
            println!("  {} {}: {}", icon(check.passed), check.name, check.message);
        }
    }
    Ok(())
}

fn verify_db(path: &Path, key: Option<PathBuf>, out: &OutputMode) -> Result<()> {
    let key_path = key.unwrap_or_else(|| writersproof_dir().unwrap().join("signing_key"));
    let key_data = Zeroizing::new(fs::read(&key_path)?);
    let hmac_key = derive_hmac_key(&key_data[..32]);

    match SecureStore::open(path, hmac_key) {
        Ok(_) => {
            if !out.quiet { println!("[OK] Database integrity verified."); }
            Ok(())
        }
        Err(e) => {
            if !out.quiet { println!("[FAIL] Database tampered or key incorrect: {}", e); }
            Err(anyhow!("DB Integrity Violation"))
        }
    }
}

fn icon(ok: bool) -> &'static str {
    if ok { "✅" } else { "❌" }
}

fn verdict_label(v: &ForensicVerdict) -> &'static str {
    match v {
        ForensicVerdict::V1VerifiedHuman => "Verified Human (High Confidence)",
        ForensicVerdict::V2LikelyHuman => "Likely Human",
        ForensicVerdict::V3Suspicious => "Suspicious Patterns Detected",
        ForensicVerdict::V4LikelySynthetic => "Likely Synthetic / AI Generated",
        ForensicVerdict::V5ConfirmedForgery => "Confirmed Forgery / Tampered",
    }
}

fn write_war_appraisal(packet: &evidence::Packet, path: &Path) -> Result<()> {
    let policy = cpop_engine::AppraisalPolicy::new("urn:cpop:policy:verify", "1.0");
    let ear = war::appraise(packet, &policy).map_err(|e| anyhow!("Appraisal failed: {e}"))?;
    fs::write(path, serde_json::to_string_pretty(&ear)?)?;
    Ok(())
}