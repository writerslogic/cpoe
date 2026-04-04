// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! `cpop attest` — One-shot text attestation via ephemeral sessions.
//!
//! This module provides a simplified, non-persistent workflow for 
//! quickly generating a WritersProof for a single block of text.

use anyhow::{anyhow, Context, Result};
use std::borrow::Cow;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};

use cpop_engine::ffi;
use crate::output::OutputMode;

macro_rules! ffi_call {
    ($call:expr) => {{
        let res = $call;
        if !res.success {
            return Err(anyhow!(
                "Engine Error: {}",
                res.error_message.unwrap_or_else(|| "Unknown failure".into())
            ));
        }
        res
    }};
}

pub(crate) fn cmd_attest(
    format: &str,
    input: Option<PathBuf>,
    output: Option<PathBuf>,
    non_interactive: bool,
    out: &OutputMode,
) -> Result<()> {
    ffi_call!(ffi::ffi_init());

    let (content, label) = resolve_input(input, non_interactive, out.quiet)?;
    
    if content.trim().is_empty() {
        return Err(anyhow!("Forensic attestation requires non-empty content."));
    }

    let session = ffi_call!(ffi::ffi_start_ephemeral_session(label));
    let session_id = session.session_id;

    if !out.quiet {
        eprintln!("🚀 Ephemeral session established: {}", &session_id[..8]);
    }

    ffi_call!(ffi::ffi_ephemeral_checkpoint(
        session_id.clone(),
        content.clone(),
        "CLI one-shot attestation".to_string(),
    ));

    let statement = get_declaration(non_interactive)?;
    let result = ffi_call!(ffi::ffi_ephemeral_finalize(session_id, content, statement));
    let proof_body = format_proof_output(format, &result)?;
    write_output(proof_body, output, out.quiet)?;

    if !out.quiet && !is_compact_format(format) {
        eprintln!("Compact reference: {}", result.compact_ref);
    }

    Ok(())
}

fn resolve_input(path: Option<PathBuf>, non_interactive: bool, quiet: bool) -> Result<(String, String)> {
    if let Some(p) = path {
        let label = p.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file")
            .to_string();
        let content = fs_to_string_hardened(&p)?;
        Ok((content, label))
    } else {
        let mut stdin = io::stdin().lock();
        if stdin.is_terminal() && !non_interactive && !quiet {
            eprintln!("📝 Paste or type text (Ctrl-D/Cmd-D when finished):");
        }
        let mut buf = String::new();
        stdin.read_to_string(&mut buf).context("Failed to read from stdin pipe")?;
        Ok((buf, "stdin".to_string()))
    }
}

fn fs_to_string_hardened(path: &Path) -> Result<String> {
    std::fs::read_to_string(path)
        .with_context(|| format!("Could not access forensic source: {}", path.display()))
}

fn get_declaration(non_interactive: bool) -> Result<String> {
    const DEFAULT_STMT: &str = "I authored this text.";

    if non_interactive || !io::stdin().is_terminal() {
        return Ok(DEFAULT_STMT.to_string());
    }

    eprint!("Declaration statement [Enter for default]: ");
    io::stderr().flush()?;

    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    let trimmed = buf.trim();

    Ok(if trimmed.is_empty() {
        DEFAULT_STMT.to_string()
    } else {
        trimmed.to_string()
    })
}

fn format_proof_output(format: &str, result: &ffi::FfiFinalizeResult) -> Result<String> {
    match format.to_lowercase().as_str() {
        "json" => Ok(serde_json::to_string_pretty(&serde_json::json!({
            "war_block": result.war_block,
            "compact_ref": result.compact_ref,
            "version": "1.0",
            "attestation_type": "ephemeral"
        }))?),
        "compact" => Ok(result.compact_ref.clone()),
        "both" => Ok(format!("{}\n\n---\nCompact Reference:\n{}", result.war_block, result.compact_ref)),
        _ => Ok(result.war_block.clone()),
    }
}

fn write_output(proof: String, path: Option<PathBuf>, quiet: bool) -> Result<()> {
    if let Some(out_path) = path {
        std::fs::write(&out_path, &proof)
            .with_context(|| format!("Failed to write proof to {}", out_path.display()))?;
        if !quiet {
            eprintln!("✅ Proof successfully sealed to: {}", out_path.display());
        }
    } else {
        let mut stdout = io::stdout().lock();
        stdout.write_all(proof.as_bytes())?;
        if !proof.ends_with('\n') {
            stdout.write_all(b"\n")?;
        }
        stdout.flush()?;
    }
    Ok(())
}

fn is_compact_format(format: &str) -> bool {
    let f = format.to_lowercase();
    f == "compact" || f == "json"
}