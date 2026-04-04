// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! `cpop config` — Management of forensic and privacy settings.

use anyhow::{anyhow, bail, Context, Result};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use cpop_engine::config::CpopConfig;
use crate::cli::ConfigAction;
use crate::util::writersproof_dir;

pub(crate) fn cmd_config(action: ConfigAction) -> Result<()> {
    let dir = writersproof_dir()?;
    let config_path = dir.join("writersproof.json");

    match action {
        ConfigAction::Show => show_config(&dir, &config_path),
        ConfigAction::Set { key, value } => set_config_key(&dir, key, value),
        ConfigAction::Edit => edit_config_in_editor(&dir, &config_path),
        ConfigAction::Reset { force } => reset_config(&dir, &config_path, force),
    }
}

fn show_config(dir: &Path, path: &Path) -> Result<()> {
    let config = CpopConfig::load_or_default(dir)?;

    println!("=== CPOP Forensic Configuration ===");
    println!("Data Dir:  {}", config.data_dir.display());
    println!("Config:    {}", path.display());
    println!("\n[VDF - Temporal Proofs]");
    println!("  Iterations/Sec:  {}", config.vdf.iterations_per_second);
    println!("  Min Iterations:  {}", config.vdf.min_iterations);
    println!("\n[Sentinel - Background Guard]");
    println!("  Auto-Start:      {}", config.sentinel.auto_start);
    println!("  Heartbeat (s):   {}", config.sentinel.heartbeat_interval_secs);
    println!("\n[Privacy & Obfuscation]");
    println!("  Hash URLs:       {}", config.privacy.hash_urls);
    println!("  Mask Titles:     {}", config.privacy.obfuscate_titles);
    println!("\n[Biometric Fingerprinting]");
    println!("  Voice Enabled:   {}", config.fingerprint.voice_enabled);
    println!("  Retention (d):   {}", config.fingerprint.retention_days);
    
    Ok(())
}

fn set_config_key(dir: &Path, key: String, value: String) -> Result<()> {
    let mut config = CpopConfig::load_or_default(dir)?;
    let parts: Vec<&str> = key.split('.').collect();

    match parts.as_slice() {
        // --- Sentinel Settings ---
        ["sentinel", "auto_start"] => {
            config.sentinel.auto_start = parse_bool(&value)?;
        }
        ["sentinel", "heartbeat_interval_secs"] => {
            config.sentinel.heartbeat_interval_secs = parse_range(&value, 1..=3600)?;
        }
        ["sentinel", "idle_timeout_secs"] => {
            config.sentinel.idle_timeout_secs = parse_range(&value, 1..=86400)?;
        }

        // --- Privacy Settings ---
        ["privacy", "hash_urls"] => config.privacy.hash_urls = parse_bool(&value)?,
        ["privacy", "obfuscate_titles"] => config.privacy.obfuscate_titles = parse_bool(&value)?,

        // --- Fingerprint Settings ---
        ["fingerprint", "voice_enabled"] => {
            handle_voice_consent_change(&mut config, dir, parse_bool(&value)?)?;
        }
        ["fingerprint", "retention_days"] => {
            config.fingerprint.retention_days = parse_range(&value, 1..=3650)?;
        }

        _ => bail!("Unknown configuration key: '{}'. Try 'cpop config show'.", key),
    }

    config.persist().context("Failed to save configuration")?;
    println!("✅ Updated {} to {}", key, value);
    Ok(())
}

fn edit_config_in_editor(dir: &Path, path: &Path) -> Result<()> {
    let editor = std::env::var("EDITOR").unwrap_or_else(|_| {
        if cfg!(target_os = "windows") { "notepad".into() } else { "nano".into() }
    });

    let (cmd, args) = parse_editor_command(&editor)?;
    
    println!("Opening {} with {}...", path.display(), cmd);
    
    let status = std::process::Command::new(&cmd)
        .args(args)
        .arg(path)
        .status()
        .with_context(|| format!("Failed to launch editor: {}", cmd))?;

    if status.success() {
        // Validate that the user didn't break the JSON structure
        CpopConfig::load_or_default(dir).context("Modified config is invalid JSON")?;
        println!("✅ Configuration updated.");
    }
    
    Ok(())
}

fn reset_config(dir: &Path, path: &Path, force: bool) -> Result<()> {
    if !force && !ask_confirm("Reset all settings to forensic defaults?")? {
        println!("Reset cancelled.");
        return Ok(());
    }

    if path.exists() {
        fs::remove_file(path).context("Could not remove config file")?;
    }

    CpopConfig::load_or_default(dir)?.persist()?;
    println!("✅ Configuration has been reset to defaults.");
    Ok(())
}

fn parse_bool(s: &str) -> Result<bool> {
    match s.to_lowercase().as_str() {
        "true" | "yes" | "1" | "on" => Ok(true),
        "false" | "no" | "0" | "off" => Ok(false),
        _ => Err(anyhow!("Invalid boolean: '{}' (use true/false)", s)),
    }
}

fn parse_range<T>(s: &str, range: std::ops::RangeInclusive<T>) -> Result<T> 
where T: std::str::FromStr + PartialOrd + std::fmt::Display + Copy {
    let val: T = s.parse().map_err(|_| anyhow!("'{}' is not a valid number", s))?;
    if !range.contains(&val) {
        bail!("Value must be between {} and {}", range.start(), range.end());
    }
    Ok(val)
}

fn ask_confirm(prompt: &str) -> Result<bool> {
    print!("{} (y/N): ", prompt);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(matches!(input.trim().to_lowercase().as_str(), "y" | "yes"))
}

fn handle_voice_consent_change(config: &mut CpopConfig, dir: &Path, enabled: bool) -> Result<()> {
    use cpop_engine::fingerprint::{ConsentManager, ConsentStatus};
    let mut manager = ConsentManager::new(dir)?;

    if enabled {
        match manager.status() {
            ConsentStatus::Granted => config.fingerprint.voice_enabled = true,
            _ => {
                println!("\n{}", cpop_engine::fingerprint::consent::CONSENT_EXPLANATION);
                if ask_confirm("Do you consent to voice fingerprinting?")? {
                    manager.grant_consent()?;
                    config.fingerprint.voice_enabled = true;
                } else {
                    bail!("Consent required to enable voice features.");
                }
            }
        }
    } else {
        manager.revoke_consent()?;
        config.fingerprint.voice_enabled = false;
    }
    Ok(())
}

fn parse_editor_command(editor: &str) -> Result<(String, Vec<String>)> {
    let parts: Vec<String> = editor.split_whitespace().map(String::from).collect();
    let (cmd, args) = parts.split_first()
        .ok_or_else(|| anyhow!("EDITOR environment variable is empty"))?;
    Ok((cmd.clone(), args.to_vec()))
}