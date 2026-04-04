

use crate::ffi::helpers::{get_data_dir, open_store};
use crate::ffi::types::FfiResult;
use zeroize::Zeroize;

/
fn load_signing_key() -> Result<ed25519_dalek::SigningKey, String> {
    let data_dir = get_data_dir().ok_or_else(|| "Data directory not found".to_string())?;
    let key_path = data_dir.join("signing_key");
    let mut key_data =
        std::fs::read(&key_path).map_err(|e| format!("Failed to read signing key: {e}"))?;
    if key_data.len() < 32 {
        key_data.zeroize();
        return Err("Signing key is too short".to_string());
    }
    let mut secret: [u8; 32] = key_data[..32]
        .try_into()
        .map_err(|_| "Invalid signing key length".to_string())?;
    key_data.zeroize();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
    secret.zeroize();
    Ok(signing_key)
}

/
#[cfg(unix)]
fn write_restrictive(path: &std::path::Path, data: &[u8]) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;

    let tmp_path = path.with_extension("tmp");
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp_path)
        .map_err(|e| format!("Failed to create temp file: {e}"))?;
    std::io::Write::write_all(&mut &file, data)
        .map_err(|e| format!("Failed to write temp file: {e}"))?;
    drop(file);
    std::fs::rename(&tmp_path, path).map_err(|e| format!("Failed to rename temp file: {e}"))
}

#[cfg(not(unix))]
fn write_restrictive(path: &std::path::Path, data: &[u8]) -> Result<(), String> {
    std::fs::write(path, data).map_err(|e| format!("Failed to write file: {e}"))
}

/
/
/
/
/
/
/
/
/
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_embed_stego_watermark(evidence_path: String, document_path: String) -> FfiResult {
    use crate::steganography::{ZwcEmbedder, ZwcParams};
    use sha2::{Digest, Sha256};

    let doc_path = match crate::sentinel::helpers::validate_path(&document_path) {
        Ok(p) => p,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Invalid document path: {e}")),
            };
        }
    };
    let ev_path = match crate::sentinel::helpers::validate_path(&evidence_path) {
        Ok(p) => p,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Invalid evidence path: {e}")),
            };
        }
    };

    if !doc_path.exists() {
        return FfiResult {
            success: false,
            message: None,
            error_message: Some(format!("Document not found: {}", doc_path.display())),
        };
    }
    if !ev_path.exists() {
        return FfiResult {
            success: false,
            message: None,
            error_message: Some(format!("Evidence not found: {}", ev_path.display())),
        };
    }

    
    let content = match std::fs::read_to_string(&doc_path) {
        Ok(c) => c,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!(
                    "Cannot read document as UTF-8 (stego requires text files): {e}"
                )),
            };
        }
    };

    
    let store = match open_store() {
        Ok(s) => s,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(e),
            };
        }
    };
    let events = match store.get_events_for_file(&document_path) {
        Ok(e) => e,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Failed to load events: {e}")),
            };
        }
    };
    let latest = match events.last() {
        Some(ev) => ev,
        None => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some("No checkpoints found for this document".to_string()),
            };
        }
    };
    let mmr_root = latest.event_hash;

    
    let signing_key = match load_signing_key() {
        Ok(k) => k,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(e),
            };
        }
    };
    let mut hmac_key: [u8; 32] = {
        let mut hasher = Sha256::new();
        hasher.update(b"witnessd-stego-key-v1");
        hasher.update(signing_key.to_bytes());
        hasher.finalize().into()
    };
    

    
    let embedder = ZwcEmbedder::new(ZwcParams::default());
    let (watermarked, binding) = match embedder.embed(&content, &mmr_root, &hmac_key) {
        Ok(r) => r,
        Err(e) => {
            hmac_key.zeroize();
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Watermark embedding failed: {e}")),
            };
        }
    };
    hmac_key.zeroize();

    
    let stem = doc_path.file_stem().unwrap_or_default().to_string_lossy();
    let ext = doc_path
        .extension()
        .map(|e| e.to_string_lossy().to_string())
        .unwrap_or_default();
    let stego_path = if ext.is_empty() {
        doc_path.with_file_name(format!("{stem}.stego"))
    } else {
        doc_path.with_file_name(format!("{stem}.stego.{ext}"))
    };
    let binding_path = doc_path.with_extension("stego.binding.json");

    
    if let Err(e) = write_restrictive(&stego_path, watermarked.as_bytes()) {
        return FfiResult {
            success: false,
            message: None,
            error_message: Some(format!("Failed to write watermarked document: {e}")),
        };
    }

    
    let binding_json = match serde_json::to_string_pretty(&binding) {
        Ok(j) => j,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Failed to serialize binding: {e}")),
            };
        }
    };
    if let Err(e) = write_restrictive(&binding_path, binding_json.as_bytes()) {
        return FfiResult {
            success: false,
            message: None,
            error_message: Some(format!("Failed to write binding record: {e}")),
        };
    }

    FfiResult {
        success: true,
        message: Some(format!(
            "Watermark embedded: {} ({} ZWCs)",
            stego_path.display(),
            binding.zwc_count
        )),
        error_message: None,
    }
}
