

//! Endpoint Security FFI -- AI tool detection persistence.
//!
//! Called from Swift when macOS Endpoint Security detects an AI tool launch.
//! Persists the signing ID into all active document sessions so evidence
//! packets can include AI tool co-presence as a limitation.

use crate::ffi::sentinel::SENTINEL;
use crate::ffi::types::FfiResult;
use crate::RwLockRecover;

/
/
/
/
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_es_ai_tool_detected(signing_id: String) -> FfiResult {
    let sentinel = match SENTINEL.get() {
        Some(s) => s,
        None => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some("Sentinel not initialized".to_string()),
            };
        }
    };

    let mut sessions = sentinel.sessions.write_recover();
    let mut updated = 0u32;
    for session in sessions.values_mut() {
        if !session.ai_tools_detected.contains(&signing_id) {
            session.ai_tools_detected.push(signing_id.clone());
            updated += 1;
        }
    }

    log::info!(
        "AI tool detected: {} (persisted to {} sessions)",
        signing_id,
        updated
    );

    FfiResult {
        success: true,
        message: Some(format!(
            "AI tool '{}' recorded in {} session(s)",
            signing_id, updated
        )),
        error_message: None,
    }
}

/
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_es_ai_tools_active() -> Vec<String> {
    let sentinel = match SENTINEL.get() {
        Some(s) => s,
        None => return Vec::new(),
    };

    let sessions = sentinel.sessions.read_recover();
    let mut tools: Vec<String> = Vec::new();
    for session in sessions.values() {
        for tool in &session.ai_tools_detected {
            if !tools.contains(tool) {
                tools.push(tool.clone());
            }
        }
    }
    tools
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sentinel::types::DocumentSession;

    #[test]
    fn test_ai_tool_detected_sentinel_not_initialized() {
        let result = ffi_sentinel_es_ai_tool_detected("com.openai.chat".to_string());
        assert!(!result.success);
        assert!(result
            .error_message
            .unwrap_or_default()
            .contains("not initialized"));
    }

    #[test]
    fn test_ai_tools_active_sentinel_not_initialized() {
        let tools = ffi_sentinel_es_ai_tools_active();
        assert!(tools.is_empty());
    }

    #[test]
    fn test_document_session_ai_tools_default_empty() {
        let session = DocumentSession::new(
            "/tmp/test.txt".to_string(),
            "com.test".to_string(),
            "Test".to_string(),
            crate::crypto::ObfuscatedString::new("test"),
        );
        assert!(session.ai_tools_detected.is_empty());
    }

    #[test]
    fn test_document_session_ai_tools_dedup() {
        let mut session = DocumentSession::new(
            "/tmp/test.txt".to_string(),
            "com.test".to_string(),
            "Test".to_string(),
            crate::crypto::ObfuscatedString::new("test"),
        );
        let tool = "com.openai.chat".to_string();
        session.ai_tools_detected.push(tool.clone());
        
        if !session.ai_tools_detected.contains(&tool) {
            session.ai_tools_detected.push(tool);
        }
        assert_eq!(session.ai_tools_detected.len(), 1);
        assert_eq!(session.ai_tools_detected[0], "com.openai.chat");
    }
}
