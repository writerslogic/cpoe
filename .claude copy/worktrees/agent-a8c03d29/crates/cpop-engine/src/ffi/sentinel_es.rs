

//! FFI functions for Endpoint Security event notifications from the host app.
//!
//! These are called by the Swift EndpointSecurityEventClient when ES events
//! match tracked documents or known AI tools.

use super::sentinel::get_sentinel;
use crate::RwLockRecover;

/
/
/
/
/
/
/
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_es_file_write(path: String, pid: i32, signing_id: String) -> bool {
    let sentinel_opt = get_sentinel();
    let sentinel = match sentinel_opt.as_ref() {
        Some(s) if s.is_running() => s,
        _ => return false,
    };

    
    let tracked = sentinel.tracked_files();
    if !tracked.iter().any(|t| t == &path) {
        return false;
    }

    log::info!(
        "ES file write detected for tracked document: {path} (pid={pid}, signing_id={signing_id})"
    );

    
    sentinel.commit_checkpoint_for_path(&path)
}

/
/
/
/
/
/
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_es_ai_tool_detected(signing_id: String, pid: i32, exec_path: String) -> bool {
    let sentinel_opt = get_sentinel();
    let sentinel = match sentinel_opt.as_ref() {
        Some(s) if s.is_running() => s,
        _ => return false,
    };

    log::warn!("AI tool detected via ES: signing_id={signing_id}, pid={pid}, path={exec_path}");

    
    let mut sessions = sentinel.sessions.write_recover();
    let mut updated = 0u32;
    for session in sessions.values_mut() {
        if !session.ai_tools_detected.contains(&signing_id) {
            session.ai_tools_detected.push(signing_id.clone());
            updated += 1;
        }
    }

    log::info!(
        "AI tool '{}' persisted to {} active session(s)",
        signing_id,
        updated
    );

    true
}

/
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_es_ai_tools_active() -> Vec<String> {
    let sentinel_opt = get_sentinel();
    let sentinel = match sentinel_opt.as_ref() {
        Some(s) if s.is_running() => s,
        _ => return Vec::new(),
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
    fn test_ai_tools_active_no_sentinel() {
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

    #[test]
    fn test_document_session_multiple_ai_tools() {
        let mut session = DocumentSession::new(
            "/tmp/test.txt".to_string(),
            "com.test".to_string(),
            "Test".to_string(),
            crate::crypto::ObfuscatedString::new("test"),
        );
        session
            .ai_tools_detected
            .push("com.openai.chat".to_string());
        session
            .ai_tools_detected
            .push("com.anthropic.claude".to_string());
        assert_eq!(session.ai_tools_detected.len(), 2);
    }

    #[test]
    fn test_collect_ai_tool_limitations_no_sentinel() {
        let result = crate::ffi::evidence_export::collect_ai_tool_limitations("/tmp/test.txt");
        assert!(result.is_none());
    }
}
