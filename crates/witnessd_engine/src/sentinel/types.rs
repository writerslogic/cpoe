// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::crypto::ObfuscatedString;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

// ============================================================================
// Event Types
// ============================================================================

/// Focus event type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocusEventType {
    /// Document gained focus
    FocusGained,
    /// Document lost focus
    FocusLost,
    /// Focus moved to unknown/non-trackable window
    FocusUnknown,
}

/// Focus change event
#[derive(Debug, Clone)]
pub struct FocusEvent {
    pub event_type: FocusEventType,
    pub path: String,
    pub shadow_id: String,
    pub app_bundle_id: String,
    pub app_name: String,
    pub window_title: ObfuscatedString,
    pub timestamp: SystemTime,
}

/// Change event type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeEventType {
    /// Document was modified
    Modified,
    /// Document was saved
    Saved,
    /// New document was created
    Created,
    /// Document was deleted
    Deleted,
}

/// File change event
#[derive(Debug, Clone)]
pub struct ChangeEvent {
    pub event_type: ChangeEventType,
    pub path: String,
    pub hash: Option<String>,
    pub size: Option<i64>,
    pub timestamp: SystemTime,
}

/// Session event type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEventType {
    /// New tracking session started
    Started,
    /// Session gained focus
    Focused,
    /// Session lost focus
    Unfocused,
    /// Document was saved
    Saved,
    /// Session ended
    Ended,
}

/// Session state change event
#[derive(Debug, Clone)]
pub struct SessionEvent {
    pub event_type: SessionEventType,
    pub session_id: String,
    pub document_path: String,
    pub timestamp: SystemTime,
}

// ============================================================================
// Window Information (for focus tracking)
// ============================================================================

/// Information about the currently focused window
#[derive(Debug, Clone)]
pub struct WindowInfo {
    /// Resolved file path of the document (if available)
    pub path: Option<String>,
    /// Application name or bundle ID
    pub application: String,
    /// Window title
    pub title: ObfuscatedString,
    /// Process ID of the owning application
    pub pid: Option<u32>,
    /// Timestamp when focus info was captured
    pub timestamp: SystemTime,
    /// Whether this appears to be a document window
    pub is_document: bool,
    /// Whether the document appears to be unsaved
    pub is_unsaved: bool,
    /// Project/workspace root if detected (for IDEs)
    pub project_root: Option<String>,
}

impl Default for WindowInfo {
    fn default() -> Self {
        Self {
            path: None,
            application: String::new(),
            title: ObfuscatedString::default(),
            pid: None,
            timestamp: SystemTime::now(),
            is_document: false,
            is_unsaved: false,
            project_root: None,
        }
    }
}

// ============================================================================
// Document Session
// ============================================================================

/// Tracks a single document's editing session
#[derive(Debug, Clone)]
pub struct DocumentSession {
    /// Document file path
    pub path: String,

    /// Unique session identifier
    pub session_id: String,

    /// Shadow buffer ID for unsaved documents
    pub shadow_id: Option<String>,

    /// Session start time
    pub start_time: SystemTime,

    /// Last focus time
    pub last_focus_time: SystemTime,

    /// Total time focused (milliseconds)
    pub total_focus_ms: i64,

    /// Number of times focused
    pub focus_count: u32,

    /// Initial document hash
    pub initial_hash: Option<String>,

    /// Current document hash
    pub current_hash: Option<String>,

    /// Number of saves
    pub save_count: u32,

    /// Number of changes detected
    pub change_count: u32,

    /// Application bundle ID
    pub app_bundle_id: String,

    /// Application name
    pub app_name: String,

    /// Window title
    pub window_title: ObfuscatedString,

    // Internal state
    pub(crate) has_focus: bool,
    pub(crate) focus_started: Option<Instant>,
}

impl DocumentSession {
    /// Create a new document session
    pub fn new(
        path: String,
        app_bundle_id: String,
        app_name: String,
        window_title: ObfuscatedString,
    ) -> Self {
        let session_id = generate_session_id();
        let now = SystemTime::now();

        Self {
            path,
            session_id,
            shadow_id: None,
            start_time: now,
            last_focus_time: now,
            total_focus_ms: 0,
            focus_count: 0,
            initial_hash: None,
            current_hash: None,
            save_count: 0,
            change_count: 0,
            app_bundle_id,
            app_name,
            window_title,
            has_focus: false,
            focus_started: None,
        }
    }

    /// Record focus gained
    pub fn focus_gained(&mut self) {
        if !self.has_focus {
            self.has_focus = true;
            self.focus_started = Some(Instant::now());
            self.last_focus_time = SystemTime::now();
            self.focus_count += 1;
        }
    }

    /// Record focus lost
    pub fn focus_lost(&mut self) {
        if self.has_focus {
            if let Some(started) = self.focus_started.take() {
                self.total_focus_ms += started.elapsed().as_millis() as i64;
            }
            self.has_focus = false;
        }
    }

    /// Check if session currently has focus
    pub fn is_focused(&self) -> bool {
        self.has_focus
    }

    /// Get total focus duration
    pub fn total_focus_duration(&self) -> Duration {
        let mut total = Duration::from_millis(self.total_focus_ms as u64);
        if let Some(started) = self.focus_started {
            total += started.elapsed();
        }
        total
    }
}

pub fn generate_session_id() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    let bytes: [u8; 16] = rng.random();
    hex::encode(bytes)
}

// ============================================================================
// Session Binding - Context for sessions without file paths
// ============================================================================

/// Session binding type for universal authorship monitoring.
///
/// Allows tracking sessions that may not have a traditional file path,
/// such as unsaved documents, browser editors, or universal keystrokes.
#[derive(Debug, Clone)]
pub enum SessionBinding {
    /// Traditional file path binding
    FilePath(PathBuf),

    /// App context for unsaved documents
    AppContext {
        /// Application bundle ID or path
        bundle_id: String,
        /// Hash of window identifier
        window_hash: String,
        /// Shadow buffer ID for content
        shadow_id: String,
    },

    /// URL context for browser-based editors
    UrlContext {
        /// Hashed domain (privacy)
        domain_hash: String,
        /// Hashed page identifier
        page_hash: String,
    },

    /// Universal session (no specific document)
    Universal {
        /// Unique session identifier
        session_id: String,
    },
}

impl SessionBinding {
    /// Create a file path binding.
    pub fn file(path: impl Into<PathBuf>) -> Self {
        Self::FilePath(path.into())
    }

    /// Create an app context binding.
    pub fn app_context(bundle_id: impl Into<String>, window_title: &str) -> Self {
        let window_hash = hash_string(window_title);
        let shadow_id = generate_session_id();
        Self::AppContext {
            bundle_id: bundle_id.into(),
            window_hash,
            shadow_id,
        }
    }

    /// Create a URL context binding.
    pub fn url_context(url: &str) -> Self {
        // Parse URL and hash components for privacy
        let (domain, path) = parse_url_parts(url);
        Self::UrlContext {
            domain_hash: hash_string(&domain),
            page_hash: hash_string(&path),
        }
    }

    /// Create a universal session binding.
    pub fn universal() -> Self {
        Self::Universal {
            session_id: generate_session_id(),
        }
    }

    /// Get the binding key for session lookup.
    pub fn key(&self) -> String {
        match self {
            Self::FilePath(path) => path.to_string_lossy().to_string(),
            Self::AppContext { shadow_id, .. } => format!("app:{}", shadow_id),
            Self::UrlContext {
                domain_hash,
                page_hash,
            } => format!("url:{}:{}", domain_hash, page_hash),
            Self::Universal { session_id } => format!("universal:{}", session_id),
        }
    }

    /// Check if this binding has a file path.
    pub fn has_file_path(&self) -> bool {
        matches!(self, Self::FilePath(_))
    }

    /// Get the file path if available.
    pub fn file_path(&self) -> Option<&Path> {
        match self {
            Self::FilePath(path) => Some(path),
            _ => None,
        }
    }
}

pub fn hash_string(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let result = hasher.finalize();
    hex::encode(&result[..8]) // Short hash for keys
}

pub fn parse_url_parts(url: &str) -> (String, String) {
    // Simple URL parsing
    let url = url
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let parts: Vec<&str> = url.splitn(2, '/').collect();
    let domain = parts.first().unwrap_or(&"").to_string();
    let path = parts.get(1).unwrap_or(&"").to_string();
    (domain, path)
}

// ============================================================================
// Document Path Inference from Window Title
// ============================================================================

/// Known document file extensions for heuristic detection.
const DOC_EXTENSIONS: &[&str] = &[
    ".docx", ".doc", ".txt", ".md", ".rtf", ".odt", ".tex", ".pdf", ".xlsx", ".xls", ".csv",
    ".pptx", ".ppt", ".rs", ".py", ".js", ".ts", ".jsx", ".tsx", ".c", ".cpp", ".h", ".java",
    ".go", ".rb", ".swift", ".kt", ".html", ".css", ".json", ".xml", ".yaml", ".yml", ".toml",
    ".sh", ".bat", ".ps1",
];

/// Attempt to infer a document file path from a window title string.
///
/// Many applications use titles like "filename.ext - AppName" or
/// "C:\path\to\file.ext - AppName". This function applies heuristics
/// to extract the file path.
pub fn infer_document_path_from_title(title: &str) -> Option<String> {
    if title.is_empty() {
        return None;
    }

    // Split on common title separators
    let separators = [" - ", " \u{2014} ", " | "];
    for sep in &separators {
        if title.contains(sep) {
            let segments: Vec<&str> = title.split(sep).collect();
            for segment in &segments {
                let segment = segment.trim();
                if looks_like_file_path(segment) {
                    return Some(segment.to_string());
                }
            }
        }
    }

    // Check the entire title as a last resort
    if looks_like_file_path(title.trim()) {
        return Some(title.trim().to_string());
    }

    None
}

/// Check if a string looks like a file path or filename with a known extension.
fn looks_like_file_path(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }

    // Check for absolute path patterns
    // Windows: C:\..., D:\...
    if s.len() >= 3
        && s.as_bytes().get(1) == Some(&b':')
        && matches!(s.as_bytes().get(2), Some(&b'\\') | Some(&b'/'))
    {
        return true;
    }
    // Unix: /...
    if s.starts_with('/') && s.len() > 1 {
        return true;
    }

    // Check for known file extensions
    let lower = s.to_lowercase();
    for ext in DOC_EXTENSIONS {
        if lower.ends_with(ext) {
            return true;
        }
    }

    false
}

/// Normalize a document path for consistent session keys
pub fn normalize_document_path(path: &str) -> String {
    let path = Path::new(path);

    // Try to get absolute path
    let abs = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());

    abs.to_string_lossy().to_string()
}
