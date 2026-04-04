

use super::defaults;
use crate::vdf::params::Parameters as VdfParameters;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CpopConfig {
    pub data_dir: PathBuf,
    pub watch_dirs: Vec<PathBuf>,
    pub retention_days: u32,
    pub presence: PresenceConfig,
    pub vdf: VdfConfig,
    pub sentinel: SentinelConfig,
    pub research: ResearchConfig,
    pub fingerprint: FingerprintConfig,
    pub privacy: PrivacyConfig,
    pub writersproof: WritersProofConfig,
    pub beacons: BeaconConfig,
}

impl Default for CpopConfig {
    fn default() -> Self {
        Self {
            data_dir: defaults::default_data_dir(),
            watch_dirs: defaults::default_watch_dirs(),
            retention_days: 30,
            presence: PresenceConfig::default(),
            vdf: VdfConfig::default(),
            sentinel: SentinelConfig::default(),
            research: ResearchConfig::default(),
            fingerprint: FingerprintConfig::default(),
            privacy: PrivacyConfig::default(),
            writersproof: WritersProofConfig::default(),
            beacons: BeaconConfig::default(),
        }
    }
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WritersProofConfig {
    pub enabled: bool,
    pub base_url: String,
    /
    pub auto_attest: bool,
    /
    pub offline_queue: bool,
}

impl Default for WritersProofConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            base_url: "https:
            auto_attest: false,
            offline_queue: true,
        }
    }
}

/
/
/
/
/
/
/
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BeaconConfig {
    /
    /
    /
    pub enabled: bool,
    /
    pub timeout_secs: u64,
    /
    pub retries: u32,
}

impl Default for BeaconConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            timeout_secs: 5,
            retries: 2,
        }
    }
}

impl BeaconConfig {
    /
    pub fn sanitize(&mut self) {
        self.timeout_secs = self.timeout_secs.clamp(1, 300);
        self.retries = self.retries.clamp(0, 10);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FingerprintConfig {
    /
    pub activity_enabled: bool,
    /
    pub voice_enabled: bool,
    pub retention_days: u32,
    /
    pub min_samples: u32,
    pub storage_path: PathBuf,
}

impl Default for FingerprintConfig {
    fn default() -> Self {
        Self {
            activity_enabled: true,
            voice_enabled: false,
            retention_days: 365,
            min_samples: 100,
            storage_path: dirs::home_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join(".writersproof")
                .join("fingerprints"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PrivacyConfig {
    /
    pub detect_sensitive_fields: bool,
    pub hash_urls: bool,
    pub obfuscate_titles: bool,
    /
    pub excluded_apps: Vec<String>,
}

impl Default for PrivacyConfig {
    fn default() -> Self {
        Self {
            detect_sensitive_fields: true,
            hash_urls: true,
            obfuscate_titles: true,
            excluded_apps: vec![
                "1Password".to_string(),
                "Keychain Access".to_string(),
                "System Preferences".to_string(),
                "Terminal".to_string(),
            ],
        }
    }
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ResearchConfig {
    /
    pub contribute_to_research: bool,
    pub research_data_dir: PathBuf,
    pub max_sessions: usize,
    pub min_samples_per_session: usize,
    /
    pub upload_interval_secs: u64,
    pub auto_upload: bool,
}

impl Default for ResearchConfig {
    fn default() -> Self {
        Self {
            contribute_to_research: false,
            research_data_dir: dirs::home_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join(".writersproof")
                .join("research"),
            max_sessions: 100,
            min_samples_per_session: 10,
            upload_interval_secs: 4 * 60 * 60,
            auto_upload: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PresenceConfig {
    pub challenge_interval_secs: u64,
    pub response_window_secs: u64,
}

impl Default for PresenceConfig {
    fn default() -> Self {
        Self {
            challenge_interval_secs: 600,
            response_window_secs: 60,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct VdfConfig {
    pub iterations_per_second: u64,
    pub min_iterations: u64,
    pub max_iterations: u64,
}

impl Default for VdfConfig {
    fn default() -> Self {
        Self {
            iterations_per_second: 1_000_000,
            min_iterations: 100_000,
            max_iterations: 3_600_000_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SentinelConfig {
    pub auto_start: bool,
    pub heartbeat_interval_secs: u64,
    pub checkpoint_interval_secs: u64,
    pub writersproof_dir: PathBuf,
    pub shadow_dir: PathBuf,
    pub wal_dir: PathBuf,
    pub watch_paths: Vec<PathBuf>,
    pub recursive_watch: bool,

    pub idle_timeout_secs: u64,
    pub allowed_apps: Vec<String>,
    pub blocked_apps: Vec<String>,
    pub track_unknown_apps: bool,
    pub hash_on_focus: bool,
    pub hash_on_save: bool,
    pub poll_interval_ms: u64,
    /
    pub snapshots_enabled: bool,
}

impl Default for SentinelConfig {
    fn default() -> Self {
        let writersproof_dir = {
            #[cfg(target_os = "macos")]
            {
                
                dirs::home_dir()
                    .map(|h| h.join("Library/Application Support/WritersProof"))
                    .unwrap_or_else(|| std::path::PathBuf::from("."))
            }
            #[cfg(not(target_os = "macos"))]
            {
                dirs::data_local_dir()
                    .map(|d| d.join("CPOP"))
                    .unwrap_or_else(|| {
                        dirs::home_dir()
                            .unwrap_or_else(|| std::path::PathBuf::from("."))
                            .join(".writersproof")
                    })
            }
        };

        Self {
            auto_start: false,
            heartbeat_interval_secs: 60,
            checkpoint_interval_secs: 60,
            writersproof_dir: writersproof_dir.clone(),
            shadow_dir: writersproof_dir.join("shadow"),
            wal_dir: writersproof_dir.join("sentinel").join("wal"),
            watch_paths: Vec::new(),
            recursive_watch: true,
            idle_timeout_secs: 1800,
            allowed_apps: vec![
                
                "com.apple.TextEdit".to_string(),
                "com.apple.iWork.Pages".to_string(),
                "com.apple.iWork.Numbers".to_string(),
                "com.apple.iWork.Keynote".to_string(),
                "com.apple.dt.Xcode".to_string(),
                
                "com.microsoft.Word".to_string(),
                "com.microsoft.Excel".to_string(),
                "com.microsoft.Powerpoint".to_string(),
                
                "code".to_string(),
                "com.microsoft.VSCode".to_string(),
                "com.microsoft.VSCodeInsiders".to_string(),
                "com.todesktop.230313mzl4w4u92".to_string(), 
                "com.sublimetext.4".to_string(),
                "com.sublimetext.3".to_string(),
                "com.jetbrains.intellij".to_string(),
                "com.jetbrains.WebStorm".to_string(),
                "com.jetbrains.pycharm".to_string(),
                "com.jetbrains.CLion".to_string(),
                "com.jetbrains.goland".to_string(),
                "com.jetbrains.rider".to_string(),
                "com.googlecode.iterm2".to_string(),
                "org.vim.MacVim".to_string(),
                "com.github.atom".to_string(),
                "com.panic.Nova".to_string(),
                "com.barebones.bbedit".to_string(),
                "com.coteditor.CotEditor".to_string(),
                
                "com.typora.Typora".to_string(),
                "md.obsidian".to_string(),
                "com.notion.Notion".to_string(),
                "com.notion.id".to_string(),
                "com.literatureandlatte.scrivener3".to_string(),
                "com.ulyssesapp.mac".to_string(),
                "net.shinyfrog.bear".to_string(),
                "com.reederapp.5.macOS".to_string(),
                "pro.writer.mac".to_string(), 
                "com.omnigroup.OmniOutliner5".to_string(),
                
                "Google Docs".to_string(),
                
                "org.libreoffice.LibreOffice".to_string(),
                "org.openoffice.script".to_string(),
                
                "org.gnome.gedit".to_string(),
                "org.gnome.TextEditor".to_string(),
                "org.kde.kate".to_string(),
            ],
            blocked_apps: vec![
                
                "com.apple.finder".to_string(),
                "explorer".to_string(),
                
                "com.apple.Terminal".to_string(),
                "com.googlecode.iterm2".to_string(),
                "org.vim.MacVim".to_string(),
                "com.github.wez.wezterm".to_string(),
                "net.kovidgoyal.kitty".to_string(),
                "io.alacritty".to_string(),
                "org.gnome.Terminal".to_string(),
                "org.kde.konsole".to_string(),
            ],
            track_unknown_apps: true,
            hash_on_focus: true,
            hash_on_save: true,
            poll_interval_ms: 100,
            snapshots_enabled: false,
        }
    }
}

impl SentinelConfig {
    /
    pub fn with_writersproof_dir(mut self, dir: impl AsRef<Path>) -> Self {
        let dir = dir.as_ref().to_path_buf();
        self.shadow_dir = dir.join("shadow");
        self.wal_dir = dir.join("sentinel").join("wal");
        self.writersproof_dir = dir;
        self
    }

    /
    /
    /
    /
    /
    pub fn is_app_allowed(&self, bundle_id: &str, app_name: &str) -> bool {
        let bid = bundle_id.to_lowercase();
        let aname = app_name.to_lowercase();
        for blocked in &self.blocked_apps {
            let b = blocked.to_lowercase();
            if b == bid || b == aname {
                return false;
            }
        }
        if self.allowed_apps.is_empty() {
            return self.track_unknown_apps;
        }
        for allowed in &self.allowed_apps {
            let a = allowed.to_lowercase();
            if a == bid || a == aname {
                return true;
            }
        }
        self.track_unknown_apps
    }

    /
    pub fn validate(&self) -> Result<()> {
        use anyhow::bail;

        fn require_nonzero(val: u64, name: &str) -> Result<()> {
            if val == 0 {
                bail!("{name} must be > 0");
            }
            Ok(())
        }

        require_nonzero(self.checkpoint_interval_secs, "checkpoint_interval_secs")?;
        require_nonzero(self.heartbeat_interval_secs, "heartbeat_interval_secs")?;
        require_nonzero(self.poll_interval_ms, "poll_interval_ms")?;

        if self.idle_timeout_secs < self.checkpoint_interval_secs {
            bail!(
                "idle_timeout_secs ({}) must be >= checkpoint_interval_secs ({})",
                self.idle_timeout_secs,
                self.checkpoint_interval_secs
            );
        }
        Ok(())
    }

    /
    pub fn ensure_directories(&self) -> Result<()> {
        fs::create_dir_all(&self.writersproof_dir)?;
        fs::create_dir_all(&self.shadow_dir)?;
        fs::create_dir_all(&self.wal_dir)?;
        Ok(())
    }
}

impl CpopConfig {
    /
    pub fn validate(&self) -> Result<()> {
        use anyhow::bail;

        if self.retention_days == 0 {
            bail!("retention_days must be > 0");
        }
        if self.vdf.iterations_per_second == 0 {
            bail!("vdf.iterations_per_second must be > 0");
        }
        if self.vdf.min_iterations == 0 {
            bail!("vdf.min_iterations must be > 0");
        }
        if self.vdf.max_iterations == 0 {
            bail!("vdf.max_iterations must be > 0");
        }
        if self.vdf.min_iterations > self.vdf.max_iterations {
            bail!(
                "vdf.min_iterations ({}) must be <= max_iterations ({})",
                self.vdf.min_iterations,
                self.vdf.max_iterations
            );
        }
        if self.presence.challenge_interval_secs == 0 {
            bail!("presence.challenge_interval_secs must be > 0");
        }
        if self.presence.response_window_secs == 0 {
            bail!("presence.response_window_secs must be > 0");
        }
        self.sentinel.validate()?;
        Ok(())
    }
}

impl From<CpopConfig> for VdfParameters {
    fn from(cfg: CpopConfig) -> Self {
        Self {
            iterations_per_second: cfg.vdf.iterations_per_second,
            min_iterations: cfg.vdf.min_iterations,
            max_iterations: cfg.vdf.max_iterations,
        }
    }
}
