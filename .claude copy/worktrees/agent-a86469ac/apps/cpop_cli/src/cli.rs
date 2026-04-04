

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "cpop",
    bin_name = "cpop",
    author,
    version,
    about = "CPOP — cryptographic proof-of-process authorship witnessing",
    long_about = "CPOP captures behavioral evidence during document creation and packages \
it into cryptographically signed packets that prove a human authored content over \
time. This provides an offline-verifiable alternative to AI detection by proving \
how something was written, not just what was written."
)]
#[command(after_help = "\
EXAMPLES:\n  \
    cpop essay.txt                       Start tracking a file\n  \
    cpop commit essay.txt -m \"Draft 1\"    Create a checkpoint\n  \
    cpop export essay.txt -t standard     Export evidence (JSON)\n  \
    cpop export essay.txt -f pdf          Export signed PDF report\n  \
    cpop export essay.txt --no-beacons    Export without beacon attestation\n  \
    cpop link essay.txt essay.pdf         Link derivative to source\n  \
    cpop verify essay.evidence.json       Verify a proof packet\n\n\
ENVIRONMENT:\n  \
    CPOP_DATA_DIR           Override default data directory (~/.writersproof)\n  \
    CPOP_BEACONS_ENABLED    Enable/disable temporal beacons (true/false)\n  \
    EDITOR                  Editor for 'cpop config edit'\n\n\
Use 'cpop <command> --help' for details on specific commands.")]
#[command(args_conflicts_with_subcommands = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /
    pub path: Option<PathBuf>,

    /
    #[arg(long, global = true)]
    pub json: bool,

    /
    #[arg(short, long, global = true)]
    pub quiet: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /
    #[command(hide = true)]
    Init {},

    /
    #[command(
        alias = "checkpoint",
        after_help = "Checkpoints are chained hashes with VDF time proofs that form \
                      an unforgeable timeline of your writing process."
    )]
    Commit {
        /
        file: Option<PathBuf>,
        /
        #[arg(short, long)]
        message: Option<String>,
        /
        #[arg(long)]
        anchor: bool,
    },

    /
    #[command(alias = "history", alias = "ls")]
    Log {
        /
        file: Option<PathBuf>,
    },

    /
    #[command(
        alias = "prove",
        after_help = "TIERS:\n  \
            basic     T1 — VDF proof only (offline)\n  \
            standard  T2 — + keystrokes + timing (recommended)\n  \
            enhanced  T3 — + behavioral analysis + hardware\n  \
            maximum   T4 — + all external anchors + full attestation\n\n\
            FORMATS:\n  \
            json  Machine-readable evidence packet\n  \
            cpop  CBOR binary wire format\n  \
            cwar  COSE-signed attestation result\n  \
            html  Self-contained HTML report (open in browser)\n  \
            pdf   Signed PDF with anti-forgery security features\n  \
            c2pa  C2PA assertion JSON (embed via c2patool)\n\n\
            BEACONS:\n  \
            Temporal beacons (drand + NIST) are enabled by default via WritersProof.\n  \
            Use --no-beacons to disable (caps security level at T2)."
    )]
    Export {
        /
        file: PathBuf,
        /
        #[arg(short = 't', long, visible_alias = "tier", default_value = "basic")]
        tier: String,
        /
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,
        /
        #[arg(short = 'f', long, default_value = "json")]
        format: String,
        /
        #[arg(long)]
        no_beacons: bool,
        /
        #[arg(long, default_value = "5", value_parser = clap::value_parser!(u64).range(1..=300))]
        beacon_timeout: u64,
    },

    /
    #[command(alias = "check")]
    Verify {
        /
        file: PathBuf,
        /
        #[arg(short, long)]
        key: Option<PathBuf>,
        /
        #[arg(long)]
        output_war: Option<PathBuf>,
    },

    /
    Presence {
        #[command(subcommand)]
        action: PresenceAction,
    },

    /
    #[command(
        after_help = "Creates a cryptographic binding between a source document's evidence \
                      chain and an exported derivative (PDF, EPUB, DOCX, etc.).\n\n\
                      EXAMPLES:\n  \
                          cpop link novel.scriv manuscript.pdf -m \"Final PDF\"\n  \
                          cpop link essay.txt essay.pdf\n  \
                          cpop link project.scriv manuscript.epub -m \"EPUB export\""
    )]
    Link {
        /
        source: PathBuf,
        /
        export: PathBuf,
        /
        #[arg(short, long)]
        message: Option<String>,
    },

    /
    #[command(args_conflicts_with_subcommands = true)]
    Track {
        #[command(subcommand)]
        action: Option<TrackAction>,
        /
        file: Option<PathBuf>,
    },

    /
    #[command(hide = true)]
    Calibrate,

    /
    Status,

    /
    #[command(hide = true)]
    Completions {
        /
        shell: clap_complete::Shell,
    },

    /
    #[command(hide = true)]
    Start {
        /
        #[arg(short, long)]
        foreground: bool,
    },

    /
    #[command(hide = true)]
    Stop,

    /
    #[command(alias = "fp")]
    Fingerprint {
        #[command(subcommand)]
        action: FingerprintAction,
    },

    /
    #[command(hide = true)]
    Attest {
        /
        #[arg(short, long, default_value = "war")]
        format: String,
        /
        #[arg(short, long)]
        input: Option<PathBuf>,
        /
        #[arg(short, long)]
        output: Option<PathBuf>,
        /
        #[arg(long)]
        non_interactive: bool,
    },

    /
    #[command(alias = "id")]
    Identity {
        /
        #[arg(long)]
        fingerprint: bool,
        /
        #[arg(long)]
        did: bool,
        /
        #[arg(long)]
        mnemonic: bool,
        /
        #[arg(long)]
        recover: bool,
    },

    /
    #[command(alias = "cfg")]
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /
    #[command(alias = "manual")]
    Man,
}

impl Commands {
    /
    /
    /
    /
    pub fn needs_auto_start(&self) -> bool {
        !matches!(
            self,
            Commands::Start { .. }
                | Commands::Stop
                | Commands::Status
                | Commands::Init { .. }
                | Commands::Calibrate
                | Commands::Config { .. }
                | Commands::Completions { .. }
                | Commands::Man
        )
    }
}

#[derive(Subcommand)]
pub enum PresenceAction {
    /
    Start,
    /
    Stop,
    /
    Status,
    /
    Challenge,
}

#[derive(Subcommand)]
pub enum TrackAction {
    /
    Start {
        /
        path: PathBuf,
        /
        #[arg(short, long, default_value_t = String::new(), hide_default_value = true)]
        patterns: String,
    },
    /
    Stop,
    /
    Status,
    /
    List,
    /
    Show {
        /
        id: String,
    },
    /
    Export {
        /
        session_id: String,
    },
}

#[derive(Subcommand)]
pub enum FingerprintAction {
    /
    Status,
    /
    Show {
        /
        #[arg(short, long)]
        id: Option<String>,
    },
    /
    Compare {
        /
        id1: String,
        /
        id2: String,
    },
    /
    List,
    /
    Delete {
        /
        id: String,
        /
        #[arg(short, long)]
        force: bool,
    },
}

#[derive(Subcommand)]
pub enum ConfigAction {
    /
    Show,
    /
    Set {
        /
        key: String,
        /
        value: String,
    },
    /
    Edit,
    /
    Reset {
        /
        #[arg(short, long)]
        force: bool,
    },
}
