#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use notify::{Config as WatchConfig, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::{self, File},
    io::{BufRead, BufReader, Read},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        Mutex, OnceLock,
        mpsc::{Receiver, channel},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const MAX_INSPECT_BYTES: u64 = 2 * 1024 * 1024;
const MAX_EVENT_PATHS: usize = 32;

#[derive(Parser, Debug)]
#[command(
    name = "tiny-rust-security-guard",
    about = "Conservative Linux guard for suspicious execution and cron persistence"
)]
struct Cli {
    /// Path to a TOML configuration file.
    #[arg(
        short,
        long,
        default_value = "/etc/tiny-rust-security-guard/config.toml"
    )]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Scan configured paths once; no filesystem changes in dry-run mode.
    Check,
    /// Scan once, then watch for filesystem events indefinitely.
    Watch,
    /// Send a harmless Discord configuration test notification.
    TestNotification,
}

#[derive(Debug, Deserialize)]
struct Config {
    monitor: MonitorConfig,
    #[serde(default)]
    detection: DetectionConfig,
    #[serde(default)]
    action: ActionConfig,
    notification: NotificationConfig,
}

#[derive(Debug, Deserialize)]
struct MonitorConfig {
    /// Numeric UID of the public runtime user, for example `id -u www`.
    web_uid: u32,
    #[serde(default = "default_watch_paths")]
    paths: Vec<PathBuf>,
    /// Cron spool locations. These are read to discover references to watched payloads.
    #[serde(default = "default_cron_paths")]
    cron_paths: Vec<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct DetectionConfig {
    /// SHA-256 values that are always quarantined when the file is owned by web_uid.
    #[serde(default)]
    known_sha256: Vec<String>,
    /// Require this many loader indicators before heuristic quarantine. Minimum 4.
    #[serde(default = "default_signal_threshold")]
    signal_threshold: usize,
    /// Suppress duplicate alerts for the same pathname and hash.
    #[serde(default = "default_alert_dedup_secs")]
    alert_dedup_secs: u64,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            known_sha256: vec![],
            signal_threshold: default_signal_threshold(),
            alert_dedup_secs: default_alert_dedup_secs(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct ActionConfig {
    /// Default false. True moves only a high-confidence matched payload to quarantine.
    #[serde(default)]
    enforce: bool,
    #[serde(default = "default_quarantine_dir")]
    quarantine_dir: PathBuf,
}

impl Default for ActionConfig {
    fn default() -> Self {
        Self {
            enforce: false,
            quarantine_dir: default_quarantine_dir(),
        }
    }
}

#[derive(Debug, Deserialize, Default)]
struct NotificationConfig {
    /// Read from this environment variable. Never place a Discord webhook in this file.
    #[serde(default = "default_webhook_env")]
    discord_webhook_env: String,
}

fn default_watch_paths() -> Vec<PathBuf> {
    vec!["/var/tmp".into(), "/tmp".into(), "/dev/shm".into()]
}
fn default_cron_paths() -> Vec<PathBuf> {
    vec!["/var/spool/cron".into(), "/var/spool/cron/crontabs".into()]
}
fn default_signal_threshold() -> usize {
    4
}
fn default_alert_dedup_secs() -> u64 {
    300
}
fn default_quarantine_dir() -> PathBuf {
    "/var/lib/tiny-rust-security-guard/quarantine".into()
}
fn default_webhook_env() -> String {
    "TRSG_DISCORD_WEBHOOK_URL".into()
}

#[derive(Debug)]
struct Finding {
    reason: String,
    sha256: String,
}

static ALERT_DEDUP: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();

fn main() -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    bail!("tiny-rust-security-guard supports Linux only");
    #[cfg(target_os = "linux")]
    run()
}

#[cfg(target_os = "linux")]
fn run() -> Result<()> {
    let cli = Cli::parse();
    let config: Config = toml::from_str(
        &fs::read_to_string(&cli.config)
            .with_context(|| format!("read {}", cli.config.display()))?,
    )?;
    validate_config(&config)?;
    match cli.command {
        Command::Check => initial_scan(&config),
        Command::Watch => watch(config),
        Command::TestNotification => {
            notify_discord(
                &config,
                "✅ **tiny-rust-security-guard:** notification test succeeded. No file was scanned, changed, or quarantined.",
            );
            Ok(())
        }
    }
}

fn validate_config(config: &Config) -> Result<()> {
    if config.monitor.paths.is_empty() {
        bail!("monitor.paths must not be empty");
    }
    if config.detection.signal_threshold < 4 {
        bail!(
            "detection.signal_threshold must be at least 4 to prevent unsafe heuristic quarantine"
        );
    }
    Ok(())
}

fn sha256(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0_u8; 65_536];
    loop {
        let read = file.read(&mut buf)?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn inspect(path: &Path, config: &Config) -> Result<Option<Finding>> {
    let metadata = match fs::metadata(path) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    if !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_INSPECT_BYTES
        || metadata.uid() != config.monitor.web_uid
    {
        return Ok(None);
    }
    let hash = sha256(path)?;
    if config
        .detection
        .known_sha256
        .iter()
        .any(|value| value.eq_ignore_ascii_case(&hash))
    {
        return Ok(Some(Finding {
            reason: "known malicious SHA-256".into(),
            sha256: hash,
        }));
    }
    let mut contents = Vec::with_capacity(metadata.len() as usize);
    File::open(path)?
        .take(MAX_INSPECT_BYTES)
        .read_to_end(&mut contents)?;
    if contents.contains(&0) {
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&contents);
    let executable_script = metadata.permissions().mode() & 0o111 != 0 || text.starts_with("#!");
    if !executable_script {
        return Ok(None);
    }
    let indicators = [
        "PHPSESSID",
        "IO::Socket::INET",
        "setsid",
        "fork",
        "eval",
        "chmod 0755",
    ];
    let count = indicators
        .iter()
        .filter(|indicator| text.contains(**indicator))
        .count();
    if count >= config.detection.signal_threshold {
        return Ok(Some(Finding {
            reason: format!(
                "high-confidence loader signature ({count}/{} indicators)",
                indicators.len()
            ),
            sha256: hash,
        }));
    }
    Ok(None)
}

fn hostname() -> String {
    fs::read_to_string("/etc/hostname")
        .unwrap_or_else(|_| "unknown-host".into())
        .trim()
        .to_string()
}

fn notify_discord(config: &Config, message: &str) {
    let Ok(webhook) = std::env::var(&config.notification.discord_webhook_env) else {
        eprintln!(
            "notification skipped: {} is unset",
            config.notification.discord_webhook_env
        );
        return;
    };
    if !webhook.starts_with("https://discord.com/api/webhooks/") {
        eprintln!("notification skipped: invalid Discord webhook URL");
        return;
    }
    let body = serde_json::json!({"content": message});
    if let Err(error) = ureq::post(&webhook).send_json(&body) {
        eprintln!("Discord notification failed: {error}");
    }
}

fn quarantine(path: &Path, finding: &Finding, config: &Config) -> Result<PathBuf> {
    fs::create_dir_all(&config.action.quarantine_dir)?;
    let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("unnamed");
    let destination = config
        .action
        .quarantine_dir
        .join(format!("{ts}-{name}-{}", &finding.sha256[..12]));
    fs::rename(path, &destination)
        .with_context(|| format!("atomic quarantine move for {}", path.display()))?;
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o600))?;
    Ok(destination)
}

fn handle(path: &Path, config: &Config) -> Result<()> {
    let Some(finding) = inspect(path, config)? else {
        return Ok(());
    };
    let dedup_key = format!("{}:{}", path.display(), finding.sha256);
    if !claim_alert(&dedup_key, config.detection.alert_dedup_secs) {
        return Ok(());
    }
    let prefix = if config.action.enforce {
        "🚨 **tiny-rust-security-guard:** quarantined"
    } else {
        "⚠️ **tiny-rust-security-guard (dry run):** would quarantine"
    };
    let message = format!(
        "{prefix} `{}` on `{}`. Reason: {}. SHA-256: `{}`",
        path.display(),
        hostname(),
        finding.reason,
        finding.sha256
    );
    if config.action.enforce {
        let destination = quarantine(path, &finding, config)?;
        eprintln!("{message}; moved to {}", destination.display());
    } else {
        eprintln!("{message}");
    }
    notify_discord(config, &message);
    Ok(())
}

fn claim_alert(key: &str, window_secs: u64) -> bool {
    let now = Instant::now();
    let mut entries = ALERT_DEDUP
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .expect("alert dedup mutex poisoned");
    entries.retain(|_, previous| now.duration_since(*previous) < Duration::from_secs(window_secs));
    if entries.contains_key(key) {
        return false;
    }
    entries.insert(key.to_owned(), now);
    true
}

fn initial_scan(config: &Config) -> Result<()> {
    for directory in &config.monitor.paths {
        for entry in
            fs::read_dir(directory).with_context(|| format!("read {}", directory.display()))?
        {
            let path = entry?.path();
            if let Err(error) = handle(&path, config) {
                eprintln!("scan {}: {error:#}", path.display());
            }
        }
    }
    inspect_cron_references(config)
}

fn inspect_cron_references(config: &Config) -> Result<()> {
    for directory in &config.monitor.cron_paths {
        let Ok(entries) = fs::read_dir(directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let cron_file = entry.path();
            let Ok(file) = File::open(&cron_file) else {
                continue;
            };
            for line in BufReader::new(file).lines().map_while(Result::ok) {
                for candidate in line
                    .split_whitespace()
                    .filter(|value| value.starts_with('/'))
                {
                    let path = Path::new(candidate);
                    if config
                        .monitor
                        .paths
                        .iter()
                        .any(|base| path.starts_with(base))
                        && let Err(error) = handle(path, config)
                    {
                        eprintln!("cron reference {}: {error:#}", path.display());
                    }
                }
            }
        }
    }
    Ok(())
}

fn watch(config: Config) -> Result<()> {
    initial_scan(&config)?;
    let (sender, receiver) = channel::<notify::Result<Event>>();
    let mut watcher = RecommendedWatcher::new(
        sender,
        WatchConfig::default().with_poll_interval(Duration::from_secs(2)),
    )?;
    for path in config
        .monitor
        .paths
        .iter()
        .chain(config.monitor.cron_paths.iter())
    {
        watcher.watch(path, RecursiveMode::NonRecursive)?;
    }
    eprintln!(
        "watching {} payload and {} cron locations in {} mode",
        config.monitor.paths.len(),
        config.monitor.cron_paths.len(),
        if config.action.enforce {
            "ENFORCE"
        } else {
            "DRY-RUN"
        }
    );
    event_loop(receiver, &config)
}

fn event_loop(receiver: Receiver<notify::Result<Event>>, config: &Config) -> Result<()> {
    for event in receiver {
        match event {
            Ok(event) if matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) => {
                for path in event.paths.into_iter().take(MAX_EVENT_PATHS) {
                    if config
                        .monitor
                        .cron_paths
                        .iter()
                        .any(|base| path.starts_with(base))
                    {
                        inspect_cron_references(config)?;
                    } else if let Err(error) = handle(&path, config) {
                        eprintln!("event {}: {error:#}", path.display());
                    }
                }
            }
            Ok(_) => {}
            Err(error) => eprintln!("filesystem watcher error: {error}"),
        }
    }
    bail!("filesystem watcher channel closed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn config_for(uid: u32) -> Config {
        Config {
            monitor: MonitorConfig {
                web_uid: uid,
                paths: vec![std::env::temp_dir()],
                cron_paths: vec![],
            },
            detection: DetectionConfig::default(),
            action: ActionConfig::default(),
            notification: NotificationConfig::default(),
        }
    }

    #[test]
    fn detects_only_a_high_confidence_script_signature() -> Result<()> {
        let path = std::env::temp_dir().join(format!("trsg-test-{}", std::process::id()));
        let mut file = File::create(&path)?;
        writeln!(
            file,
            "#!/usr/bin/perl\nPHPSESSID IO::Socket::INET setsid fork"
        )?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        assert!(inspect(&path, &config_for(fs::metadata(&path)?.uid()))?.is_some());
        fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn refuses_an_unsafe_signal_threshold() {
        let mut config = config_for(1);
        config.detection.signal_threshold = 3;
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn suppresses_duplicate_alerts_within_the_window() {
        let key = format!("dedupe-test-{}", std::process::id());
        assert!(claim_alert(&key, 300));
        assert!(!claim_alert(&key, 300));
    }
}
