# tiny-rust-security-guard

A small, conservative Linux host-security guard written in Rust. It watches a few high-risk writable directories, detects only high-confidence suspicious payloads, optionally quarantines them, and can notify Discord.

It is intentionally **not** marketed as a general antivirus or RCE prevention system. It is a low-overhead defense-in-depth control for a specific operational failure mode: a public runtime account dropping an executable payload in a temporary directory and referencing it from cron.

## Safety model

- Uses event-driven filesystem notifications after one startup scan; it does not repeatedly crawl disks.
- Defaults to `enforce = false`: it never changes a file until explicitly enabled.
- De-duplicates identical pathname/hash alerts for five minutes, so create/chmod watcher bursts do not spam Discord.
- Quarantines only files owned by the configured runtime UID when either a known SHA-256 matches or a strict executable loader signature matches at least four independent indicators.
- Quarantine is an atomic rename. If the quarantine directory is on another filesystem, the action fails safely instead of copying and deleting.
- Reads cron spools only to find a suspicious payload referenced from a watched directory. It never rewrites a crontab.
- The Discord webhook is read only from an environment variable, never the TOML config.

## What it cannot do

It cannot repair the application vulnerability, remove a webshell elsewhere, protect against root, or prove a clean host. Use it alongside patching, minimal PHP permissions, secret rotation, audit logging, and backups.

## Install from a release

Download the matching Linux binary from GitHub Releases:

- `aarch64-unknown-linux-musl` for ARM64 servers.
- `x86_64-unknown-linux-musl` for Intel/AMD64 servers.

Verify `SHA256SUMS` before installing. Then:

```bash
sudo install -m 0755 tiny-rust-security-guard /usr/local/sbin/tiny-rust-security-guard
sudo install -d -m 0750 /etc/tiny-rust-security-guard /var/lib/tiny-rust-security-guard/quarantine
sudo install -m 0640 config.example.toml /etc/tiny-rust-security-guard/config.toml
sudo install -m 0600 deploy/secret.env.example /etc/tiny-rust-security-guard/secret.env
sudo install -m 0644 deploy/tiny-rust-security-guard.service /etc/systemd/system/tiny-rust-security-guard.service
```

Set `TRSG_DISCORD_WEBHOOK_URL` in `/etc/tiny-rust-security-guard/secret.env`, set the actual `web_uid` in `config.toml`, then test only notifications:

```bash
sudo systemctl daemon-reload
sudo /usr/local/sbin/tiny-rust-security-guard --config /etc/tiny-rust-security-guard/config.toml test-notification
sudo systemctl enable --now tiny-rust-security-guard
```

Keep `enforce = false` for at least a day. Review `journalctl -u tiny-rust-security-guard -f`, then choose whether to enable quarantine.

## Development

```bash
cargo fmt --check
cargo test
cargo clippy -- -D warnings
cargo build --release
```

## Releases

Pushing a `v*` tag runs GitHub Actions and creates release assets for Linux x86_64 and ARM64, along with `SHA256SUMS`.
