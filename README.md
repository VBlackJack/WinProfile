# WinProfile Suite

WinProfile is a Windows-only administrative application for inspecting user profiles, repairing `ProfileList` registry state, and performing selective file migrations.

## Safety model

- The executable embeds a `requireAdministrator` manifest on GNU and MSVC builds.
- Repairs are disabled until a profile and at least one action are selected.
- A dry-run performs the same preflight checks without mutating state.
- Registry mutations require durable snapshots and are verified after execution.
- A failed repair restores the captured registry state and records the outcome.
- Migration refuses reparse points, overlapping roots, and existing destination files.
- Every copied file is SHA-256 verified; cancellation removes all files and directories created by the operation.
- Audit writes are serialized, flushed to disk, bounded to 10 MiB, and rotated across five archives.
- Automated ACL reset is intentionally absent: WinProfile has no generic policy capable of reconstructing an account-specific DACL safely.
- The former named-pipe broker was removed because it was not installed or operated as a real Windows service.

Closing applications through Restart Manager and launching a TrustedInstaller console are destructive expert operations. Both require elevation, explicit confirmation, and an audit event.

## Build and test

The repository pins Rust 1.97.1. On Windows:

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo build --workspace --all-targets --release --locked
```

The official packaging job uses the MSVC toolchain so the executable contains both the elevation manifest and Windows version metadata. Its downloadable artifact is explicitly named `UNSIGNED`; it is build evidence, not a publishable release. GNU builds embed the mandatory elevation manifest without requiring `windres`.

`cargo audit` currently reports no known vulnerability. It does report four unmaintained transitive crates (`bincode`, `paste`, `rustybuzz`, and `ttf-parser`) pulled into the lockfile by Slint 1.17.1, the latest available Slint release. These warnings are accepted temporarily and must be re-evaluated whenever Slint is updated.

## Data locations

Production data is stored below `%ProgramData%\WinProfile`:

- `Snapshots`: binary registry snapshots and JSON metadata;
- `audit_log.jsonl`: durable JSON-lines audit journal;
- `audit_log.jsonl.1` through `.5`: rotated archives;
- `Exports`: non-overwriting audit exports.

## Recovery

A pre-repair canonical profile key is renamed to a timestamped `.pre-repair-*` key instead of being deleted. Registry snapshots remain available in `%ProgramData%\WinProfile\Snapshots`. If automatic rollback reports a failure, stop further repairs and preserve the audit journal and snapshots for manual recovery.

## Release signing

Source code cannot manufacture a trusted signing identity. Release signing requires an organization-controlled PFX certificate and timestamp service; the CI release gate must receive those credentials from protected secrets before publishing an artifact.

Licensed under Apache-2.0. See [LICENSE](LICENSE).
