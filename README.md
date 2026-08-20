# WinProfile Suite

WinProfile is a Windows-only administrative application for inspecting user profiles, repairing `ProfileList` registry state, and performing selective file migrations.

## Safety model

- The executable embeds a `requireAdministrator` manifest on GNU and MSVC builds.
- Repairs are disabled until a profile and at least one action are selected.
- Repair suggestions are exact: `.bak` repair is suggested only for a `.bak` anomaly, state reset only for a dirty state mask, and hive unlock only for a locked `NTUSER.DAT`.
- A dry-run performs the same preflight checks without mutating state.
- Registry mutations require durable snapshots and are verified after execution.
- A failed repair restores the captured registry state and records the outcome.
- A profile reported as loaded cannot be repaired or used as a migration source; sign the user out and scan again first.
- Migration opens each path component with `NtCreateFile` relative to a verified root or parent handle and refuses junction traversal, overlapping roots including `SUBST` aliases, and existing destination files.
- Source and destination file handles deny concurrent writers and deletion. Every copied file is SHA-256 verified, and cancellation is checked between 1 MiB chunks and during verification.
- Closing the window is blocked during repair. During migration, closing requests cancellation and waits for success or rollback before hiding the window.
- Migration rollback removes only files and directories created by the current transaction, using the handles retained by that transaction.
- Audit writes are serialized, flushed to disk, bounded to 10 MiB, and rotated across five archives.
- Older permissive `%ProgramData%\WinProfile` storage is never trusted or repaired in place. Before any service starts, WinProfile asks whether to detach the whole opaque object under a unique `WinProfile.Legacy.Untrusted.*` name and create a new protected root.
- Automated ACL reset is intentionally absent: WinProfile has no generic policy capable of reconstructing an account-specific DACL safely.
- The former named-pipe broker was removed because it was not installed or operated as a real Windows service.
- The About dialog includes Slint's official `AboutSlint` attribution widget.

Closing applications through Restart Manager and launching a TrustedInstaller console are destructive expert operations. Both require elevation, explicit confirmation, and an audit event.

## Build and test

The portable `rust-toolchain.toml` pins Rust 1.97.1. Install the exact Windows GNU toolchain used for local development:

```powershell
rustup toolchain install 1.97.1-x86_64-pc-windows-gnu --profile minimal --component clippy,rustfmt
```

Run every local gate with the explicit host toolchain selector:

```powershell
cargo +1.97.1-x86_64-pc-windows-gnu fmt --all -- --check
cargo +1.97.1-x86_64-pc-windows-gnu clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo +1.97.1-x86_64-pc-windows-gnu test --workspace --all-features --locked
cargo +1.97.1-x86_64-pc-windows-gnu build --workspace --all-targets --release --locked
```

Regular CI runs for `main`, pull requests, manual dispatches, and a weekly dependency audit. Every GitHub Action is pinned to a full commit SHA. CI builds and verifies the MSVC executable, PE metadata, elevation manifest, and checksum, but uploads no artifact.

The tag-triggered release workflow repeats the quality gates, signs and timestamps the MSVC executable, and requires `Get-AuthenticodeSignature` to report `Valid` before publishing the executable and checksum. Missing signing secrets or any failed gate prevents publication. GNU builds embed the mandatory elevation manifest without requiring `windres`.

`cargo audit` currently reports no known vulnerability. It does report four unmaintained transitive crates (`bincode`, `paste`, `rustybuzz`, and `ttf-parser`) pulled into the lockfile by Slint 1.17.1. These warnings are accepted temporarily and must be re-evaluated whenever Slint is updated.

## Data locations

Production data is stored below `%ProgramData%\WinProfile`:

- `Snapshots`: binary registry snapshots and JSON metadata;
- `audit_log.jsonl`: durable JSON-lines audit journal;
- `audit_log.jsonl.1` through `.5`: rotated archives;
- `Exports`: non-overwriting audit exports.

If an older permissive root is found, its contents are not opened or imported. Close every other WinProfile instance before consenting: a binary from an earlier release does not know the new recovery lock. With explicit consent, WinProfile renames only that exact top-level object to `%ProgramData%\WinProfile.Legacy.Untrusted.<id>` and creates a new protected `%ProgramData%\WinProfile`. The detached object retains its previous permissions, is neither a trusted backup nor a forensic image, and is never automatically deleted. See [Legacy storage recovery](docs/storage-recovery.md).

## Recovery

A pre-repair canonical profile key is renamed to a timestamped `.pre-repair-*` key instead of being deleted. Registry snapshots remain available in `%ProgramData%\WinProfile\Snapshots`. If automatic rollback reports a failure, stop further repairs and preserve the audit journal and snapshots for manual recovery.

An interrupted legacy-storage transition resumes from a protected sibling journal on the next launch. Do not rename, delete, or change permissions on `WinProfile.Bootstrap`, `WinProfile.Next.*`, or `WinProfile.Legacy.Untrusted.*` while recovery is pending.

## Release signing

Source code cannot manufacture a trusted signing identity. Release signing requires an organization-controlled PFX certificate and timestamp service; the CI release gate must receive those credentials from protected secrets before publishing an artifact.

Licensed under Apache-2.0. See [LICENSE](LICENSE).
