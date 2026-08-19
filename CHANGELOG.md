# Changelog

## 2026.819.0 - Unreleased remediation

### Security

- Embedded a mandatory administrator manifest for GNU and MSVC builds.
- Replaced unsafe raw predefined registry handles with a typed root selector.
- Restored every enabled token privilege and rejected unavailable privileges.
- Removed the invalid generic ACL reset and the non-service broker implementation.
- Made TrustedInstaller service, token, session, environment, and process failures fail closed.

### Reliability

- Added mandatory registry snapshots, non-destructive key renames, verification, and rollback.
- Added transactional, cancellable, non-overwriting migration with SHA-256 verification.
- Made scanner degradation visible instead of silently skipping unreadable state.
- Serialized and bounded the durable audit journal and implemented verified export.
- Moved long-running operations off the Slint event loop.

### User experience

- Added keyboard-operable navigation, virtualized lists, explicit confirmations, safe defaults, and migration cancellation.
- Externalized user-facing text into parity-validated English and French catalogs.
- Increased secondary-text contrast and corrected status localization.

### Engineering

- Added regression tests, a tracked lockfile, pinned Rust toolchain, CI gates, and architecture documentation.
