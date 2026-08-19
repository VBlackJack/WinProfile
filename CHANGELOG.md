# Changelog

All notable changes to this project are documented in this file.

## [2026.819.0] - 2026-08-19

### Added

- Added Windows profile discovery with explicit anomaly reporting.
- Added transactional profile repair with registry snapshots, postcondition verification, and rollback.
- Added cancellable, non-overwriting profile migration with per-file SHA-256 verification.
- Added handle-rooted migration with relative `NtCreateFile` traversal, junction checks, `SUBST` alias overlap detection, and retained rollback handles.
- Added a bounded, durable JSON-lines audit journal with verified exports and rotation.
- Added English and French user interfaces with catalog parity validation.
- Added an About dialog with Slint's official `AboutSlint` attribution widget.
- Added pinned Rust tooling, regression tests, SHA-pinned CI quality gates, weekly dependency auditing, and MSVC packaging verification.

### Changed

- Moved scanning, repair, migration, export, and token acquisition off the Slint event loop.
- Replaced raw predefined registry handles with typed roots and scoped privilege guards.
- Made destructive actions require elevation, explicit selection, and confirmation.
- Limited automatic repair suggestions to their exact matching anomaly types.
- Blocked repair and migration for profiles reported as loaded.
- Made window closing wait for an active repair or request migration cancellation and rollback.
- Removed unsigned artifact uploads from regular CI; only a tag workflow with a valid Authenticode signature can publish release files.

### Fixed

- Prevented partial registry repair and migration results from being reported as successful.
- Preserved canonical profile keys during `.bak` repair instead of deleting them.
- Rejected unavailable token privileges, invalid console sessions, junction traversal, overlapping migration roots including `SUBST` aliases, existing destination files, and concurrent file mutation.
- Checked migration cancellation between copy chunks and verification reads, with exact-handle rollback of transaction-created data.
- Made scanner, audit, Restart Manager, localization, and TrustedInstaller failures visible and fail closed.
- Removed the unsafe generic ACL reset and the incomplete named-pipe broker.
- Added keyboard-operable navigation, virtualized lists, migration cancellation, and accessible labels.

[2026.819.0]: https://github.com/VBlackJack/WinProfile/releases/tag/v2026.819.0
