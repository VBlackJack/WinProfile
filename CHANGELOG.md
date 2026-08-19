# Changelog

All notable changes to this project are documented in this file.

## [2026.819.0] - 2026-08-19

### Added

- Added Windows profile discovery with explicit anomaly reporting.
- Added transactional profile repair with registry snapshots, postcondition verification, and rollback.
- Added cancellable, non-overwriting profile migration with per-file SHA-256 verification.
- Added a bounded, durable JSON-lines audit journal with verified exports and rotation.
- Added English and French user interfaces with catalog parity validation.
- Added pinned Rust tooling, regression tests, CI quality gates, and MSVC packaging.

### Changed

- Moved scanning, repair, migration, export, and token acquisition off the Slint event loop.
- Replaced raw predefined registry handles with typed roots and scoped privilege guards.
- Made destructive actions require elevation, explicit selection, and confirmation.
- Marked CI package artifacts as unsigned build evidence until the release signing workflow succeeds.

### Fixed

- Prevented partial registry repair and migration results from being reported as successful.
- Preserved canonical profile keys during `.bak` repair instead of deleting them.
- Rejected unavailable token privileges, invalid console sessions, reparse points, overlapping migration roots, and existing destination files.
- Made scanner, audit, Restart Manager, localization, and TrustedInstaller failures visible and fail closed.
- Removed the unsafe generic ACL reset and the incomplete named-pipe broker.
- Added keyboard-operable navigation, virtualized lists, migration cancellation, and accessible labels.

[2026.819.0]: https://github.com/VBlackJack/WinProfile/releases/tag/v2026.819.0
