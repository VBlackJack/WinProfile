# WinProfile 2026.819.0

WinProfile 2026.819.0 is the first public release of the Windows profile inspection, repair, and selective migration suite.

## Highlights

- Profile repairs are transactional: every affected registry key is snapshotted, mutations are verified, and failures trigger rollback.
- Repair suggestions are enabled only by their exact matching anomaly; unrelated warnings do not preselect a destructive action.
- Migrations traverse from verified root handles with relative `NtCreateFile` calls. They refuse junction traversal, overwrites, overlapping roots including `SUBST` aliases, and concurrent source or destination mutation.
- Every copied file is verified with SHA-256. Cancellation is checked between 1 MiB chunks and verification reads, and rollback removes only transaction-created data through retained handles.
- Profiles reported as loaded cannot be repaired or used as migration sources. Window closing is blocked during repair and requests cancellation plus rollback during migration.
- Administrative operations require an embedded elevation manifest, a live elevation check, and explicit operator confirmation.
- The audit journal is serialized, durable, bounded, rotated, and exportable without overwriting an existing export.
- Long-running work runs outside the Slint event loop, with keyboard navigation and English/French catalog validation.
- The About dialog includes Slint's official `AboutSlint` attribution widget.

## Release integrity

- GitHub Actions references are pinned to full commit SHAs, and dependency auditing also runs on a weekly schedule.
- Regular CI builds and verifies the MSVC executable, PE metadata, elevation manifest, and checksum without uploading an unsigned artifact.
- The tag workflow repeats formatting, linting, tests, dependency auditing, build, and PE verification before signing.
- Publication occurs only after timestamped signing succeeds and Windows reports the Authenticode status as `Valid`.

## Installation and verification

1. Download `winprofile-admin.exe` and `SHA256SUMS.txt` from this release.
2. Verify that the SHA-256 digest matches `SHA256SUMS.txt`.
3. Verify that the Authenticode status is `Valid` and inspect the signer before launching the executable.
4. Run the executable on a supported Windows system and approve the administrator elevation prompt.

The executable is not published if signing, timestamping, Authenticode verification, PE metadata verification, tests, or dependency auditing fails.

## Operational caution

Profile repair, Restart Manager shutdown, and TrustedInstaller console launch are expert operations. Use a tested backup and validate the workflow on a disposable machine before operating on production profiles.

Sign the source user out and scan again before migration. File handles stabilize each file while it is copied, but WinProfile does not create a VSS snapshot of the complete tree; directory membership and cross-file state can therefore change if another process modifies the offline profile. This release makes no compatibility claim for UNC/SMB or ReFS migration paths.
