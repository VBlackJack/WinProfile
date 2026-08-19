# WinProfile 2026.819.0

WinProfile 2026.819.0 is the first public release of the Windows profile inspection, repair, and selective migration suite.

## Highlights

- Profile repairs are transactional: every affected registry key is snapshotted, mutations are verified, and failures trigger rollback.
- Migrations refuse overwrites, reparse points, and overlapping roots; copied files are verified with SHA-256 and cancellation removes only transaction-created data.
- Administrative operations require an embedded elevation manifest, a live elevation check, and explicit operator confirmation.
- The audit journal is serialized, durable, bounded, rotated, and exportable without overwriting an existing export.
- Long-running work runs outside the Slint event loop, with keyboard navigation and English/French catalog validation.

## Installation and verification

1. Download `winprofile-admin.exe` and `SHA256SUMS.txt` from this release.
2. Verify that the SHA-256 digest matches `SHA256SUMS.txt`.
3. Verify that the Authenticode status is `Valid` and inspect the signer before launching the executable.
4. Run the executable on a supported Windows system and approve the administrator elevation prompt.

The executable is intentionally not published if signing, timestamping, PE metadata verification, tests, or dependency auditing fails.

## Operational caution

Profile repair, Restart Manager shutdown, and TrustedInstaller console launch are expert operations. Use a tested backup and validate the workflow on a disposable machine before operating on production profiles.
