# Legacy storage recovery

WinProfile may stop before the dashboard when `%ProgramData%\WinProfile` exists but does not satisfy the protected production-storage contract. This is a fail-closed startup condition, not proof that the files are damaged.

## Safe choices

- **Quit** is the default choice and makes no recovery change. Use it when you are unsure, another WinProfile instance may be running, or the directory is being examined by an incident-response team.
- **Detach and continue** requires an initially unchecked consent control. First close every other WinProfile process in every Windows session, including older versions. WinProfile then renames the exact top-level object to `WinProfile.Legacy.Untrusted.<id>`, creates a new protected `WinProfile` root, writes a terminal audit event there, and only then opens the dashboard.
- **Retry recovery** resumes a recorded transition. Use it after closing an older WinProfile process or resolving the exact sharing or access error shown in the technical details.

The detached object is opaque and untrusted. WinProfile never reads, imports, restores, or changes the permissions of its contents. It is never automatically deleted. Its previous permissions remain unchanged, so it may still be accessible to the same users or software as before. It is not a forensic image and must not be treated as verified backup material.

## If recovery is interrupted

1. Leave `WinProfile.Bootstrap`, `WinProfile.Next.*`, `WinProfile.Legacy.Untrusted.*`, and the current `WinProfile` object unchanged.
2. Close every older WinProfile process in all sessions.
3. Launch the same signed WinProfile build as administrator.
4. Read the displayed technical error, then choose **Retry recovery** once.
5. If the same error returns, quit and preserve the entire ProgramData namespace for an administrator. Do not reset ACLs, rename objects manually, copy legacy journals into the new root, or delete state markers.

Recovery is serialized by a protected kernel lock and checks persistent file identities at every resumable phase. A collision, sharing violation, substituted object, reparse component, invalid marker, ambiguous migration, audit failure, or privilege-restoration failure stops startup without choosing a fallback path.

The lock coordinates versions that implement this recovery protocol. It cannot force an already running binary from an earlier release to participate, so closing all other instances before consent is a required operating condition rather than a guarantee WinProfile can infer from the namespace alone.

## After successful startup

The active `%ProgramData%\WinProfile` root contains only newly trusted product data. The legacy object remains at its unique detached name with its old permissions. Decide retention or disposal under the organization's backup, legal-hold, and incident-response policy; WinProfile deliberately provides no delete or import command for it.
