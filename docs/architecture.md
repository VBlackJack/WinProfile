# Architecture and trust boundaries

## Components

`app-ui` owns the Slint event loop, confirmation workflow, and worker dispatch. It never performs scanning, repair, migration, export, or token acquisition on the UI thread.

`core-profiles` owns profile discovery, anomaly classification, repair plans, and migration transactions. It depends on the platform and audit crates but has no UI dependency.

`audit-journal` owns durable JSON-lines logging, rotation, exports, registry snapshots, and snapshot restoration.

`platform-win32` is the only layer that calls low-level Windows APIs. Handles use RAII wrappers, predefined registry roots are typed, and privilege changes are scoped.

`webbrowser-shim` is a narrow compatibility adapter for Slint's Windows backend. It replaces a transitive dependency on a separately packaged MinGW `shlwapi` archive with `ShellExecuteW` from the Windows bindings already used by the workspace. WinProfile does not currently expose a browser-opening control.

## Legacy storage boundary

No audit, snapshot, controller, scan, or profile service is created until startup has classified `%ProgramData%\WinProfile`. A canonical root is accepted only through its retained handle, exact protected SYSTEM/Administrators DACL, owner, type, and non-reparse checks. A legacy root is treated as one opaque, untrusted namespace object: its children, journals, and snapshots are never enumerated, parsed, imported, restored, or deleted.

Recovery requires explicit consent in the top-level Slint startup view. Quit and window close perform no recovery mutation. After consent, a protected sibling `%ProgramData%\WinProfile.Bootstrap` directory and an exclusive share-zero lock serialize all instances. ProgramData, bootstrap, the legacy object, and the pre-created replacement root are opened relative to verified directory handles. Persistent `FILE_ID_INFO` identities detect substitution. The exact legacy object is renamed with `NtSetInformationFile(FileRenameInformation)`, a non-null `RootDirectory` handle, a validated single-component relative name, and replacement disabled. Reparse traversal and absolute-path fallback are absent; a junction at the exact legacy name is detached as a junction without opening its target.

The startup check runs after the Slint event loop begins, so the blocking recovery view is painted and responsive before services can be constructed. A fresh detachment requires an initially unchecked consent control; durable recovery resumes are exempt. The view exposes the same `AboutSlint` attribution as normal operation.

The append-only bootstrap phases are synchronized before namespace cutovers and advance monotonically through `Prepared`, `Detached`, `RootReady`, `AuditPending`, and `Done`. After `Detached`, recovery never moves the untrusted object back to the production name. `SeBackupPrivilege` and `SeRestorePrivilege` are scoped only around namespace work and explicitly restored, with operation and restore failures preserved together. A terminal event is synchronized in the new journal before `Done`; only then is the controller constructed. The logger and snapshot engine retain the same validated `StorageRoot` token.

The detached name is `WinProfile.Legacy.Untrusted.<random-id>`. Its old permissions are deliberately unchanged, so it may remain accessible to principals that could access it before detachment. It is not a forensic copy and is never automatically removed. The bootstrap lock coordinates this and later releases only; it cannot retroactively coordinate an older binary that does not implement the lock. Operators must close every other WinProfile instance before fresh consent. Operator handling is documented in [storage recovery](storage-recovery.md).

## Repair transaction

1. For a non-dry repair, acquire the exclusive operation guard before any preflight or effect.
2. Reject the historical `unlock_hive` contract. Restart Manager is inspection-only and no product path asks it to stop or restart a process.
3. Reject an empty registry-action selection, then validate the absolute profile path and inspect `NTUSER.DAT`. Measured application/PID blockers produce `ManualCloseRequired`; any inspection error is fail-closed.
4. Validate the selected SID, live `HKEY_USERS` state, registry key, profile path, and requested registry actions.
5. Re-inspect `NTUSER.DAT` immediately before either a dry-run success event or snapshot/mutation. This core check is independent of the possibly stale UI scan.
6. For dry-run, audit the validated plan and stop without snapshot or mutation.
7. Capture every registry key that may be changed and audit transaction start.
8. Preserve an existing canonical key under a unique timestamped name.
9. Rename the `.bak` key and apply selected State/RefCount changes.
10. Re-read the canonical key and verify every postcondition.
11. Audit success. If this write fails, roll back.
12. On any execution error, reverse renames and restore all snapshots.

The UI preserves the measured blocker strings, including application and PID, without parsing or truncating their accessibility labels. Repair remains disabled until the operator saves work, closes the listed applications manually, and obtains a new scan without a lock or inspection-failure anomaly. There is no process-shutdown confirmation and no claim that application state can be rolled back.

The tool does not invent filesystem ACLs. Account-specific ownership or DACL remediation requires a separately defined policy and is outside this transaction.

## Migration transaction

Migration is permitted only for an unloaded source profile. The controller rejects a loaded profile before elevation, operation registration, or worker dispatch.

Filesystem traversal is rooted in opened directory handles. Each component is opened with `NtCreateFile`, `OBJECT_ATTRIBUTES.RootDirectory`, and `FILE_OPEN_REPARSE_POINT`, then inspected through the returned handle before use. Directory enumeration and child opens remain relative to those verified handles. Source and destination ancestry is compared by volume and file identity, so path aliases such as `SUBST` cannot bypass equal, nested, or ancestor-root rejection.

Destination files use `FILE_CREATE` and therefore never overwrite existing content. Source and destination file handles grant only `FILE_SHARE_READ`, blocking concurrent write and delete opens while a file is copied and verified. SHA-256 is accumulated from the opened source handle; the destination is rewound and rehashed through the exact created handle, with its byte length checked before it enters the deterministic receipt manifest.

The transaction retains handles to every created object. A delete-on-failure guard covers errors before transaction registration, and rollback consumes those handles from children to parents without resolving paths again. Cancellation is checked between one-megabyte chunks, during destination verification, and immediately before terminal success logging.

This is not an atomic point-in-time tree snapshot: WinProfile does not use VSS, so different files can represent different instants even though each individual file is protected while open. UNC/SMB and ReFS behavior, denied-ACL recovery, backup/restore privileges, and `FILE_OPEN_FOR_BACKUP_INTENT` are not measured and are not part of the current guarantee.

## Audit integrity

Audit file operations share a process-wide lock. Each JSON event is serialized before the lock, appended, flushed, and synchronized before it enters the display buffer. Invalid existing JSON prevents startup rather than silently discarding history. Export uses a unique name and verifies byte length.

## Elevation and packaging

The PE manifest requests administrator elevation. Runtime token elevation is checked again before destructive operations. GNU builds embed the manifest through a pure Rust COFF object. The official MSVC release build also compiles `resources/version.rc`. Authenticode signing remains an external publication credential and must be verified before release.

## Accessibility boundary

The Slint tree uses navigation and main landmarks, list/list-item semantics for profile and audit collections, named progress values, and polite/assertive live regions for changing status. Technical strings remain byte-for-byte visible through a read-only selectable details panel rather than being localized or irreversibly elided. Keyboard oracles cover the recovery Quit default, English/French selection with Enter and Space, and Escape dismissal with safe focus restoration. Theme colors used for secondary, accent, error, and maintenance text are runtime contrast-tested against their actual backgrounds; the 12 px body minimum is a product readability rule, not presented as a WCAG font-size threshold.

These automated semantics do not prove the complete Windows accessibility stack. Narrator speech order, Accessibility Insights findings, high-contrast behavior, and layout at 150% DPI still require an elevated Windows release-VM pass.
