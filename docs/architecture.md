# Architecture and trust boundaries

## Components

`app-ui` owns the Slint event loop, confirmation workflow, and worker dispatch. It never performs scanning, repair, migration, export, or token acquisition on the UI thread.

`core-profiles` owns profile discovery, anomaly classification, repair plans, and migration transactions. It depends on the platform and audit crates but has no UI dependency.

`audit-journal` owns durable JSON-lines logging, rotation, exports, registry snapshots, and snapshot restoration.

`platform-win32` is the only layer that calls low-level Windows APIs. Handles use RAII wrappers, predefined registry roots are typed, and privilege changes are scoped.

`webbrowser-shim` is a narrow compatibility adapter for Slint's Windows backend. It replaces a transitive dependency on a separately packaged MinGW `shlwapi` archive with `ShellExecuteW` from the Windows bindings already used by the workspace. WinProfile does not currently expose a browser-opening control.

## Repair transaction

1. Validate the selected SID, live `HKEY_USERS` state, registry key, profile path, and requested actions.
2. For dry-run, audit the validated plan and stop.
3. Capture every registry key that may be changed.
4. Audit transaction start.
5. Optionally request graceful closure of `NTUSER.DAT` lockers.
6. Preserve an existing canonical key under a unique timestamped name.
7. Rename the `.bak` key and apply selected State/RefCount changes.
8. Re-read the canonical key and verify every postcondition.
9. Audit success. If this write fails, roll back.
10. On any execution error, reverse renames and restore all snapshots.

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
