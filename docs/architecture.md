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

The source and destination are canonicalized before mutation. Equal, nested, or ancestor roots are rejected. Every directory and file created by the transaction is recorded. Files use create-new semantics and are read back for SHA-256 verification. The receipt includes file count, byte count, and a deterministic aggregate manifest hash. Failure or cancellation removes only entries created by the current transaction and never deletes pre-existing destination content.

## Audit integrity

Audit file operations share a process-wide lock. Each JSON event is serialized before the lock, appended, flushed, and synchronized before it enters the display buffer. Invalid existing JSON prevents startup rather than silently discarding history. Export uses a unique name and verifies byte length.

## Elevation and packaging

The PE manifest requests administrator elevation. Runtime token elevation is checked again before destructive operations. GNU builds embed the manifest through a pure Rust COFF object. The official MSVC release build also compiles `resources/version.rc`. Authenticode signing remains an external publication credential and must be verified before release.
