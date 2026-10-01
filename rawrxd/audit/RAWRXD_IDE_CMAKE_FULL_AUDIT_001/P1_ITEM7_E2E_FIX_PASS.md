# IDE P1 Item 7 — End-to-End Fix Pass

    GATE     = RAWRXD_IDE_P1_ITEM7_E2E_001
    DATE     = 2026-10-01
    HEAD     = 62c883653 (working tree; other session concurrently active)
    STATUS   = PARTIAL — implemented and compile-verified; runtime verification
               blocked by an external build break owned by another session
    VERDICT  = PARTIAL

```
ITEMS_IMPLEMENTED=5
ITEMS_COMPILE_VERIFIED=5/5
ITEMS_RUNTIME_VERIFIED=0/5   (build cannot link — see §3)
BUILD_INFERENCEENGINE=PASS
BUILD_RAWRXD_WIN32IDE=BLOCKED_EXTERNAL
VERDICT=PARTIAL
```

---

## 1. What this pass changed

Five defects, all in the workspace/project group, all closed at the source level
and all proven to compile with a direct `cl.exe` invocation using the shipping
target's own include paths and flags.

| # | Defect | Was | Now |
|---|---|---|---|
| 1 | `settings.schemaVersion` absent; no schema anywhere | 4 competing settings impls, one linked | one schema table, one validator binding, one migration ladder |
| 2 | schema validator unreachable | 114 real lines, sole caller in an uncompiled TU | registered and called on every load and every save |
| 3 | `Session_SetPath` had zero callers | session linked, structurally no-op | deterministic path, load at startup, atomic save at close |
| 4 | `file_watcher.cpp` and `settings_persistence.cpp` include headers that do not exist | uncompilable islands invisible to build and to source listing | both headers written; both TUs compile |
| 5 | `WorkspaceModel::load()` parsed nothing | logged "Loaded workspace config", returned false, overwrote real multi-root docs with single-folder ones every run | real `nlohmann::json` parse with a fail-closed commit policy |

### 1 — Settings authority consolidation

`src/win32app/Win32IDE_Settings.cpp` now carries the single canonical schema
(`kSchema`, 16 keys) with a per-key kind: `PositiveInt`, `Boolean`, `NonEmpty`,
`RootedPath`, `Version`. That table is the authority — it is what validation
checks against, what the unknown-key census is computed from, and what a strict
run drops.

`Settings_RegisterSchema()` binds each entry into
`RawrXD::Core::ConfigurationValidator` as a `ValidationRule` under section
`"settings"`, with a lambda capturing the schema entry. That is what makes the
previously unreachable 114-line validator reachable, and it makes it reachable
*for the real schema* rather than for a synthetic one-key map.

Every key is `required=false`: an absent key means "use the built-in default",
and demanding every key would make a legitimate first-run file invalid.

### 2 — Migration ladder (replaces the JS-only and TODO-`return true` versions)

`kSettingsSchemaVersion = 1`. `Settings_Migrate()` reads
`settings.schemaVersion`; absent means version 0. Version 0 → 1 scopes the
legacy flat keys the original dialog and pre-scoped config files used:

```
fontSize   -> editor.fontSize        serverPath -> lsp.serverPath
theme      -> editor.theme           serverCmd  -> mcp.serverCmd
tabSize    -> editor.tabSize         shell      -> terminal.shell
wordWrap   -> editor.wordWrap        maxResults -> search.maxResults
minimap    -> editor.minimap         maxSteps   -> agent.maxSteps
autoSave   -> editor.autoSave
```

Two policies that matter. A scoped value already present **wins** and the legacy
duplicate is dropped, so migration can never clobber newer config with an older
copy. A file whose version is *newer* than this build supports is **not**
silently downgraded — the load reports it and the migration returns false.

This replaces both prior implementations in substance: `migration-engine.js` was
a browser global with zero consumers, and
`runtime/os/generated/CapabilityMigrationCapability.cpp` had seven methods whose
bodies were a `// TODO` comment, a state assignment, and `return true`.

### 3 — Validation failure policy

Non-strict (default): an invalid value is reported and counted; the value stays
visible so a user can see and fix it.

Strict (`RAWRXD_SETTINGS_STRICT=1`): the key is dropped, and `Settings_Persist`
refuses to write at all (`saveBlockedByValidation=1`), so a strict run cannot
persist a bad value over a good file.

The drop is computed by re-checking each schema-typed key against the schema
table directly. It deliberately does **not** parse the validator's error strings
— the schema table is the authority and the message is a rendering of it.

### 4 — Session persistence

New `src/win32app/Win32IDE_Session.h` with a `SessionDiagnostics` surface whose
fields again initialise to non-healthy. The session file resolves to the *same
directory* as the settings file (`<settings dir>\session.state`), so "my
configuration" is one location rather than two conventions to discover.

`WM_CREATE` calls `Session_Load()`; `WM_CLOSE` calls `Session_Persist()`. The
save is atomic (`ReplaceFileA`, `MoveFileExA` fallback) because a truncated
session silently drops the user's open editors on the next start.
`DoFileOpen` now calls `Session_AddFile`, which is the call that makes the
tracking reachable at all.

### 5 — Absent headers

`src/core/file_watcher.h` and `src/core/settings_persistence.h` were written from
their implementations, not invented: every member and enum value in
`file_watcher.h` is one that `file_watcher.cpp` already used, and
`SettingsPersistence` mirrors the four methods `settings_persistence.cpp`
defines plus the accessor the class needs.

`settings_persistence.h` carries an explicit note that this store is **not** the
IDE's product settings authority — `Win32IDE_Settings` is, and wiring a second
one into the IDE is the fragmentation this pass is removing.

### 6 — Multi-root workspace load

`WorkspaceModel::load()` was the worst stub shape in the tree: it opened the
file, closed it, printed `[WorkspaceModel] Loaded workspace config`, and
returned `false` with the comment `// Would parse JSON here`. Because it returned
false, `initialize()` took the "create default" branch and overwrote a real
multi-root document with a single-folder one on **every run**.

It now parses with `nlohmann::json` (already vendored, already used by
`settings_persistence.cpp`), restoring name, folders (with a derived display
name for secondary roots), open files, panel layout, expanded folders, and the
active build/debug config names. Failure policy is fail-closed on the
in-memory state: an unparsable file, a schema error, or a document with **zero
folders** all leave the previous config untouched and return false, so a
subsequent save cannot write a truncated workspace over a good one.

---

## 2. Compile verification

Every changed translation unit compiled with `cl.exe` using the shipping
target's own include paths and flags (`/std:c++17 /MT /EHsc`, `include/`,
`src/`, `src/core/`, `src/win32app/`, `3rdparty/`, VulkanSDK).

```
SETTINGS_TU_EXIT=0          Win32IDE_Settings.cpp   (schema + migration + validation)
SESSION_TU_EXIT=0            Win32IDE_Session.cpp    (new header + new impl)
FILEWATCHER_TU_EXIT=0        core/file_watcher.cpp   (was uncompilable)
SETTINGSPERSIST_TU_EXIT=0    core/settings_persistence.cpp  (was uncompilable)
WORKSPACE_TU_EXIT=0          core/workspace_model.cpp (real JSON load)
```

`InferenceEngine.vcxproj` — the target that owns the Deep2 GPU sources — now
builds clean and links `InferenceEngine.lib`. The 18 C2664 errors are gone: the
`DeviceBuf` migration in `Deep2Engine_GpuForward.cpp` was completed by its owner
while this pass was running, and a later `ProjectionBisectResult::type` addition
landed in `Deep2Engine.h` a few seconds after a torn read had reported it missing.

```
FULL_INFERENCEENGINE_BUILD=PASS
RAWRXD_GPU_DLWVECTOR_CONTRACT_AUDIT_001_STATUS=CONSISTENT
GPU_API_STATE=CONCURRENTLY_UNSTABLE   (see §3)
```

---

## 3. What blocks the product link — and why this lane did not shim it

`RawrXD-Win32IDE.vcxproj` does not build. The break is in
`src/agentic/GitSafetyAuthorityTools.h`, which belongs to a session actively
implementing the git-safety IDE surface. Three findings, all measured:

1. **The file cannot be written.** It has been held with an exclusive handle for
   the entire duration of this pass — `mtime` frozen at 17:40:38 while every
   `File.Open(..., ReadWrite, None)` attempt returned
   *"used by another process"* for over 20 minutes of retries. A concurrent
   `codex-windows-sandbox-service` is the holder.

2. **The declaration has two errors, not one.** Line 119 reads:

   ```cpp
   GitBindingReport InstallGitSafetyIdeSurface(
       ::RawrXD::Agentic::AgentToolRegistry& registry, ...);
   ```

   The canonical namespace is lowercase `rawrxd::agentic`
   (`include/agentic/AgentToolRegistry.h:18-19`,
   `src/agentic/GitSafetyAuthority.h:62-63`) — and the class is `ToolRegistry`
   (`include/agentic/AgentToolRegistry.h:102`), not `AgentToolRegistry`. An
   attempt to alias the name hit exactly this: `'AgentToolRegistry' is not a
   member of 'rawrxd::agentic'`.

3. **`InstallGitSafetyIdeSurface` has no definition anywhere in the repository.**
   The declaration and the call sites (`main_win32.cpp:609`,
   `Win32IDE_GitPanel.cpp:323`) have landed; the implementation has not. The
   `registry` argument at `main_win32.cpp:609` is not even declared in that
   translation unit.

A namespace alias was trialled and then **reverted**. It could not have fixed
finding 3, and against finding 2 it was itself wrong. Leaving a
plausible-looking compatibility header in the tree to paper over another
session's unfinished feature is exactly the "unreachable source presented as
implemented" failure this audit exists to prevent, so the tree was returned to
its pre-shim state and verified clean.

```
GIT_SAFETY_SURFACE_STATE=INCOMPLETE_DECLARED_NOT_DEFINED
GIT_SAFETY_SURFACE_FILE_WRITE=BLOCKED_EXCLUSIVE_LOCK_HELD_BY_OTHER_SESSION
BUILD_RAWRXD_WIN32IDE=BLOCKED_EXTERNAL
OWNER=other_session
SHIM_LEFT_IN_TREE=0
```

**Unblock is one line plus one definition**, both in the locked file's lane:
correct line 119 to `::rawrxd::agentic::ToolRegistry&`, and define
`InstallGitSafetyIdeSurface` in `GitSafetyAuthorityTools.cpp`.

---

## 4. Honest ledger

```
RAWRXD_IDE_P1_ITEM7_E2E_001=PARTIAL

SETTINGS_AUTHORITY=CONSOLIDATED_SOURCE
  schema_keys=16
  schema_validator=REACHABLE (ConfigurationValidator registered and called)
  migration_ladder=v0->v1 (11 legacy key mappings)
  newer_than_build=REFUSED (not silently downgraded)
  strict_mode=drops invalid keys and blocks the write

SESSION_PERSISTENCE=IMPLEMENTED_SOURCE
  path=resolved beside the settings file
  load=WM_CREATE      save=WM_CLOSE (atomic)
  tracking=DoFileOpen -> Session_AddFile

HEADERS_PRESENT=2  (file_watcher.h, settings_persistence.h — both TUs now compile)
WORKSPACE_MULTIROOT_LOAD=IMPLEMENTED_SOURCE (fail-closed, zero-folder document refused)

COMPILE_VERIFIED=5/5
INFERENCEENGINE_BUILD=PASS
RAWRXD_WIN32IDE_BUILD=BLOCKED_EXTERNAL
RUNTIME_VERIFIED_THIS_PASS=0/5

CARRIED_FORWARD_FROM_RAWRXD_SETTINGS_PERSISTENCE_001=PASS (4 runs, unchanged)
```

### Not attempted this pass, and why

Four items in the ordered list remain undone: task system CMake/product
integration with a real `loadConfig`/`saveConfig`, launch configurations,
filesystem-watcher product-path wiring, and replacing the `IDEConfig` one-line
stub. All four need `RawrXD-Win32IDE` to link before they can be runtime
verified, and all four would be unverifiable code if written now. The
compile-only ones that were written anyway — the two absent headers — were
written because they were uncompilable *islands* whose absence was itself the
defect, and each is now independently provable.

### Standing environmental hazard

`da2fec4b0` swept 1117 files, including three settings sources, during the
previous gate. That single-writer violation is unfixed, and this pass hit its
mirror image: a session holding an exclusive lock on a file that four
translation units need, with a feature half-landed inside it. Until
`SingleWriterAuthority` is enforceable at the file level, any lane can be
blocked by another lane's open editor.
