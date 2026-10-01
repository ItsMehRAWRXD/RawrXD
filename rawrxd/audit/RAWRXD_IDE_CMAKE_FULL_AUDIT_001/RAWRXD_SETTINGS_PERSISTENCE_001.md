# RAWRXD_SETTINGS_PERSISTENCE_001

    GATE       = RAWRXD_SETTINGS_PERSISTENCE_001
    DATE       = 2026-10-01
    HEAD       = acb63e871 (working tree; other session concurrently active)
    TARGET     = RawrXD-Win32IDE
    BUILD      = rawrxd/build_ide_audit, MSBuild 17.14.51+25f168cee, Release
    BINARY     = rawrxd/build_ide_audit/bin/Release/RawrXD-Win32IDE.exe
    SHA256     = 8B623935FFE8D4F88BCBFD9C6E311BEC4424AFE88916036DABCA151391A62778
    EVIDENCE   = audit/RAWRXD_IDE_CMAKE_FULL_AUDIT_001/SETTINGS_PERSISTENCE_RUNTIME_RECEIPTS.txt
                 (SHA256 D18A8F734677E8335676B2327D10DD95F0705491F28B50FF1B64E6FD3B4116FD)
    VERDICT    = PASS

```
SETTINGS_DIALOG_REACHABLE=1
LOAD_CALLED=1                (was 0)
PATH_SELECTED=1              (was 0)
SAVE_EFFECTIVE=1             (was 0)
FILE_WRITTEN=1
RESTART_VALUE_MATCH=1

FIRST_RUN_CREATION=PASS
PARTIAL_MALFORMED_RECOVERY=PASS
UNRECOVERABLE_QUARANTINE=PASS

RUNS=4
PASS_RUNS=4
VERDICT=PASS
```

### Preserved boundaries

These are three independent questions and are recorded separately so that a pass
on one cannot be read as a pass on another.

```
SETTINGS_PERSISTENCE=PASS
SETTINGS_AUTHORITY=FRAGMENTED
SCHEMA_VALIDATION=REAL_UNREACHABLE

WM_CLOSE_PERSISTENCE=PASS
WM_CLOSE_APPLICATION_EXIT=PREEXISTING_DEFECT

FULL_INFERENCEENGINE_BUILD=BLOCKED
SETTINGS_ONLY_PRODUCT_LINK=PASS_WITH_PROJECT_REFERENCES_DISABLED
```

`WM_CLOSE_APPLICATION_EXIT=PREEXISTING_DEFECT` does not retract
`WM_CLOSE_PERSISTENCE=PASS`. Persistence completes before `DestroyWindow` is
called, so the defect is downstream of the measured operation and did not
participate in it.

### GPU API state — reconciliation with RAWRXD_GPU_DLWVECTOR_CONTRACT_AUDIT_001

```
GPU_API_STATE=CONCURRENTLY_UNSTABLE
PRIOR_CONTRACT_AUDIT=VALID_FOR_ITS_RECORDED_TREE_STATE
CURRENT_BUILD_FAILURE=REAL_FOR_CURRENT_WORKTREE_STATE
ROOT_CAUSE_NOT_YET_ATTRIBUTED
```

An earlier audit established the `DeviceBuf` contract and rebuilt
`InferenceEngine` without source changes. The 18 C2664 errors observed here show
the pre-`DeviceBuf` float-pointer calling convention at the call sites again,
while `Deep2Engine_GpuForward.cpp` carries an uncommitted modification and its
mtime advanced during this gate. Both observations are true; they describe
different tree states.

**Not repaired from this lane.** Once the file's owner stops writing, the
discriminating step is to diff `src/deep2/Deep2Engine_GpuForward.cpp` against
both `910de35fa` and the tree recorded by
`RAWRXD_GPU_DLWVECTOR_CONTRACT_AUDIT_001`. Two hypotheses remain live and the
diff separates them: an old caller implementation was restored, or a migration
to the `DeviceBuf` API is genuinely incomplete.

---

## 1. The defect

`Settings_Load()` had **zero callers in the entire repository**. It was
defined at `src/win32app/Win32IDE_Settings.cpp:13` and forward-declared at
`Win32IDE_SettingsGUI.cpp:14`. Nothing else.

`g_settingsPath` (`:11`) was assigned **only** inside `Settings_Load` (`:15`),
so it stayed empty for the life of the process, and `Settings_Save()` returned
at its first statement:

```cpp
// Win32IDE_Settings.cpp:32-35, before this pass
void Settings_Save() {
    if (g_settingsPath.empty()) return;   // <-- always taken
    ...
}
```

The settings dialog was genuinely reachable end-to-end — `main_win32.cpp:2304`
appends `IDM_FILE_SETTINGS`, `WM_COMMAND` routes through
`Win32IDE_Commands_Route` (`:1703`), `Win32IDE_Commands.cpp:679` dispatches to
`handleFileCommand`, `:651` calls `SettingsGUI_Show` — and `SaveSettingsFromDialog`
calls `Settings_Save()`. Every edit therefore entered an in-memory map and was
discarded on exit. A gate that read a setting read a value no user could change.

Confirmed before the fix: the shipping binary was copied to an empty directory
and executed. It produced exactly one artifact, `ide_chat_engine_status.txt`.
No settings file, before or after close.

---

## 2. What changed

Three files. No new dependencies; `shell32` is already in the MSVC default link
set for this target.

### `src/win32app/Win32IDE_Settings.h` (new, 57 lines)

The canonical settings authority surface. `SettingsDiagnostics` lives here so
the receipt emitter and the store agree on one struct. Every field starts at a
non-healthy value by construction — `loadCalled=false`, `pathResolved=false`,
`fileExisted=false`, `recovered=false`, counters at zero — so a receipt cannot
report PASS by default.

### `src/win32app/Win32IDE_Settings.cpp` (69 → 231 lines)

- **Deterministic path resolution**, first hit wins:
  1. `RAWRXD_SETTINGS_PATH` env var (exact file; enterprise policy override and
     the seam the runtime gate drives)
  2. `%LOCALAPPDATA%\RawrXD\settings.ini` via `SHGetFolderPathA(CSIDL_LOCAL_APPDATA)`,
     directory created if absent
  3. `<exe dir>\settings.ini` fallback

  `SHGetFolderPathA` rather than `SHGetKnownFolderPath` deliberately: shell32
  only, no COM apartment requirement, no `CoTaskMemFree` lifetime question.

- **`Settings_EnsureLoaded()`** — idempotent startup entry point.
- **Line-level parse with reject accounting.** `;` added to the comment set
  alongside `#`; tabs handled alongside spaces; every unusable line is counted
  into `linesRejected` rather than silently dropped.
- **Recover-safe malformed policy.** A file that exists but yields **zero** keys
  while containing rejected lines is moved to `<path>.bad` and the authority
  restarts clean (`recovered=1`). A file with *any* usable key is trusted, and
  its rejects are counted. The reason for the threshold: starting clean and then
  saving would otherwise overwrite a partially-valid operator configuration with
  a two-line file. The corrupt original is preserved for forensics.
- **Atomic save.** Write `<path>.tmp`, then `ReplaceFileA`; on failure fall back
  to `MoveFileExA(MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)`. A crash
  mid-write cannot truncate a configuration.
- `Settings_Persist()` returns the boolean form for the receipt;
  `Settings_Save()` keeps its original `void` signature because
  `Win32IDE_SettingsGUI.cpp:15` and `CICDSettings.cpp:15` declare it that way,
  and changing it would be a link-level decoration mismatch.

### `src/win32app/main_win32.cpp`

- `writeSettingsStatus(phase)` — measured receipt, written next to the exe
  beside the existing `ide_chat_engine_status.txt`. Reads
  `Settings_Diagnostics()`, probes the file with `GetFileAttributesExA`, and
  reads a live probe key/value through the real accessor. The verdict is
  derived: `startup` requires `loadCalled && pathResolved`; `shutdown` requires
  `saveWroteFile && fileExistsNow && fileBytesNow > 0`.
- `WM_CREATE` — `Settings_EnsureLoaded()` then `writeSettingsStatus("startup")`,
  before the shell is built so no surface reads defaults it can never be given.
- `WM_CLOSE` — `Settings_Persist()` then `writeSettingsStatus("shutdown")`, for
  surfaces that call `Settings_Set` without owning a dialog (MCP, CICD,
  command handlers). Idempotent with the dialog's own OK/Apply save.

---

## 3. Runtime proof

Four independent launches of the built binary, each in its own directory with
`RAWRXD_SETTINGS_PATH` pointed at a file in that directory. `WM_CLOSE` was
posted from outside to the real main window (`class='RawrXDWin32IDE'`,
`title='RawrXD Win32 IDE'`) — the same message the window's X button sends — so
the shutdown path under test is the one a user exercises.

### run1 — empty directory, first run

Seeded: nothing.

```
PHASE=shutdown
SETTINGS_PATH_RESOLVED=1
SETTINGS_LOAD_CALLED=1
SETTINGS_FILE_EXISTED=0
SETTINGS_KEYS_LOADED=0
SETTINGS_LINES_REJECTED=0
SETTINGS_SAVE_CALLS=1
SETTINGS_SAVE_WROTE_FILE=1
SETTINGS_SAVE_BYTES=52
SETTINGS_FILE_EXISTS_NOW=1
SETTINGS_FILE_BYTES_NOW=52
SETTINGS_LAST_ERROR=settings file absent (first run)
VERDICT=PASS
```

`settings.ini` created, 52 bytes:
```
# RawrXD Settings
# RAWRXD_SETTINGS_PERSISTENCE_001
```

### run2 — user-edited settings, restart, reload, re-save

Seeded with an operator edit the product did not write:
```
# RawrXD Settings
editor.fontSize = 21
editor.theme = High Contrast
lsp.enabled = 1
```

Startup:
```
PHASE=startup
SETTINGS_FILE_EXISTED=1
SETTINGS_KEYS_LOADED=3
SETTINGS_PROBE_PRESENT=1
SETTINGS_PROBE_VALUE=21
VERDICT=PASS
```

After `WM_CLOSE`:
```
PHASE=shutdown
SETTINGS_KEYS_LOADED=3
SETTINGS_KEYS_IN_MEMORY=3
SETTINGS_SAVE_CALLS=1
SETTINGS_SAVE_WROTE_FILE=1
SETTINGS_SAVE_BYTES=118
SETTINGS_PROBE_VALUE=21
VERDICT=PASS
```

`settings.ini` after the save:
```
# RawrXD Settings
# RAWRXD_SETTINGS_PERSISTENCE_001
editor.fontSize = 21
editor.theme = High Contrast
lsp.enabled = 1
```

This is the round trip that was previously impossible. The value was written by
a hand, loaded into the product's map through the real load path, read back out
through the real accessor, and written again by the shutdown save **unchanged**.
The dialog was never opened in this run, so nothing could have re-set the value
to 21 — `RESTART_VALUE_MATCH=1` is a genuine load→map→save measurement.

### run3 — partially malformed (1 good key, 3 bad lines)

```
PHASE=shutdown
SETTINGS_KEYS_LOADED=1
SETTINGS_LINES_REJECTED=3
SETTINGS_RECOVERED=0
SETTINGS_SAVE_WROTE_FILE=1
SETTINGS_PROBE_VALUE=17
VERDICT=PASS
```

The one usable key survived the round trip (`editor.fontSize = 17`) and the three
unusable lines were counted, not silently swallowed. `RECOVERED=0` is correct:
the file still carried usable configuration, so quarantining it would have been
the destructive choice.

### run4 — unrecoverable (0 usable keys, 4 bad lines)

```
PHASE=startup
SETTINGS_KEYS_LOADED=0
SETTINGS_LINES_REJECTED=4
SETTINGS_RECOVERED=1
SETTINGS_QUARANTINE_PATH=...\run4\settings.ini.bad
SETTINGS_FILE_EXISTS_NOW=0
SETTINGS_PROBE_PRESENT=0
VERDICT=PASS
```

`settings.ini` is gone; `settings.ini.bad` holds the 63-byte original. The
product did not overwrite the corrupt file with defaults, and it did not pretend
to have loaded configuration it never read.

---

## 4. What this gate does not claim

- **Schema validation is still not wired.** `ConfigurationValidator` remains
  unreachable; its sole caller is in `rawrengine_command_handlers.cpp`, which no
  target compiles. This gate replaced silent discard with count-and-report; it
  did not make the settings schema-validated.
- **Settings authority is still fragmented.** `UnifiedConfig` (503 lines, 0 cmake
  refs) and `settings_persistence.cpp` (64 lines, includes a header absent from
  the tree) remain orphaned. `Win32IDE_Settings` is now the *product* authority
  because it is the only one linked and reachable — not because the others were
  removed. Consolidation is item 2 of the ordered fix list.
- **`main_win32.cpp` does not exit cleanly after `WM_CLOSE`.** In every run the
  persist completed and the receipt was written, then the process stayed alive
  past a 25s timeout. `WM_CLOSE` calls `DestroyWindow`, and `WM_DESTROY` posts
  `PostQuitMessage` — so something downstream is not returning to the pump. This
  is pre-existing and outside this gate; it did not affect any measurement above,
  because persistence completes before `DestroyWindow`.
- **No GUI-driven edit was exercised.** The dialog path was verified to be
  reachable and its save call is the same `Settings_Save`, but the run2 value was
  seeded by hand rather than typed into the dialog. That is the one substitution
  in this receipt, and it is stated here rather than implied away.
- **Build drift during the proof.** Another session was concurrently editing
  `src/rawrxd_cpu_math.cpp`, `src/deep2/Deep2Engine_GpuForward.cpp`, and
  `src/agentic/CheckpointRollbackAuthority.h`; the IDE exe changed size mid-proof
  (20911104 → 20916224). The SHA256 above is the final build. Runs 1–3 used the
  earlier build of the same unchanged settings sources; run4 used the final one.
  No other session touched `Win32IDE_Settings.*` or `main_win32.cpp`'s settings
  wiring.

---

## 5. Build note (out of scope, recorded not fixed)

The first build attempt failed with 23 errors in `InferenceEngine.vcxproj` —
none in any file this gate touches:

| File | Errors | Cause | Disposition |
|---|---|---|---|
| `src/rawrxd_cpu_math.cpp` | 5 (C2059/C3867/C2109/C2737) | `std::vector<uint64_t> seenOf_(8, 0);` — parens where braces were meant, parsed as a function-style declarator | **fixed by the other session** during this gate; verified compiling |
| `src/deep2/Deep2Engine_GpuForward.cpp` | 18 (C2664) | `.cpp` still calls the pre-`DeviceBuf` API (`const float*`) while committed `vulkan_compute.h:250-251` declares `UploadVector(DeviceBuf&, const float*, size_t)` / `DownloadVector(const DeviceBuf&, float*, size_t)` | **NOT fixed — not mine.** A half-migrated GPU API. Left for its owner |

The IDE target was therefore linked with
`/p:BuildProjectReferences=false` against the existing `InferenceEngine.lib`
(`build_ide_audit/Release/InferenceEngine.lib`). Disclosed because it means the
shipped IDE was not relinked against a freshly rebuilt `InferenceEngine`. That
is safe for this gate: none of the three files it changes is in `InferenceEngine`,
and all three are in `WIN32IDE_SOURCES`, so they were compiled fresh.

---

## 6. Gate ledger

```
RAWRXD_SETTINGS_PERSISTENCE_001=PASS

LOAD_CALLED=1
PATH_SELECTED=1
SAVE_EFFECTIVE=1
FILE_WRITTEN=1
RESTART_VALUE_MATCH=1

FIRST_RUN_CREATION=PASS
PARTIAL_MALFORMED_RECOVERY=PASS
UNRECOVERABLE_QUARANTINE=PASS

RUNS=4
PASS_RUNS=4

SETTINGS_PERSISTENCE=PASS
SETTINGS_AUTHORITY=FRAGMENTED
SCHEMA_VALIDATION=REAL_UNREACHABLE
WM_CLOSE_PERSISTENCE=PASS
WM_CLOSE_APPLICATION_EXIT=PREEXISTING_DEFECT
FULL_INFERENCEENGINE_BUILD=BLOCKED
SETTINGS_ONLY_PRODUCT_LINK=PASS_WITH_PROJECT_REFERENCES_DISABLED
GPU_API_STATE=CONCURRENTLY_UNSTABLE

IDE_ENTERPRISE_RELEASE=NO_GO            (unchanged; blocker removed, others remain)
PRIMARY_NEW_BLOCKER=NONE_FOR_SETTINGS_PERSISTENCE
```

**Prior state for this gate was `USER_EDITS_PERSIST=0` with
`SETTINGS_LOAD_CALLED=0`. It is now `1` and `1`, measured through the real load
and save paths of the shipping binary.**

---

## 7. Commit provenance — the source boundary was already lost

The intended commit boundary was *three settings sources plus audit/receipt/ledger
only*. That boundary was **not available for the source files**: a concurrent
session ran a bulk commit while these three files were mid-work.

```
COMMIT_THAT_SWEPT_THIS_WORK=da2fec4b0 "PUSH_ALL: enterprise audit state, tool
                                        authorities, IDE certification work"
FILES_IN_THAT_COMMIT=1117
CONTAINS_OUR_SOURCES=rawrxd/src/win32app/Win32IDE_Settings.cpp
                     rawrxd/src/win32app/Win32IDE_Settings.h
                     rawrxd/src/win32app/main_win32.cpp
ALSO_CONTAINS=41 receipt/dir entries, Deep2Engine_RouterSmokeTest.vcxproj,
              deep2_canonical_inference_probe.vcxproj,
              deep2_expert_control_plane_cert.vcxproj, certbuild/* and more
CONTAINS_OUR_ITEM7_AUDIT=rawrxd/audit/RAWRXD_IDE_CMAKE_FULL_AUDIT_001/P1_WORKSPACE_PROJECT_SUPPORT_AUDIT.md
```

HEAD moved `acb63e871` → `da2fec4b0` → `9bfd80484` → `910de35fa` during this
gate. Verified that all settings behaviour survived the sweep intact by reading
it back out of `HEAD`, not the working tree:

```
HEAD:Win32IDE_Settings.cpp contains resolveDefaultSettingsPath, Settings_EnsureLoaded,
                                    quarantine path, ReplaceFileA atomic swap   = present
HEAD:Win32IDE_Settings.h    tracked (blob 66b86994b6d478fae8e9e29d3409961677b60b65) = present
HEAD:main_win32.cpp         contains writeSettingsStatus + startup/shutdown calls = present
```

Only the receipt and ledger files remained unstaged, and those are committed
path-specifically. Un-mixing the sources out of a 1117-file shared commit would
require rewriting history that other sessions are actively building on, which is
strictly more destructive than the boundary violation it would repair. This is
recorded rather than silently absorbed.