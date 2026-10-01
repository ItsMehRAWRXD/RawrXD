# IDE P1 Item 7 — Workspace / Project Support: Authority Analysis

    SCOPE        = 9 capabilities (multi-root workspace, filesystem watchers,
                   workspace persistence, task definitions, launch configurations,
                   unified settings, settings schema validation, configuration
                   migration, per-project configuration)
    METHOD       = Repo-wide census. NOT a win32app/*.cpp scan.
    DATE         = 2026-10-01
    HEAD         = acb63e871
    EVIDENCE     = source census + CMakeLists/vcxproj inclusion census +
                   .obj presence census in build_ide_audit + ASCII string scan
                   of the linked shipping binary
    BINARY       = rawrxd/build_ide_audit/bin/Release/RawrXD-Win32IDE.exe
                   (20782080 bytes, 2026-10-01 17:04:36)

**This audit corrects the record.** `RAWRXD_IDE_PARITY_AUDIT_001` §11 marked
`Task runner (tasks.json equivalent)` MISSING because `Win32IDE_Tasks.cpp` was
listed in the missing-225 set. That is a filename conclusion, not a capability
conclusion. A repo-wide census finds **1190 lines of real task-runner
implementation** in `src/core/task_system.hpp` under a different name.

It also finds the opposite problem. Three of the nine capabilities have real
implementation on disk that is **not linked into any target** and is
**structurally incapable of linking** — one of them includes a header that does
not exist in the tree.

---

## Classification summary

| # | Capability | Source on disk | In a build target | Has callers | Classification |
|---|---|---|---|---|---|
| 1 | multi-root workspace | yes | **NO** | NO | **ORPHAN** |
| 2 | filesystem watchers | yes (×3) | 1 of 3, and that one unreachable | NO | **PARTIAL / ORPHAN** |
| 3 | workspace persistence | yes | **NO** | NO | **ORPHAN** |
| 4 | task definitions / tasks.json | **1190 lines, real** | **NO** | NO | **ORPHAN (not missing)** |
| 5 | launch configurations | **none anywhere** | — | — | **ABSENT** |
| 6 | unified settings | 4 competing impls | 1 (ini-backed) | yes | **FRAGMENTED** |
| 7 | settings schema validation | yes (real, 114 lines) | YES | 1, itself never compiled | **UNREACHABLE** |
| 8 | configuration migration | js only | **NO** | NO | **ABSENT in product** |
| 9 | per-project configuration | stub (1 line) | YES (compiles to 909 B) | NO | **STUB** |

Counts, measured:

```
CAPABILITIES_ANALYZED=9
SOURCE_PRESENT=8
SOURCE_ABSENT=1
LINKED_AND_REACHABLE=1
LINKED_BUT_UNREACHABLE=1
ORPHAN_SOURCE_NOT_LINKED=5
COMPILED_STUB=1
VERDICT=FAIL
```

---

## 1. Multi-root workspace — ORPHAN

**Source exists and is real.** `src/core/workspace_model.cpp`, 481 lines,
`RawrXD::IDE::WorkspaceModel`. The multi-root data structure is genuine:

- `WorkspaceFolder{ path, name, isRoot }` — `workspace_model.cpp:44`
- `WorkspaceConfig::folders` is a `std::vector<WorkspaceFolder>` — `:78`
- `addFolder(const std::string&, const std::string&)` — `:169`, dedups against
  existing folders, sets `isRoot=false`
- `removeFolder(const std::string&)` — `:194`, refuses to remove the last root
- `getFolders()` — `:163`
- C API: `RawrXD_IDE_InitWorkspace` `:431`, `RawrXD_IDE_AddOpenFile` `:451`

**It is not linked.** `Select-String workspace_model CMakeLists.txt` → 0 hits.
Across all 137 `*.vcxproj` in `cmlink/`, `workspace_model` → 0 hits.
`workspace_model.obj` does not exist in `build_ide_audit`. The string
`[WorkspaceModel]` is absent from the shipping binary; so is
`RawrXD_IDE_InitWorkspace`.

**It has no callers.** The only 4 references in the whole repo are the file's
own definition and the source-listing text files (`all_cpp.txt:677`,
`real_sources.txt:685`, and two siblings) — those are inventory dumps, not code.

**Its own load path is a stub regardless.** Even if it were linked,
`WorkspaceModel::load()` never parses anything:

```cpp
// src/core/workspace_model.cpp:373-394
bool load() {
    std::ifstream file(m_configPath);
    if (!file.is_open()) return false;
    file.close();
    fprintf(stderr, "[WorkspaceModel] Loaded workspace config: %s\n", ...);
    // Would parse JSON here
    return false;   // Trigger default generation for now
}
```

So `initialize()` always takes the "create default" branch, and every run
overwrites `.rawrxd/workspace.json` with a single-folder document. **Save is
real, load is a lie that reports success in its own log line.**

The IDE's real explorer is single-root by construction, not by omission:
`src/win32app/Win32IDE_Sidebar.cpp:186` inserts exactly one root node from
`GetCurrentDirectoryW`, and the file contains no `AddRoot`, `roots_`, or
multi-root path.

```
MULTIROOT_SOURCE=workspace_model.cpp(481L)
MULTIROOT_IN_CMAKE=0
MULTIROOT_IN_VCXPROJ=0/137
MULTIROOT_OBJ_PRESENT=0
MULTIROOT_CALLERS=0
MULTIROOT_IN_BINARY=0
MULTIROOT_LOAD_IS_STUB=1  (workspace_model.cpp:388 `return false; // Trigger default generation for now`)
IDE_EXPLORER_ROOTS=1  (Win32IDE_Sidebar.cpp:186, no add-root API)
VERDICT=ORPHAN
```

---

## 2. Filesystem watchers — PARTIAL, all three paths unreachable

Three independent implementations exist. None is reachable from the IDE.

### 2a. `src/core/file_watcher.cpp` — cannot compile

76 lines, real `ReadDirectoryChangesW` loop with `FILE_NOTIFY_INFORMATION`
parsing and correct `FILE_ACTION_*` → `FileChangeType` mapping (`:47-54`).
The implementation is fine. The translation unit is not:

```cpp
// src/core/file_watcher.cpp:1
#include "file_watcher.h"
```

**`src/core/file_watcher.h` does not exist.** Verified by
`Test-Path .\src\core\file_watcher.h` → False, and
`Get-ChildItem -Recurse -Filter file_watcher.h` over the whole repo → 0 files.
`file_watcher.cpp` is not in `CMakeLists.txt` (the single `file_watcher` cmake
hit is `src/cli/style/rawr_file_watcher.cpp` at
`cmake/RawrRemainingStyleCli.fragment.cmake:16`, a **different path that also
does not exist** — `Test-Path` → False).

This is the exact shape of a source that "exists" in a file listing and is
absent from the product.

### 2b. `src/core/file_system.hpp` — real, zero includes

836 lines. `FileSystem::startWatching` at `:563` is a complete cross-platform
watcher: `CreateFileA(FILE_FLAG_OVERLAPPED)` on Windows, `inotify_add_watch`
with `IN_MODIFY|IN_CREATE|IN_DELETE|IN_MOVED_FROM|IN_MOVED_TO` elsewhere
(`:584-596`), plus a watcher thread at `:601-604`. Real code.

Adoption: `Select-String "file_system.hpp"` across `src/` → **1 hit, which is
the file's own first-line comment.** Nothing includes it. Nothing calls
`FileSystem::startWatching`.

### 2c. `src/repo/FileIndex.cpp` — linked, never started

`FileWatcher` class at `:28`, `ReadDirectoryChangesW` at `:106`,
`FileIndexManager::StartWatching()` at `:402` wires it up. This file **is** in
the build (1 cmake ref, and `src/repo/FileIndex.cpp` appears in a target source
list). But `StartWatching()` has **no caller anywhere in the repo** — the only
matches are its own declaration in `FileIndex.hpp:43` and
`RepositoryIntelligence.hpp:213,326`. The watcher object is constructed only
inside `StartWatching` itself, so it is never constructed.

### 2d. A fourth, in a file that is not compiled at all

`src/core/rawrengine_command_handlers.cpp:152` `HandleIOCPFileWatcher` builds a
real IOCP + directory handle pair. That file is **excluded from every target**:

```
CMakeLists.txt:3381  # NOTE: rawrengine_command_handlers.cpp removed
CMakeLists.txt:4081  # REMOVED: src/core/rawrengine_command_handlers.cpp - references UpdateSignatureVerifier, PerfTelemetry (unresolved)
CMakeLists.txt:5819  # EXCLUDED: missing plugin_signature.h
```

and `rawrengine_command_handlers.obj` is absent from both `build_ide` and
`build_ide_audit`.

```
WATCHER_IMPLS_ON_DISK=4  (file_watcher.cpp, file_system.hpp, FileIndex.cpp, rawrengine_command_handlers.cpp)
WATCHER_LINKED_AND_REACHABLE=0
WATCHER_MISSING_HEADER_BLOCKS_COMPILE=1  (file_watcher.h absent repo-wide)
WATCHER_CMAKE_STALE_REFERENCE=1  (cmake/RawrRemainingStyleCli.fragment.cmake:16 -> src/cli/style/rawr_file_watcher.cpp, absent)
WATCHER_STARTWATCHING_CALLERS=0
VERDICT=PARTIAL_ORPHAN
```

---

## 3. Workspace persistence — ORPHAN

The persistence layer that the multi-root model would use is
`Win32IDE_Session.cpp`, 51 lines, `pipe`-delimited save/load of open files with
cursor positions. Real, and correctly linked:

```
Win32IDE_Session.cpp exists=True, cmakeRefs=1 (CMakeLists.txt:5356, inside WIN32IDE_SOURCES)
Win32IDE_Session.obj PRESENT in build_ide_audit/RawrXD-Win32IDE.dir/Release
```

It is also **called by nothing**. `Session_SetPath`, `Session_AddFile`,
`Session_Save`, `Session_Load`, `Session_GetFiles` each appear exactly once in
the repo — their own definitions. `Session_SetPath` has zero callers, so
`g_sessionPath` (`:12`) stays empty, and both `Session_Save` (`:24`) and
`Session_Load` (`:32`) early-return on the empty path. **The persistence code
is linked, never invoked, and structurally no-ops when invoked.**

The `.rawrxd/workspace.json` route (via `WorkspaceModel`) is worse — not
linked, not called, and its load half is a stub (§1).

Verified by running the shipping binary in a clean directory:
`RawrXD-Win32IDE.exe` was copied to an empty temp dir and executed. It produced
exactly one artifact, `ide_chat_engine_status.txt`. **No `.rawrxd/`,
no `workspace.json`, no session file, no settings file.**

```
SESSION_SOURCE=Win32IDE_Session.cpp(51L)
SESSION_IN_CMAKE=1 (CMakeLists.txt:5356)
SESSION_OBJ_PRESENT=1
SESSION_CALLERS=0
SESSION_PATH_SET_CALLERS=0   -> g_sessionPath always empty
SESSION_EFFECTIVE=NOOP
WORKSPACE_JSON_ROUTE_LINKED=0
RUNTIME_ARTIFACTS_OBSERVED=1 (ide_chat_engine_status.txt only)
VERDICT=ORPHAN
```

---

## 4. Task definitions / tasks.json equivalent — ORPHAN, **not absent**

This is the correction the earlier audit got wrong.

`RAWRXD_IDE_PARITY_AUDIT_001:277` recorded:

> | Task runner (tasks.json equivalent) | MISSING | Win32IDE_Tasks.cpp listed in
> missing-225 | Source file absent |

The filename is absent. The capability is not.

`src/core/task_system.hpp` — **1190 lines**, namespace `rawrxd`, all methods
`inline` in the header. This is a complete VS Code-shaped task runner:

- `enum class TaskType { Shell, Process, Build, Test, Run, Custom }` — `:29`
- `TaskRunner` class — `:143`
- process execution: `createProcess` `:541`, `readProcessOutput` `:611`,
  `terminateProcess` `:662`, `executeTask` `:456`
- problem matchers: `addProblemMatcher` `:186`, `matchProblems` `:683`,
  `parseOutput` `:668` — i.e. error-to-diagnostic parsing from task output
- dependency graph: `resolveDependencies` `:723`, `runGroup` `:164`
- variable expansion: `expandVariables` `:224` — VS Code `${...}` semantics
- build-system detection: `detectBuildSystem` `:246`, `detectCMake` `:292`,
  `detectMake` `:294`, `detectMSBuild` `:294`, `detectNinja` `:296`,
  `parseCMakeLists` `:298`, `parseMakefile` `:300`, `parseVcxproj` `:301`
- convenience entry points `build()` `:850`, `test()` `:864`, `clean()` `:878`,
  `rebuild()` `:892`
- 36 `inline` method bodies (counted via `TaskRunner::` grep)

**It is not linked.** `Select-String task_system CMakeLists.txt` → 0 hits.
Across all 137 vcxproj → 0 hits. No `.obj`.

**It has no includers.** `Select-String task_system.hpp` across `src/`,
`tools/`, `include/` → 1 hit, which is its own line-1 comment.

**Its config-file entry points are stubs**, which is the part that actually
matches the earlier "missing" verdict:

```cpp
// src/core/task_system.hpp:810
inline void TaskRunner::loadConfig(const std::string& config_path) {
    // TODO: Parse JSON/YAML config file
}
// :814
inline void TaskRunner::saveConfig(const std::string& config_path) {
    // TODO: Write JSON/YAML config file
}
```

So even a linked `TaskRunner` could not load a `tasks.json`. Its whole external
contract for configuration is two empty functions.

### The call site that does not exist

`src/core/application.cpp:425`:

```cpp
if (taskRunner_) {
    taskRunner_->LoadTasksConfiguration(path + "\\.vscode\\tasks.json");
}
```

This looks like working `.vscode/tasks.json` support. It is not:

- `Tasks::TaskRunner` is a **forward declaration only** —
  `src/core/application.h:12`: `namespace Tasks { class TaskRunner; }`
- Repo-wide, `class TaskRunner` has exactly **two** definitions:
  `application.h:12` (the forward decl) and `task_system.hpp:143` — and the
  latter is in namespace `rawrxd`, not `Tasks`. They are different types.
- `LoadTasksConfiguration` appears exactly **once** in the entire repo: that
  call site. No declaration, no definition.
- Same for `LoadWorkspaceSettings`, `SaveWorkspaceSettings`, `SetTaskEventCallback`,
  `GetInteger`, `SettingValue` — each appears only in `application.cpp`.
- `Settings::SettingsManager` (`application.h:13`) likewise has no definition.
  The nearest real thing, `RawrXD::SettingsManager` in
  `src/core/unlinked_symbols_batch_021.cpp:56`, is a different namespace and
  has empty bodies: `Initialize` returns `true` (`:66`), `Shutdown` is `{}`
  (`:67`), `SetWindowState` is `{}` (`:69`).
- **`application.cpp` is not in any build target.** `Select-String
  application.cpp CMakeLists.txt` → 0 hits; `application.obj` absent from
  `build_ide_audit`.

`application.cpp` is 618 lines of a service-container design that was never
built. It is the single largest source of phantom capability in this area.

```
TASKRUNNER_SOURCE=task_system.hpp(1190L, 36 inline method bodies)
TASKRUNNER_IN_CMAKE=0
TASKRUNNER_IN_VCXPROJ=0/137
TASKRUNNER_OBJ_PRESENT=0
TASKRUNNER_INCLUDERS=0  (1 self-comment)
TASKRUNNER_LOADCONFIG_BODY=TODO_STUB  (task_system.hpp:810-812)
TASKRUNNER_SAVECONFIG_BODY=TODO_STUB  (task_system.hpp:814-816)
TASKRUNNER_EXECUTION_ENGINE=REAL (createProcess/readProcessOutput/matchProblems/resolveDependencies/detect*)
TASKS_JSON_READER=0
PHANTOM_CALLSITE=application.cpp:425 (file not in any target)
EARLIER_VERDICT_MISSING=RETRACTED
VERDICT=ORPHAN_NOT_ABSENT
```

---

## 5. Launch configurations — ABSENT

The only honest zero in this audit. No file, no symbol, no reference.

`Get-ChildItem -Recurse -Include *.cpp,*.hpp,*.h` over `src/` searched for
`launch.json`, `LaunchConfig`, `launchConfig` → **0 matches anywhere.**

`launch.json` is absent from the shipping binary's ASCII content.

`IDM_FILE_...` / `IDM_...` command-ID space in `Win32IDE_Commands.cpp:69-94`
covers File, Edit, and Recent. There is no launch/run-config ID.

Two adjacent names exist and are unrelated to launch configurations:

- `MeasuredIdeLaunch()` at `src/win32app/main_win32.cpp:1050` — a startup
  precondition gate that reports `IDE_LAUNCH=PASS/FAIL` into the receipt. It
  measures whether the main window was created; it launches nothing and holds no
  configuration.
- `src/core/native_debugger_*` — a native debugger, and
  `src/win32app/Win32IDE_Debugger.cpp` is **listed at `CMakeLists.txt:5334` but
  the file does not exist** (`Test-Path` → False). `rawrxd_filter_missing_sources`
  silently drops it at configure time with only `message(WARNING)`.

```
LAUNCHCONFIG_SYMBOLS=0
LAUNCHCONFIG_FILES=0
LAUNCHCONFIG_IN_BINARY=0
IDE_LAUNCH_STRING_PRESENT=1  (main_win32.cpp:1055, a startup gate, not a config system)
DEBUGGER_SOURCE_LISTED_IN_CMAKE=1
DEBUGGER_FILE_EXISTS=0  (CMakeLists.txt:5334 -> dropped by filter at configure time)
VERDICT=ABSENT
```

---

## 6. Unified settings — FRAGMENTED, four competing implementations

Not one settings system. Four, none reconciled, one linked.

### 6a. Linked and reachable — `Win32IDE_Settings.cpp` (69 lines)

Flat `std::unordered_map<std::string,std::string>`, `key = value` line format,
`#` and `[` treated as comments (`:20`).

Linked (`CMakeLists.txt:5345`, `:5399`; `Win32IDE_Settings.obj` present in
`build_ide_audit/RawrXD-Win32IDE.dir/Release`) and reachable: the binary
contains `"RawrXD Settings"` @10832722, `"# RawrXD Settings"` @10832720,
`"Font Size:"`, `"Tab Size:"`, `"lsp.serverPath"` @11253960, `"mcp.serverCmd"`
@11254136, `"Show Minimap"`.

The UI path is genuinely closed end-to-end, which is a real credit:

```
main_win32.cpp:2304   AppendMenuA(hFile, MF_STRING, IDM_FILE_SETTINGS, "Se&ttings...")
main_win32.cpp:1703   if (Win32IDE_Commands_Route(wmId)) break;      (WM_COMMAND)
Win32IDE_Commands.cpp:679   if (commandId >= 1000 && < 2000) handleFileCommand(...)
Win32IDE_Commands.cpp:651   case IDM_FILE_SETTINGS: SettingsGUI_Show(g_hwndMain)
Win32IDE_SettingsGUI.cpp:334 SettingsGUI_Show -> DialogBoxIndirectParamA with a
                                real synthesized template (:307 BuildSettingsTemplate)
```

`BuildSettingsTemplate` at `:307` exists specifically because the original code
passed a NULL template to `DialogBoxParamA` and could never have displayed
anything — the comment at `:301-306` documents the repair.

**But it never reads or writes anything.** `Settings_Load` has **zero callers**:

```
Settings_Load occurrences, whole repo (all file types): 4
  - Win32IDE_Settings.cpp:13     (the definition)
  - Win32IDE_SettingsGUI.cpp:14  (a forward declaration)
  - same two lines in 3 Agent Manager worktrees + _n2_stage (copies, not callers)
```

`g_settingsPath` (`Win32IDE_Settings.cpp:11`) is assigned **only** inside
`Settings_Load` (`:15`). With no caller, `g_settingsPath` stays empty, and
`Settings_Save` returns immediately at `:34`:

```cpp
void Settings_Save() {
    if (g_settingsPath.empty()) return;    // <-- always taken
    ...
}
```

**The settings dialog edits an in-memory map that is discarded when the process
exits.** Confirmed by running the shipping binary in an empty directory: the
only file it produced was `ide_chat_engine_status.txt`. No settings file.

### 6b. `src/core/UnifiedConfig.{hpp,cpp}` — ORPHAN

135 + 368 lines, a real single-pass non-allocating JSON5 scanner over a
memory-mapped file: `LoadFromFile` `:32`, `LoadFromString` `:81`, `Get` `:133`,
`GetBool` `:177`, `HasKey` `:197`, `ParseValue` `:230`, `ParseString` `:274`,
`ParseNumber` `:293`, `FindKey` `:332`. Plus `ConfigKeys::` compile-time key
constants (`UnifiedConfig.hpp:122` onward) covering model/ui/keybindings/lsp.

Not linked (`UnifiedConfig` in CMakeLists → 0; no `.obj`), and only 2
references exist: its own `#include` and `test_unified_config.cpp:4`.

Two of its own methods are stubs by its own admission:

```cpp
// UnifiedConfig.cpp:201
size_t UnifiedConfig::GetKeys(...) const noexcept {
    // Simplified implementation - would enumerate object keys
    // For now, return 0 (stub)
    return 0;
}
// :207
bool UnifiedConfig::Validate() const noexcept {
    // Simplified validation - check basic structure
    if (!m_data) return false;
    // Must start with '{' or '['
    ...
}
```

`Validate()` is a one-character root check, not schema validation. Its own test
binary `src/core/test_unified_config.exe` exists but **fails to launch** —
exit code `-1073741515` = `0xC0000135` `STATUS_DLL_NOT_FOUND`.

### 6c. `src/core/settings_persistence.cpp` — cannot compile

64 lines, and the persistence logic is the best of the four: nlohmann JSON,
`tmp`-then-`ReplaceFileA` atomic replace with a delete+rename fallback
(`:41-45`), mutex-guarded, key-scoped get/set/remove.

```cpp
// src/core/settings_persistence.cpp:1
#include "settings_persistence.h"
```

**`settings_persistence.h` does not exist.** Repo-wide search → 0 files.
`src/core/session_manager.cpp:2` includes the same non-existent header. Not in
CMakeLists (0 hits).

### 6d. `src/config/IDEConfig.{h,cpp}` — STUB, but compiled

```cpp
// src/config/IDEConfig.h   (3 lines total)
#pragma once
// Stub header

// src/config/IDEConfig.cpp (1 line total)
#include "IDEConfig.h"
```

Listed in three targets (`CMakeLists.txt:442`, `:2572`, `:5431`) and it does
compile: `IDEConfig.obj` is present in
`build_ide_audit/RawrXD-Win32IDE.dir/Release`, **909 bytes** — an object with
no code in it. `CMakeLists.txt:2571` even comments that it is
"required by OrchestratorBridge", which it cannot be.

The `WIN32IDE_SOURCES` list itself is `set(...)` at `CMakeLists.txt:5236` and
grows by `list(APPEND ...)` through `:7158`, so the absent-file entries cited
in this receipt (`Win32IDE_Tasks.cpp` at `:6049`, `Win32IDE_Debugger.cpp` at
`:5334`) are both genuinely inside it and genuinely filtered out at `:7062`.

### 6e. `migration-engine.js` — see §8

```
SETTINGS_IMPLEMENTATIONS=4  (Win32IDE_Settings.cpp, UnifiedConfig, settings_persistence.cpp, IDEConfig)
SETTINGS_LINKED=1  (Win32IDE_Settings.cpp)
SETTINGS_REACHABLE_VIA_UI=1  (menu -> WM_COMMAND -> router -> dialog)
SETTINGS_PERSISTENCE_EFFECTIVE=0  (Settings_Load callers=0 -> g_settingsPath empty -> Settings_Save no-op)
SETTINGS_MISSING_HEADER_BLOCKS_COMPILE=1  (settings_persistence.h)
SETTINGS_DECLARED_VALIDATE_IS_STUB=1  (UnifiedConfig.cpp:207)
SETTINGS_SCHEMA_FILES_ON_DISK=0  (no *schema*.json / settings.json anywhere)
RUNTIME_SETTINGS_FILE_WRITTEN=0
VERDICT=FRAGMENTED
```

---

## 7. Settings schema validation — UNREACHABLE

The validator is the most genuinely correct code in this audit.
`src/core/ConfigurationValidator.{h,cpp}`, 50 + 114 lines:

- `ValidationRule{ name, validator, errorMessage, required }` — `.h:10`
- `ValidationResult{ valid, errors, warnings }` — `.h:17`
- section-scoped rules, strict-mode unknown-key detection —
  `.cpp:46-57`
- 5 concrete built-in validators:
  - `validatePort` `:81` — `std::stoi` + range `1..65535`
  - `validatePath` `:90` — `has_root_path()`
  - `validateBoolean` `:94` — case-folded, accepts true/false/1/0
  - `validatePositiveInteger` `:100`
  - `validateMemorySize` `:109` — regex `^\d+[kmgt]?$`, case-insensitive

**It is compiled into the shipping IDE target.** `CMakeLists.txt:3375`, `:4076`,
`:4530`, `:5563`; `ConfigurationValidator.obj` present in
`build_ide_audit/RawrXD-Win32IDE.dir/Release` **and**
`build_ide_audit/InferenceEngine.dir/Release`.

**It has exactly one caller, and that caller is in a file no target compiles.**

`src/core/rawrengine_command_handlers.cpp:175`:

```cpp
CommandResult HandleIDEDiagnosticAutoHealer(const CommandContext& ctx) {
    auto& validator = RawrXD::Core::ConfigurationValidator::instance();
    validator.addRule("ide", {"workspace", [](const std::string& v) { return !v.empty(); },
                              "workspace missing", true});
    std::unordered_map<std::string, std::string> config{
        {"workspace", std::filesystem::current_path().string()}
    };
    auto result = validator.validateSection("ide", config);
    ...
}
```

This is the **only** call site in the repo. It does not validate any settings
file — it constructs a map containing the current directory and asserts it is
non-empty. And `rawrengine_command_handlers.cpp` is excluded from every target:

```
CMakeLists.txt:3381  # NOTE: rawrengine_command_handlers.cpp removed
CMakeLists.txt:3728  list(REMOVE_ITEM GOLD_UNDERSCORE_SOURCES src/core/rawrengine_command_handlers.cpp ...)
CMakeLists.txt:4081  # REMOVED: ... references UpdateSignatureVerifier, PerfTelemetry (unresolved)
CMakeLists.txt:5819  # EXCLUDED: missing plugin_signature.h
```

`rawrengine_command_handlers.obj` is absent from `build_ide` and
`build_ide_audit`.

The `ConfigurationValidator` string is absent from the shipping binary, and the
linked-in object contributes no reachable call edge. **The validator ships as
dead code inside the product.**

There is also **no schema artifact to validate against**: `Get-ChildItem
-Recurse -Include *schema*.json, settings.json` over the whole repo → 0 files.
`validateSection` requires a caller to supply `unordered_map<string,string>`;
nothing in the product constructs one from a user-facing config document.

```
SCHEMA_VALIDATOR_SOURCE=ConfigurationValidator.{h(50L),cpp(114L)}
SCHEMA_VALIDATOR_QUALITY=REAL  (5 concrete built-in validators)
SCHEMA_VALIDATOR_IN_CMAKE=4  (CMakeLists.txt:3375,4076,4530,5563)
SCHEMA_VALIDATOR_OBJ_PRESENT=2  (RawrXD-Win32IDE.dir, InferenceEngine.dir)
SCHEMA_VALIDATOR_CALLERS=1  (rawrengine_command_handlers.cpp:176)
SCHEMA_VALIDATOR_CALLER_IN_BUILD=0  (rawrengine_command_handlers.cpp excluded at 3381/3728/4081/5819)
SCHEMA_VALIDATOR_CALLER_OBJ=0
SCHEMA_VALIDATOR_IN_BINARY=0
SCHEMA_ARTIFACT_FILES_ON_DISK=0
SCHEMA_REACHABLE_VALIDATION=0
VERDICT=UNREACHABLE
```

---

## 8. Configuration migration — ABSENT in the product

### 8a. `src/core/migration-engine.js` — real, browser-only, not linked

108 lines, `RawrMigrationEngine`, three registered versioned migrations
(`:14` v1 seed, `:23` v2 adds `securityContext`, `:34` v3 adds `session` +
`errors`), plus `registerMigration` `:46`, `processMigrationPipeline` `:50`,
and an auto-instantiation at `:107`:

```js
window.RawrMigrationEngine = new RawrMigrationEngine();
```

It is a **browser** global. `Select-String` for `RawrMigrationEngine`,
`migration-engine`, and `processMigrationPipeline` across all of `src/`
(`.cpp`, `.hpp`, `.h`, `.js`) returns matches **only inside
`migration-engine.js` itself**. No C++ or other JS file references it.
`migration-engine` in CMakeLists → 0. No `.obj` equivalent. Absent from the
binary.

### 8b. `src/runtime/os/generated/CapabilityMigrationCapability.cpp` — TODO body, not linked

77 lines, and every method is a placeholder that returns success:

```cpp
bool CapabilityMigrationCapability::discover(CapabilityContext& ctx) {
    // TODO: hand-written discover logic for Migration
    state_ = CapabilityState::Discovered;
    return true;                    // <-- unconditional
}
// admit / initialize / execute / observe / verify / commit / persist
// all follow the identical shape: TODO comment, state assignment, return true
```

This is the exact failure pattern the project ledger already names: a hardcoded
success return that no runtime evidence backs. It is not compiled:
`src/runtime/os/generated/` → **0** hits in CMakeLists (no `file(GLOB)` covers
it either — the only globs are `src/ui/*.cpp` at `:337` and ASM at `:338`).
`RuntimeCapabilityRegistration.cpp` → 0 hits. The whole `src/runtime/os`
tree is outside the build.

So is `KernelMigrationCapability.cpp` (0 cmake refs) and
`MigrationEngine` in `src/core/migration-engine.js` (0).

```
MIGRATION_JS_SOURCE=migration-engine.js(108L, 3 registered migrations, real)
MIGRATION_JS_CONSUMERS=0  (window global; no C++/JS referrer)
MIGRATION_JS_IN_CMAKE=0
MIGRATION_GENERATED_CAPS=2  (CapabilityMigrationCapability.cpp, KernelMigrationCapability.cpp)
MIGRATION_GENERATED_BODIES=TODO_RETURN_TRUE  (9 unconditional returns)
MIGRATION_GENERATED_IN_CMAKE=0
MIGRATION_IN_BINARY=0
CONFIG_VERSION_FIELD_IN_SETTINGS_PATH=0  (configVersion appears only in reasoning_schema_versioning.cpp:187,212 — reasoning, not settings)
VERDICT=ABSENT_IN_PRODUCT
```

---

## 9. Per-project configuration — STUB

`.rawrxd/` is genuinely used across the product, but for agent/authority
infrastructure, not for IDE project settings:

```
src/authority/SingleWriterAuthority.cpp:36   ".rawrxd/leases"
src/agentic/rawrxd_scale_value_pack.cpp:541  ".rawrxd"/"index"/"workspace.rxidx"
src/agentic/rawrxd_scale_value_pack.cpp:909  ".rawrxd"/"checkpoints"
src/agentic/rawrxd_scale_value_pack.cpp:1321 ".rawrxd"/"sessions"/<id>
src/ceo/CEOAgentTypes.hpp:37-39               ".rawrxd/memory", ".rawrxd/state", ".rawrxd/logs"
```

None of these is project configuration the IDE reads.

The IDE's own per-project surface:

- `Win32IDE_Settings` is **user-global only** — one flat map, one path, no
  layering (§6a).
- `WorkspaceModel` would own `.rawrxd/workspace.json`, but is not linked, not
  called, and its load is a stub (§1).
- `src/config/IDEConfig.cpp` is **one line** and `IDEConfig.h` is **three lines**
  (`// Stub header`). Compiled into 3 targets as a 909-byte object (§6d).
- `application.cpp:420` `settingsManager_->LoadWorkspaceSettings(path)` is the
  one per-project settings read in the tree — a method with no declaration and
  no definition anywhere, in a file no target compiles (§4).
- `main_win32.cpp:1375` `opts.workspaceRoot = getExeDir();` — the IDE's
  workspace root is **the exe's own directory**, not a user-selected or
  project-derived folder. `Win32IDE_Sidebar.cpp:186` likewise uses
  `GetCurrentDirectoryW`.

```
PERPROJECT_CONFIG_SOURCE=IDEConfig.cpp(1L) + IDEConfig.h(3L) = STUB
PERPROJECT_CONFIG_IN_CMAKE=3  (CMakeLists.txt:442,2572,5431)
PERPROJECT_CONFIG_OBJ_BYTES=909  (compiled, empty)
PERPROJECT_SETTINGS_LAYERING=user-global-only  (no workspace/user/project scopes)
PERPROJECT_WORKSPACE_ROOT_SOURCE=exe_dir  (main_win32.cpp:1375) / cwd  (Win32IDE_Sidebar.cpp:186)
DOT_RAWRXD_USED_FOR=leases,index,checkpoints,sessions,memory,state,logs  (not IDE settings)
PHANTOM_PERPROJECT_CALLSITE=application.cpp:420 (file in no target)
VERDICT=STUB
```

---

## What each earlier verdict should become

| Earlier record | Correction |
|---|---|
| `RAWRXD_IDE_PARITY_AUDIT_001:277` — task runner MISSING | **RETRACTED.** 1190 real lines in `src/core/task_system.hpp`. Downgraded to ORPHAN, not absent. |
| `RAWRXD_IDE_PARITY_AUDIT_001:275` — run configuration MISSING | **CONFIRMED.** Zero symbols, zero files. |
| `RAWRXD_IDE_PARITY_AUDIT_001:276` — debug launch MISSING | **CONFIRMED and worsened.** `CMakeLists.txt:5334` still lists `Win32IDE_Debugger.cpp`; the file does not exist and `rawrxd_filter_missing_sources` drops it with only a warning. |
| `RAWRXD_IDE_PARITY_AUDIT_001` §13 settings | **CORRECTED to FRAGMENTED.** The UI is reachable and repaired; persistence has zero callers. |

---

## The two structural defects this exposes

**A. `rawrxd_filter_missing_sources` masks absent sources.** Defined at
`CMakeLists.txt:201`, applied to `WIN32IDE_SOURCES` at `:7062`. Its non-strict
branch (`:235`) is `message(WARNING)` — it drops the missing entry and
configures successfully. So `CMakeLists.txt` lists `Win32IDE_Tasks.cpp`
(`:6049`), `Win32IDE_Debugger.cpp` (`:5334`),
`src/cli/style/rawr_file_watcher.cpp` (`cmake/RawrRemainingStyleCli.fragment.cmake:16`)
— **none of which exist** — and the build reports success. A source list that
disagrees with the tree is precisely what an authority audit needs to see, and
this filter is what makes it invisible.

**B. Two translation units include headers that do not exist.**
`src/core/file_watcher.cpp:1` → `file_watcher.h` (absent).
`src/core/settings_persistence.cpp:1` → `settings_persistence.h` (absent).
`src/core/session_manager.cpp:2` includes the same absent header. All three are
outside the build, so the tree "looks complete" in a file listing while being
uncompilable if anyone ever wired them up.

---

## Gate

```
RAWRXD_IDE_P1_ITEM7_WORKSPACE_PROJECT_SUPPORT_001
SCOPE=9 capabilities
SOURCE_PRESENT=8   SOURCE_ABSENT=1
ORPHAN_SOURCE_NOT_LINKED=5
LINKED_AND_REACHABLE=1        (Win32IDE_Settings.cpp UI, persistence dead)
LINKED_BUT_UNREACHABLE=1      (ConfigurationValidator)
COMPILED_STUB=1               (IDEConfig.obj, 909 bytes)
SETTINGS_IMPLEMENTATIONS_COMPETING=4
SETTINGS_PERSISTENCE_EFFECTIVE=0
FILES_WITH_ABSENT_INCLUDES=3
CMAKE_ENTRIES_REFERENCING_ABSENT_FILES=3
RUNTIME_ARTIFACTS_PRODUCED_BY_SHIPPING_BINARY=1  (ide_chat_engine_status.txt only)
VERDICT=FAIL
```

**The shipping IDE has one reachable settings dialog, whose persistence path
has zero callers and therefore never writes a file. Every other capability in
this group is source on disk that no target compiles.**