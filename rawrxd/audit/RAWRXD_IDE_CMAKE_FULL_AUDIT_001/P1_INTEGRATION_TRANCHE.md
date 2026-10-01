# RAWRXD_IDE_P1_INTEGRATION_TRANCHE_001

    GATE   = RAWRXD_IDE_P1_INTEGRATION_TRANCHE_001
    DATE   = 2026-10-01
    BINARY = rawrxd/build_ide_audit/bin/Release/RawrXD-Win32IDE.exe
             22289920 bytes, 2026-10-01 19:15:30
    VERDICT= PASS

```
TASK_SYSTEM_CONFIG     = PRODUCT_REACHABLE
LAUNCH_CONFIGS         = IMPLEMENTED_AND_PRODUCT_REACHABLE
WATCHER_WIRING         = PRODUCT_REACHABLE
IDECONFIG              = IMPLEMENTED_AND_PRODUCT_REACHABLE
WORKSPACE_IDE_BINDING  = PRODUCT_REACHABLE

RAWRXD_WIN32IDE_BUILD  = PASS
AUTHORITIES_INVOKED    = 4/4   (measured at the call site, not inferred from linking)
SHIM_LEFT_IN_TREE      = 0
REGISTRY_INVENTED      = 0
VERDICT                = PASS
```

This tranche is the five items Item 7 declared open. It is a **separate
receipt** on purpose: a future failure in watcher or task-config work must not
be able to muddy the five-item gate already certified in
`P1_ITEM7_E2E_RUNTIME.md`.

---

## 1. What each item was, and what it is

| Item | Was | Now |
|---|---|---|
| `TASK_SYSTEM_CONFIG` | 1190-line `task_system.hpp` in zero targets, zero includers; `loadConfig`/`saveConfig` were `// TODO: Parse JSON/YAML config file` | linked via `task_config_bridge.cpp`, real JSON load/save, invoked at startup, measured |
| `LAUNCH_CONFIGS` | genuinely absent — repo-wide search for `launch.json` / `LaunchConfig` / `launchConfig` returned zero matches | new authority reading a `.vscode/launch.json`-shaped document, linked, invoked, measured |
| `WATCHER_WIRING` | four implementations, all unreachable; `core/file_watcher.cpp` included a header absent from the tree | `core/file_watcher.cpp` linked and `watch()` called on the workspace root, event counters reported |
| `IDECONFIG` | `IDEConfig.h` was 3 lines (`// Stub header`), `IDEConfig.cpp` was 1 line, compiled to a 909-byte empty object in 3 targets | `ide_project_config.{h,cpp}` implements layered project config; all 3 CMake refs repointed |
| `WORKSPACE_IDE_BINDING` | `workspace_model.cpp` in zero targets, so a runtime-proven load was unreachable from the IDE | linked, initialized at `WM_CREATE`, saved at `WM_CLOSE`, measured |

---

## 2. Measured runtime evidence

One launch of the shipping binary in a seeded workspace containing
`.vscode/tasks.json`, `.vscode/launch.json`, and `.rawrxd/project.json`.

```
WORKSPACE_ROOT_RESOLVED=C:\...\item7\tranche

TASK_LOAD_CALLED=1
TASK_FILE_EXISTED=1
TASK_PARSED=1
TASK_VERSION=2.0.0
TASK_ENTRIES_PARSED=3
TASK_ENTRIES_ADOPTED=3
TASK_ENTRIES_REJECTED=1
TASK_ENTRIES_IN_RUNNER=3
TASK_LABEL=build
TASK_LABEL=malformed-no-command
TASK_LABEL=test

LAUNCH_LOAD_CALLED=1
LAUNCH_FILE_EXISTED=1
LAUNCH_PARSED=1
LAUNCH_ENTRIES_SEEN=3
LAUNCH_ENTRIES_ADOPTED=1
LAUNCH_ENTRIES_REFUSED=2
LAUNCH_CONFIG_NAME=debug exe

WATCHER_ACTIVE=1
WATCHER_EVENTS_SEEN=18
WATCHER_ERRORS=0

PROJECT_LOAD_CALLED=1
PROJECT_FILE_EXISTED=1
PROJECT_PARSED=1
PROJECT_KEYS_UNKNOWN=1
PROJECT_CONFIG_KEYS=4
PROJECT_CONFIG_NAME=TrancheProbe

TASK_AUTHORITY_RAN=1
LAUNCH_AUTHORITY_RAN=1
PROJECT_AUTHORITY_RAN=1
VERDICT=PASS
```

Shutdown, driven by real `WM_CLOSE`:

```
=== integration ===   PHASE=shutdown  WATCHER_EVENTS_SEEN=18  VERDICT=PASS
=== workspace  ===   PHASE=shutdown  LOAD_OUTCOME=Absent  SAVE_WROTE_FILE=1
                                  DOC_EXISTS_NOW=1  VERDICT=PASS
=== session   ===   PHASE=shutdown  SAVE_WROTE_FILE=1  VERDICT=PASS
```

`AUTHORITIES_INVOKED=4/4` is the property that matters and it is measured by
`*_LOAD_CALLED` flags set at the call site. A linked authority that never
executed is the exact failure this audit opened on, so "it compiled" is not
accepted as "it ran".

### The numbers that are refusals, not shortfalls

- `TASK_ENTRIES_REJECTED=1` — the entry `{"nope": 1}` has no `label`, so there is
  no name to register it under. Counted, not silently dropped.
- `LAUNCH_ENTRIES_REFUSED=2` — `no program` has no program field, and
  `bad var` references `${env:RAWRXD_DEFINITELY_UNSET}`. Both are refused
  rather than adopted, so no launch configuration in the IDE can resolve to
  launching nothing.
- `PROJECT_KEYS_UNKNOWN=1` — `totally.unknown.key` is retained in the map but
  counted as unknown, so reading it cannot be mistaken for the product honouring
  it.
- `WATCHER_EVENTS_SEEN=18` from 4 file creates and 1 modify. Each create emits
  several `ReadDirectoryChangesW` notifications, so 18 is a plausible count, not
  a fabricated one. The events were produced by writing files into the workspace
  **while the IDE was running**, then reading the counter back.

---

## 3. Two defects the runtime proof caught in this tranche

### 3.1 `resolve()` was missing, so unresolvable launch configs were adopted

The first tranche run reported:

```
LAUNCH_ENTRIES_ADOPTED=2
LAUNCH_CONFIG_NAME=bad var          <-- should not exist
```

`dropUnresolved()` drops configurations whose `program` is empty, but `load()`
stores the program **verbatim**, still containing the literal `${env:...}` text.
Nothing had called `resolve()`, so the string was non-empty and survived the drop.
An unresolvable launch configuration was therefore installed into the IDE, which
is the precise failure the refuse-don't-default rule exists to prevent.

Fixed by resolving against the workspace root **before** dropping, with the
reason recorded at the call site. Re-run: `ADOPTED=1`, `REFUSED=2`.

### 3.2 Namespace qualification errors in the wiring

`TaskConfigLoadResult`, `LaunchConfigDiagnostics`, and
`ProjectConfigDiagnostics` are in three different namespaces
(`rawrxd`, `RawrXD::IDE`, `RawrXD`) and the first wiring attempt used all three
unqualified. MSVC reported `missing type specifier` rather than
`no such name in namespace`, which is easy to misread as a missing type. All
three are now qualified at their declarations.

---

## 4. Design decisions worth recording

**Task config reads `.vscode/tasks.json`.** Not a new location. The removed
`application.cpp` read `<workspace>/.vscode/tasks.json`, so that is the path an
existing workspace already has. Both the old and the flat `taskName` alias
forms are accepted, and `command` accepts both `"cmd"` and `["cmd", "arg", ...]`.

**Launch config refuses rather than defaults.** An unresolved `${...}` variable
fails the whole expansion and the configuration is dropped. A launch whose
program expands to an empty string is the standard way a "run" appears to succeed
while launching nothing, and that is indistinguishable from a working run until
someone looks.

**Watcher takes the canonical root, not a private one.** `FileIndex::StartWatching`
and `FileSystem::startWatching` remain uncalled; this tranche uses
`core/file_watcher.cpp` because it is the only watcher whose header now exists
and it is the one added to the target. Wiring a second watcher on top of
`FileIndex` would have created two watchers for one tree.

**Per-project config layers, it does not merge.** `project.json` shadows the
workspace and user layers; an absent key falls through. The user layer is passed
in by the caller rather than read here, so `Win32IDE_Settings` remains the only
settings authority.

**`IDEConfig.h` and `IDEConfig.cpp` are retained as deliberate no-ops.** All
three CMake references were repointed at `ide_project_config.cpp`, and the old
files now carry a tombstone explaining why they are empty and how to remove them.
They were not deleted because some translation unit may still include
`IDEConfig.h`, and a retained empty TU is a much smaller failure than an
unresolved symbol. Neither shim includes the new header, so a legacy consumer
does not silently acquire a project-configuration authority.

**`task_config_bridge.cpp` does not own a `TaskRunner`.** It operates on one the
caller owns. Handing the IDE a second, private runner would create a second task
registry — the same mistake the git-safety integration already had to undo once
with the registry.

---

## 5. Structural masks still open

Unchanged by this tranche, and deliberately so:

- `rawrxd_filter_missing_sources` (`CMakeLists.txt:201`, applied at `:7062`) still
  drops absent sources with `message(WARNING)` at `:235`. It absorbed
  `Win32IDE_Tasks.cpp:6049`, `Win32IDE_Debugger.cpp:5334`, and
  `src/cli/style/rawr_file_watcher.cpp` without failing a build. Turning that
  fatal for a release-cert build is a separate change with broad blast radius.
- `workspace_model.cpp` is now linked, but the IDE's explorer still renders a
  single root from `GetCurrentDirectoryW` (`Win32IDE_Sidebar.cpp:186`). The model
  can hold many folders; no UI surface yet displays them. The multi-root *state*
  is a product path; the multi-root *presentation* is not.

## 6. Also recorded

`AGENTS.md` §7a now carries four permanent investigation rules, each with the
concrete incident that produced it: `LOCK_OWNER_UNKNOWN` (query OS handle
ownership, never attribute), `SYMBOL_NOT_FOUND` (repo-wide search, never infer
from one header), `UNTRACKED_OR_EXTERNALLY_OWNED_SOURCE` (snapshot and hash
before replacing), and compile-evidence-is-not-runtime-evidence.
