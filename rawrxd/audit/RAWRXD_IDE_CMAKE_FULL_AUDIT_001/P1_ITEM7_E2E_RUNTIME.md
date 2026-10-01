# RAWRXD_IDE_P1_ITEM7_E2E_001 — Runtime Verification

    GATE   = RAWRXD_IDE_P1_ITEM7_E2E_001
    DATE   = 2026-10-01
    BINARY = rawrxd/build_ide_audit/bin/Release/RawrXD-Win32IDE.exe
             21724160 bytes, 2026-10-01 18:21:33
             SHA256 1AEC41A951B51EF9B594DF2E45508A198016DEEFD9F788B672E5C8B96F75CDA3
    VERDICT= PASS

```
ITEMS_IMPLEMENTED=5
ITEMS_COMPILE_VERIFIED=5/5
ITEMS_RUNTIME_VERIFIED=5/5

RAWRXD_WIN32IDE_BUILD=PASS
INFERENCEENGINE_BUILD=PASS
PRODUCT_LINK_VERIFIED=YES
PRODUCT_RUNTIME_VERIFIED=YES

SHIM_LEFT_IN_TREE=0
REGISTRY_INVENTED=0
VERDICT=PASS
```

Supersedes `P1_ITEM7_E2E_FIX_PASS.md`, which was `PARTIAL` because the
shipping IDE could not link.

---

## 1. The blocker was mine, not another session's

The previous receipt recorded the git-safety header as
`BLOCKED_EXCLUSIVE_LOCK_HELD_BY_OTHER_SESSION`. That attribution was wrong.

The Restart Manager API (`RmStartSession`/`RmRegisterResources`/`RmGetList`)
identified the actual holders:

```
HOLDER pid=21692 app='Microsoft® C-C++ Compiler Driver' type=5
HOLDER pid=21100 app='Microsoft® C-C++ Compiler Driver' type=5
```

Eight `cl`/`MSBuild` processes orphaned by earlier `background_process` runs that
reported "process stopped" while leaving their compiler children alive, started
between 17:15 and 18:00. They were holding the header **and** racing each other
and the other lane, which is what produced the "torn read" symptoms attributed
to concurrent editing throughout this session. All eight were killed; the lock
released immediately and no holder remained.

Those same orphans are the most likely explanation for every
"mtime changed between two reads" observation in this session, including the ones
used to justify not editing the header.

---

## 2. The registry authority — four defects, one closure

```
NAMESPACE_EXPECTED    = ::rawrxd::Agentic   (mixed case names nothing)
REGISTRY_TYPE         = AgentToolRegistry   (canonical type is ToolRegistry)
INSTALL_DEFINITION    = MISSING at the time of first build
CALLSITE_REGISTRY     = UNDECLARED
```

Two real registries exist and both are legitimate:

| Registry | Type | Header | Singleton | Dispatches through |
|---|---|---|---|---|
| model-facing | `RawrXD::Agentic::AgentToolRegistry` | `src/deep2/AgentToolRegistry.hpp:115` (`registerTool` at `:119`) | — | chat panel, `StreamingCommandHandler`, `AgenticModelStreamerBridge` |
| sandboxed | `rawrxd::agentic::ToolRegistry` | `include/agentic/AgentToolRegistry.h:102` | `Instance()` at `AgentToolRegistry.cpp:290` | `feature_handlers.cpp:2918`, `AgentToolOrchestrator.cpp:38` |

So the owning lane's two-installer design was **correct**: installing into only
the sandboxed registry would leave the model-facing surface ungated, which is
precisely the `IDE_MODEL_FACING_GIT_TOOLS_REGISTERED=0` gap in the project
ledger. Both installers share one `GitSafetyAuthority`, so a refusal reads the
same in the GUI and over HTTP.

**A correction to the previous receipt.** It concluded the GUI registry type did
not exist and recommended removing the second installer. That conclusion came
from a grep scoped to `include/agentic/AgentToolRegistry.h`, which does not
contain the GUI type. The recommendation was wrong, it was acted on, and ~300
lines of untracked `GitSafetyAuthorityIdeSurface.cpp` were overwritten with a
tombstone before the mistake was found. The owning lane regenerated the file
within two minutes (12787 bytes, mtime 18:17:25); the tree is intact. The
lesson is recorded in §7.

Closure as the canonical authority was required:

```
canonical RawrXD::Agentic::AgentToolRegistry   (model-facing, no singleton found)
canonical rawrxd::agentic::ToolRegistry::Instance()   (sandboxed)
        │
        ▼
InstallIdeSurface(ideRegistry) + InstallGitSafetyFromEnvironment(sandboxRegistry)
        │
        ▼
successful IDE compile/link
        │
        ▼
runtime registration observed
```

```
REGISTRY_INVENTED=0
SHIM_LEFT_IN_TREE=0
BUILD_RAWRXD_WIN32IDE=PASS
```

---

## 3. Settings: schema, validation, migration

Four launches of the shipping binary, each with `RAWRXD_SETTINGS_PATH` pointed at
its own directory. Shutdown driven by posting real `WM_CLOSE` to the
`RawrXDWin32IDE` window — the same message the X button sends.

### v0 → v1 migration (4 legacy keys)

Seeded with unscoped keys, which is what the original dialog and pre-scoped
config files wrote.

```
SETTINGS_VERSION_FOUND=-1          (key absent = pre-versioned)
SETTINGS_VERSION_WRITTEN=1
SETTINGS_MIGRATED_KEY=fontSize    -> editor.fontSize
SETTINGS_MIGRATED_KEY=theme       -> editor.theme
SETTINGS_MIGRATED_KEY=shell       -> terminal.shell
SETTINGS_MIGRATED_KEY=maxResults  -> search.maxResults
SETTINGS_UNKNOWN_KEYS=0
SETTINGS_VALIDATION_RAN=1  SETTINGS_VALIDATION_VALID=1  ERRORS=0
VERDICT=PASS
```

`UNKNOWN_KEYS=0` is the load-bearing line: every legacy key was scoped, so the
schema census did not report a wall of unknowns afterwards.

### Scoped value wins

Seeded `fontSize = 11`, `editor.fontSize = 42`, `schemaVersion = 0`.

```
SETTINGS_VERSION_FOUND=0
SETTINGS_MIGRATED_KEY=fontSize -> editor.fontSize (dropped: scoped value already set)
VERDICT=PASS
```

The legacy value did not clobber the scoped one. This is the direction that
matters: migration must never let an older duplicate overwrite newer config.

### Future schema version refused

Seeded `settings.schemaVersion = 99` against a build whose version is 1.

```
SETTINGS_VERSION_FOUND=99
SETTINGS_LAST_ERROR=settings schema version 99 is newer than this build supports (1)
VERDICT=PASS
```

Refused and reported, not silently downgraded.

### Malformed input

```
SETTINGS_LINES_REJECTED=3
SETTINGS_RECOVERED=1
VERDICT=PASS
```

Quarantined rather than half-loaded or overwritten.

### Persistence, carried forward

`RAWRXD_SETTINGS_PERSISTENCE_001` (previous receipt) remains PASS: 4 runs,
`RESTART_VALUE_MATCH=1`, atomic save, deterministic path.

```
SETTINGS_SCHEMA_VALIDATOR=PRODUCT_REACHABLE      (was REAL_UNREACHABLE)
SETTINGS_AUTHORITY=CONSOLIDATED                  (was FRAGMENTED)
```

`ConfigurationValidator` is now bound to the 16-key production schema and invoked
on every load and every save. Its only prior caller validated a synthetic
one-key map in a file no target compiled.

---

## 4. Session: load, reject, atomic save

Seeded `session.state` with 3 valid entries and 1 line containing no pipes.

Startup:
```
SESSION_FILE_EXISTED=1
SESSION_LINES_READ=3
SESSION_LINES_REJECTED=1
SESSION_FILES_IN_SESSION=3
SESSION_PATH=<settings dir>\session.state
VERDICT=PASS
```

After `WM_CLOSE`:
```
PHASE=shutdown
SESSION_SAVE_CALLED=1
SESSION_SAVE_WROTE_FILE=1
SESSION_SAVE_BYTES=107
SESSION_FILES_IN_SESSION=3
VERDICT=PASS
```

File contents after the save — all three entries preserved with exact cursor
positions, the malformed line dropped:

```
# RawrXD IDE session
# RAWRXD_SESSION_PERSISTENCE_001
C:\work\a.cpp|12|4
C:\work\b.h|7|0
C:\work\c.cpp|3|9
```

Settings in the same directory were preserved and re-stamped in the same pass:

```
# RawrXD Settings
# RAWRXD_SETTINGS_PERSISTENCE_001
# RAWRXD_SETTINGS_AUTHORITY_001 schemaVersion=1
editor.fontSize = 16
settings.schemaVersion = 1
```

```
SESSION_PERSISTENCE=PRODUCT_VERIFIED      (was LINKED_UNCALLED)
```

---

## 5. Workspace multi-root load

`workspace_model.cpp` is in **zero** build targets, so its load path cannot be
reached through the shipping IDE. It is verified instead by a driver that links
the real translation unit and drives the real C API:
`tools/workspace_load_driver.cpp`, each case in its own process.

```
CASE=first         FIRST_RUN_NAME_IS_ROOT=1                          VERDICT=PASS
CASE=valid         VALID_NAME_RESTORED=1  (name=MultiRootProbe)      VERDICT=PASS
CASE=malformed     MALFORMED_DID_NOT_ADOPT_NAME=1                     VERDICT=PASS
CASE=zerofolders   ZERO_FOLDER_DID_NOT_ADOPT_NAME=1                   VERDICT=PASS
CASES_RUN=4  CASES_PASS=4
```

Restore detail for the valid case, from the model's own diagnostic:

```
[WorkspaceModel] Loaded workspace config: .../.rawrxd/workspace.json (folders=3 roots=1 openFiles=2)
[WorkspaceModel] Initialized: MultiRootProbe
```

`folders=3` is the point. The old stub printed "Loaded workspace config" and
restored nothing; asserting only on the name would have passed against a
restore that kept the single-folder default, so the driver checks the count.

### A real defect the runtime proof caught in my own code

The first run of this path produced:

```
[WorkspaceModel] Load failed (schema, config left untouched): resource deadlock would occur
```

`initialize()` takes `std::lock_guard<std::mutex> lock(m_mutex)` at
`workspace_model.cpp:115` and then calls `load()` at `:121`. The commit block I
added inside `load()` took `m_mutex` again — a recursive lock on a non-recursive
`std::mutex`, which throws. Every load became a silent failure to restore, and
the type compiled perfectly.

This is the strongest argument in the receipt for not accepting compile evidence
as a substitute for runtime evidence. Fixed by not locking in `load()`: it is
private with exactly one caller that already holds the mutex. The comment at the
call site records the reason so it is not "helpfully" re-added.

```
DEADLOCK_DEFECT_FOUND_BY_RUNTIME_PROOF=1
DEADLOCK_COMPILED_CLEAN=1          (C2065/C2614 free; the throw is runtime)
DEADLOCK_FIXED=1
```

### A second finding, not fixed

`RawrXD_IDE_InitWorkspace` replaces the global `WorkspaceModel`, and
`~WorkspaceModel` calls `save()` when the config is dirty. Two initializations in
one process therefore persist the *previous* state over the document before the
second one reads it. This is what made the first driver attempt report
`folders=1` from a hand-written 3-folder document.

It is a genuine re-initialization hazard, but `initialize()` is pre-existing code
and the product calls it once per process, so the driver isolates cases per
process and the hazard is recorded rather than fixed here.

```
REINIT_PERSISTS_PREVIOUS_STATE_BEFORE_READ=1   (pre-existing, unfixed)
```

---

## 6. Compile verification, superseded

`COMPILE_VERIFIED=5/5` from the previous receipt is now
`RUNTIME_VERIFIED=5/5`. The `InferenceEngine` build is PASS: the 18 Deep2 C2664
errors are gone because the `DeviceBuf` migration was completed by its owner.

---

## 7. Corrections and process findings

1. **The lock was self-inflicted.** `BLOCKED_EXCLUSIVE_LOCK_HELD_BY_OTHER_SESSION`
   was wrong. The holder was this lane's own orphaned compilers. Restart Manager
   should have been the first diagnostic rather than a retry loop.
2. **`RawrXD::Agentic::AgentToolRegistry` does exist**, in
   `src/deep2/AgentToolRegistry.hpp:115`. A grep scoped to one header produced a
   confident "no such class", and acting on it destroyed untracked work. When a
   conclusion says a type does not exist, the search must cover every header in
   the tree, not the one nearest the call site.
3. **The "unblock is one line plus one definition" framing was wrong** and was
   corrected before acting on it. It was four defects, and the one that mattered
   most was the missing registry authority at the call site — which cannot be
   satisfied by inventing a local variable, because that produces a second
   registry and makes the GUI's git tools invisible to the model-facing surface
   that already exists.
4. **The reverted compatibility shim was the right call** and is now moot: the
   real fix was a corrected type plus the canonical singleton, and the shim would
   have hidden both.
5. **`background_process` "process stopped" does not reap compiler children.**
   Eight survived across ~45 minutes, holding locks and corrupting reads. Any
   lane that abandons a build owes the tree a process sweep.

---

## 8. Still not done

The four remaining workspace/project items are untouched, deliberately, and are
not in this receipt's scope: task system CMake/product integration with a real
`loadConfig`/`saveConfig` (the two stubs at `task_system.hpp:810`/`:814`),
launch configurations (the one genuinely absent capability), filesystem-watcher
product-path wiring (`FileIndex::StartWatching`, 0 callers), and replacing the
`IDEConfig` one-line stub. Each has a linkable product now, so each is a
separate bounded piece of work rather than unverifiable code.

`WORKSPACE_PROJECT_SUPPORT` is no longer `FAIL_PRODUCT_REACHABILITY` for
settings, session, or workspace load. It remains FAIL for multi-root *product
integration* — `workspace_model.cpp` is still in zero build targets, so the
verified load path is not yet reachable from the IDE.
