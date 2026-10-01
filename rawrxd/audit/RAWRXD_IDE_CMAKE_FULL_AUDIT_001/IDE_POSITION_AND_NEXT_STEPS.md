# IDE Audit — Position Now, and Next Steps

    SCOPE            = RawrXD Win32 IDE, from the point the enterprise/audit work
                       was declared finished through the current working tree
    AUDIT_RECORD     = audit/RAWRXD_IDE_CMAKE_FULL_AUDIT_001/
    HEAD             = fcb5756cc
    DATE             = 2026-10-01
    VERDICT_KEYS     = RAWRXD_IDE_CMAKE_FULL_AUDIT_001 = IN_PROGRESS
                       PRODUCT_COMPLETION                   = FAIL

Both verdicts are reported separately and must not be conflated. The audit work
is substantial and mostly complete; the product is not.

---

## 1. What "finished" meant, and what it actually meant

The audit closed its own Batch 0–3 chain and wrote a completion checklist. The
checklist is explicit that discovery is not implementation:

> Rule: **discovery/audit work that actually happened is checked; implementation
> or certification that has not happened remains unchecked.** A "found the
> defect" checkbox is never upgraded to a "fixed the defect" checkbox.

That rule is the correct one and this report preserves it. The most important
consequence is in section 4: a large number of boxes are checked that describe
*knowledge*, not *repair*, and the difference between the two is where the
product actually stands.

---

## 2. Where the audit actually is, by area

### A. Deep2 generation lifecycle — D2 closed, D1/D3 open

```ini
D2_KV_RESET                        = PASS   (measured, 4 gens, 1 engine)
GENERATION_INHERITED_KV             = 0
ITEM_03_RESET_CLEARS_KV_ENTRIES    = FAIL_LITERAL
D1_RESULT_CONTRACT                 = OPEN
D3_EOS_TERMINATION                 = NOT_FIXED
TOKEN_DECODE_RETURNS_CR            = NOT_FIXED
```

D2 is genuinely closed. D1 and D3 are not: `ForwardFailure + completed=true`
remains reachable, and no test ever observed an EOS token — D3 "passes" only on
an `IS_EOS_OVERRIDE_PRESENT=1` invariant, never on observed behavior.

### B. CMake source coverage — measured, largely unreconciled

```ini
TOTAL_IMPLEMENTATION_FILES = 1968
BOUND                      =  616
UNBOUND                    = 1271
AMBIGUOUS                  =   81
MISSING_BOUND              =  360
WIN32IDE_SOURCES_DROPPED   =  225
ORPHAN_CMAKE_TREES         =    7
UNCONFIGURED_TARGETS       =   17
```

The 225 drops are now *visible* rather than silent: `rawrxd_filter_missing_sources`
prints a per-list warning, accumulates a global count, and honours
`-DRAWRXD_STRICT_SOURCES=ON` to make any drop `FATAL_ERROR`. The default stays
permissive, so **a clean configure still does not mean the shipping surface is
intact** — it means the drops were announced.

### C. `rawr` agentic CLI — the 85-source hole

The canonical entrypoint `src/cli/rawr_main.cpp` is missing, and
`target_sources(rawr ...)` suppresses the list. Consequence: **85 declared
agentic CLI sources are omitted with no CMake error.** Configure looks healthy
while the agentic CLI is absent from the binary. Unchecked: compile, link, run,
and prove both `rawr run` and `rawr agent` share one runtime core.

### D. Win32 IDE target topology — two competing definitions

`win32ide_strict/CMakeLists.txt` is **unreachable** from the shipping root.
Consequently `RawrXD-Win32IDE-Tests` and `RawrXD-Layer0-Final-Evidence` are
unreachable from the shipping root, and nothing in the build stops a
certification target from being defined in a tree no one configures.

### E. Build methodology — linked, but not deterministically

```ini
06_ide_build.log   0 compile errors, 0 link errors, 68 warnings
18_ctest_inventory.log   Total Tests: 0
```

The IDE binary links. But `--parallel 1` was not used for the authoritative
build (deviation recorded, not concealed), and **the test inventory is zero** —
so "the IDE builds" is currently the strongest runtime claim available, and
there is no ctest surface behind it.

### F. Runtime certification — measured, deliberately not certified

```ini
MEASURED_EXE                 = build_ide_audit\bin\Release\RawrXD-Win32IDE.exe
MEASURED_EXE_BYTES           = 20457984
MEASURED_RESPONDING          = 1
MEASURED_MAIN_WINDOW_HANDLE  = 26543562   (non-zero => window exists)
MEASURED_MAIN_WINDOW_TITLE   = RawrXD Win32 IDE
MEASURED_THREAD_COUNT        = 5
MEASURED_TERMINATION         = FORCED_BY_AUDIT
```

A window exists and the process responds. That is the ceiling. `IDECore_Shutdown`
has zero callers, no SHA-256 ties the binary to the build being certified, and
the smoke ended in a forced kill — so **no shutdown claim of any kind is
available**, and surfaces are individually PARTIAL or NOT_PRESENT.

### G. Response-coded agent — classification correctly withdrawn

Groundedness is `NOT_TESTABLE_YET`, and it should stay there. The Batch 3
retrospective records why, and the reason is decisive:

> nemotron-3.5-lightning:30b is a base (non-instruct) model. It is not designed
> to follow tool-call protocols. Greedy argmax on a base model on a short prompt
> yields degenerate repetition.

Observed output confirms it — `B[0] text=ing Innov Innov subs Innov photoseles…`.
**Certifying agent groundedness on a base model would produce a false pass.**
Batch 3D is INCONCLUSIVE (killed mid-inference, 16 min, no emission), and
3E/3F/3G never ran.

### H. Workspace / project support — mostly source that no target compiles

Repo-wide authority analysis of nine capabilities. Full evidence in
`P1_WORKSPACE_PROJECT_SUPPORT_AUDIT.md`.

| Capability | Verdict |
|---|---|
| multi-root workspace | ORPHAN (`workspace_model.cpp`, 481 L, 0 cmake refs, 0 callers, load is a stub) |
| filesystem watchers | PARTIAL/ORPHAN (4 impls; 1 includes an absent header, 1 has 0 includes, 1 is linked but never started) |
| workspace persistence | ORPHAN (`Win32IDE_Session.cpp` linked, 0 callers, no-ops on empty path) |
| task definitions / tasks.json | **ORPHAN, not missing** — 1190 L in `task_system.hpp`, 0 cmake refs, `loadConfig`/`saveConfig` are TODOs |
| launch configurations | ABSENT — zero symbols, zero files, repo-wide |
| unified settings | FRAGMENTED — 4 competing impls; the linked one has 0 `Settings_Load` callers, so it never persists |
| settings schema validation | UNREACHABLE — real 114 L validator, in 4 targets, sole caller in a file no target compiles |
| configuration migration | ABSENT in product — browser-only JS, generated caps return `true` with TODO bodies |
| per-project configuration | STUB — `IDEConfig.cpp` is 1 line, compiles to a 909-byte object |

```
RAWRXD_IDE_P1_ITEM7_WORKSPACE_PROJECT_SUPPORT_001=FAIL
ORPHAN_SOURCE_NOT_LINKED=5
LINKED_AND_REACHABLE=1   (settings UI; persistence dead)
SETTINGS_PERSISTENCE_EFFECTIVE=0
RUNTIME_ARTIFACTS_PRODUCED_BY_SHIPPING_BINARY=1  (ide_chat_engine_status.txt only)
```

Two corrections to `RAWRXD_IDE_PARITY_AUDIT_001`: §11's "task runner MISSING"
is **retracted** (a filename conclusion, not a capability conclusion), and §11's
"run configuration MISSING" is **confirmed**.

This also gives item 9 below a concrete instance. Three sources include headers
that do not exist anywhere in the tree — `file_watcher.cpp:1`,
`settings_persistence.cpp:1`, `session_manager.cpp:2` — and `rawrxd_filter_missing_sources`
(`CMakeLists.txt:201`, applied at `:7062`) drops three more absent entries
(`Win32IDE_Tasks.cpp:6049`, `Win32IDE_Debugger.cpp:5334`,
`src/cli/style/rawr_file_watcher.cpp`) with only `message(WARNING)` at `:235`.

### I. Settings persistence — CLOSED (`RAWRXD_SETTINGS_PERSISTENCE_001`)

The highest-severity finding from §2-H has been fixed and measured. Receipt:
`RAWRXD_SETTINGS_PERSISTENCE_001.md`.

`Settings_Load()` had **zero callers repo-wide**. `g_settingsPath` was assigned
only inside it, so `Settings_Save()` returned at its first line and every edit
made through the File > Settings dialog was discarded on exit.

Now: `Settings_EnsureLoaded()` runs at `WM_CREATE`, `Settings_Persist()` runs at
`WM_CLOSE`, path resolution is deterministic (`RAWRXD_SETTINGS_PATH` →
`%LOCALAPPDATA%\RawrXD\settings.ini` → exe dir), saves are atomic
(`ReplaceFileA` with a `MoveFileExA` fallback), and malformed input is counted
and — when nothing usable parses — quarantined to `<path>.bad` rather than
overwritten.

Four launches of the built binary, each in its own directory:

```
SETTINGS_LOAD_CALLED=1          (was 0)
SETTINGS_PATH_SET=1             (was 0)
SETTINGS_SAVE_EFFECTIVE=1       (was 0)
RESTART_VALUE_MATCH=1           (21 seeded -> 21 loaded -> 21 re-written)
EMPTY_DIR_FIRST_RUN_CREATES=1   (52-byte settings.ini)
PARTIAL_MALFORMED_COUNTED=1     (3 rejects counted, 1 good key preserved)
UNRECOVERABLE_QUARANTINED=1     (recovered=1, original preserved)
RUNS_EXECUTED=4   RUNS_VERDICT_PASS=4
VERDICT=PASS
```

Still open, unchanged: settings authority is **fragmented** (`UnifiedConfig` and
`settings_persistence.cpp` remain orphaned), schema validation is still
**unreachable**, and `main_win32.cpp` still does not exit after `WM_CLOSE`
(pre-existing, recorded in the receipt).

---

## 3. What is genuinely done

Worth stating plainly, because it is real and it is not nothing:

- The IDE **compiles and links** from a clean configure with announced drops.
- Deep2 **D2** is closed on measurement, not assertion.
- Source-coverage is **fully enumerated** (1968/616/1271/81/360) rather than
  guessed at, and the enumeration is reproducible from a configure log.
- The dropped-source count is now machine-greppable
  (`RAWRXD_DROPPED_SOURCE_TOTAL`) and can be made fatal on demand.
- Groundedness was **withdrawn** instead of certified — a false pass was avoided.
- The 3-batch claim conflicts were **audited against source** rather than
  accepted; four of eight external claims were contradicted by working-tree
  evidence, including two that would otherwise have been recorded as PASS.

---

## 4. The single most important structural finding

Two IDE CMake authorities exist and only one is reachable. The consequences are
not cosmetic:

1. Test and certification targets can be *defined and never built*. Nothing
   fails. A green configure plus a zero-test ctest inventory is exactly what an
   unreachable subtree looks like.
2. Certification that "depends on an unreachable CMake subtree" is possible by
   construction, and the audit has already classified two such targets.

This is the same class of defect as the worker-pool one just closed: **a
subsystem that reports success because nothing ever exercised it.** The
`RAWRXD_IDE_SOURCES` drops, the missing `rawr_main.cpp`, and
`Total Tests: 0` are three instances of one failure mode.

### 4.1 Why `win32ide_strict` cannot simply be bound — measured

The audit recorded this subtree as "unreachable" but did not establish *why*, and
the reason rules out the obvious fix. `win32ide_strict/CMakeLists.txt` is a
**standalone project** (line 15: `project(RawrXD-Win32IDE LANGUAGES CXX)`), and
it defines target names that the shipping root **already defines**:

| Target | in `win32ide_strict` | in root `CMakeLists.txt` | collision |
|---|---|---|---|
| `RawrXD-Win32IDE` | yes | yes | **yes** |
| `test_q2k_single_tensor_oracle` | yes | yes | **yes** |
| `RawrXD-Win32IDE-Tests` | yes | no | no |
| `RawrXD-Layer0-Final-Evidence` | yes | no | no |
| `RawrXD-ProductionProfiler-Test` | yes | no | no |

So `add_subdirectory(win32ide_strict)` cannot work as-is: CMake rejects a
duplicate target name at configure time. The subtree must be re-homed with
**renamed** targets, or retired and its unique tests moved into the root. Binding
it unchanged trades a silent unreachability for a hard configure failure — a
better failure, but still not a fix.

This also means `RawrXD-Layer0-Final-Evidence` and `RawrXD-Win32IDE-Tests` are
the *only* definitions of those targets anywhere, and neither is reachable from
the shipping root. They are not duplicated elsewhere; they are simply absent.

---

## 5. Next steps, in dependency order

Each step names the gate it closes and the evidence that would close it. Nothing
here is claimed as done.

### P0 — establish one IDE build authority (unblocks E, F, and all IDE runtime work)

1. Bind `win32ide_strict` from the shipping root, or delete it and re-home its
   targets. **Close:** `--target help` lists every intended shipping and test
   target from the canonical root.
2. Prove no production certification depends on an unreachable subtree.
   **Close:** a receipt enumerating every certification target and its
   reachability, with `UNREACHABLE_CERTIFICATION_TARGETS=0`.
3. Restore `src/cli/rawr_main.cpp` and bind the 85 agentic CLI sources.
   **Close:** configure shows the surface present; `rawr` compiles, links, and
   both `rawr run` and `rawr agent` execute.
4. Make `Total Tests: 0` non-acceptable. **Close:** `ctest` enumerates a
   non-zero, named inventory.

### P1 — close the lifecycle chain (unblocks IDE chat, streaming, cancellation)

5. D1 result-state invariants. **Close:** the four forbidden predicates are
   proven unreachable, not merely unobserved — currently
   `ForwardFailure + completed=true` is reachable at `Deep2Engine.cpp:4118`.
6. D3 EOS termination on an observed token, plus CR-return fix.
   **Close:** a generation that terminates on EOS *below* the token ceiling,
   with the EOS token id logged.

### P2 — repair the shipping surface (unblocks I)

7. Reconcile the 225 dropped `WIN32IDE_SOURCES`: restore the files or remove the
   entries. **Close:** `RAWRXD_DROPPED_SOURCE_TOTAL=0` under
   `-DRAWRXD_STRICT_SOURCES=ON`, which is already fatal-capable today.
8. Classify all 1271 unbound files as intentionally excluded or wrongly unbound;
   resolve the 81 ambiguous and 360 missing-bound references.
9. Remove every silent `EXISTS` gate that hides a required production subsystem.

### P3 — runtime certification (only after P0/P1)

10. Launch the freshly built IDE, take SHA-256 against the build being
    certified, exercise each surface, and shut down **cleanly**.
    **Close:** `IDECore_Shutdown` has a caller and returns; no process or thread
    survives; `MEASURED_TERMINATION=NORMAL`.

### P4 — agentic certification (only after P1, on an instruct model)

11. Re-scope Batch 3 to instrument the engine, not the model. Pass criterion per
    the retrospective: either the response contains
    `RAWR_TOOL name=git_status`, **or** it does not and the engine correctly
    parsed the absence and reported zero tool calls. Either outcome is a pass;
    only a silent mis-parse is a failure.
12. Use an instruct model, or add a few-shot regime. A base model cannot
    validate instruction-following, and running that validation anyway is what
    produces a false groundedness pass.

---

## 6. Gates that remain closed regardless of the above

Per the corrected ledger, these stay closed and are not advanced by anything in
this report:

```ini
RAWRXD_RECEIPT_IMMUTABILITY_AUTHORITY_001 = RETRACTED_FALSE_PASS
RAWRXD_SINGLE_WRITER_AUTHORITY_001         = FAIL_RECURRING
SAFE_TO_PROMOTE_RECEIPT_IMMUTABILITY       = 0
SAFE_TO_W8_CERTIFY                        = 0
SAFE_TO_GPU                               = 0
```

## 7. Authority — IDE

```ini
IDE_COMPILE_AND_LINK            = PASS (measured, 06_ide_build.log)
IDE_CMAKE_AUTHORITY_CANONICAL   = NOT_ESTABLISHED (2 competing roots, 1 reachable)
IDE_AGENTIC_CLI_SURFACE         = DROPPED_85_SOURCES
IDE_CTEST_TESTS                 = 0
IDE_CLEAN_SHUTDOWN              = NOT_EXERCISED
IDE_D2                          = PASS
IDE_D1                          = OPEN
IDE_D3                          = NOT_FIXED
AGENTIC_GROUNDEDNESS            = NOT_TESTABLE_YET (base model; correctly withdrawn)

RAWRXD_IDE_CMAKE_FULL_AUDIT_001 = IN_PROGRESS
PRODUCT_COMPLETION              = FAIL
```