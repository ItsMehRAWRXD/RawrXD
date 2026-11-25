# RawrXD — Work Packages 3–10 (2026-11-25)

Companion to `AUDIT_IDE_FULL_2026-11-25.md`. These are **specifications, inventories and acceptance
tests** — they advance readiness but **do not close any of the 58 backlog tasks**. State separation:
`PATCHED ≠ BUILT ≠ TESTED ≠ CERTIFIED`. No backlog item is promoted by this document.

---

## Package 3 — LSP regression coverage (spec; execution needs MSVC)

Target: `Win32IDE_LSPClient.cpp` strict `Content-Length` parser (lines ~774–798). The parser now accepts
only pure decimal digits, bounded by `kMaxLspMessage = 256 MB`, rejecting empty/alpha/negative/zero/
overflow/trailing-garbage, dropping the frame on reject.

| # | Input `Content-Length` | Expected |
|---|------------------------|----------|
| 1 | `Content-Length: 42` | Process normally (42) |
| 2 | `Content-Length:` (empty) | Reject safely (0), frame dropped |
| 3 | `Content-Length: abc` | Reject safely |
| 4 | `Content-Length: 99999999999999999999` | Reject (overflow) before allocation |
| 5 | `Content-Length: -5` | Reject safely |
| 6 | `Content-Length: 0` | Reject safely |
| 7 | `Content-Length: 123abc` | Reject (trailing garbage) |
| 8 | `Content-Length: 268435457` (>256 MB) | Reject before allocation |
| 9 | malformed frame, then valid frame | Recover: bad frame dropped, next frame parsed |
| 10 | repeated malformed frames | No crash, no unbounded allocation |

**Open caveat (from review):** dropping a bad header does not guarantee byte-stream resync if the bad
frame carried an unknown-length body; case 9 must verify recovery vs. reconnect. 256 MB ceiling should be
checked against real LSP payloads (large `textDocument/didChange`).

## Package 4 — Crash diagnostic acceptance (spec; execution needs MSVC)

Target: consolidated `RawrxdCrashFilter` (`main_win32.cpp:306-331`) → chains to `rawrxdUnhandledException`
(minidump, `:15-128`); single install at `:338`.

| # | Fault injection | Expected |
|---|-----------------|----------|
| 1 | Null deref on a worker thread | `IDE_CRASH.log` witness line (code/addr/module/tid) + minidump + `exception_stack.txt` |
| 2 | Fault with no PDB | Witness + module+RVA still emitted (non-zero log) |
| 3 | `EXCEPTION_BREAKPOINT` | Filter returns CONTINUE_SEARCH (no false dump) |
| 4 | Stack overflow | External capture (WER LocalDumps) — CRT filter may not run |
| 5 | Terminating code path | Process ends with `EXCEPTION_EXECUTE_HANDLER` after dump |

**Open caveat:** `fopen_s`/`fputs` may allocate/lock internally; not strictly heap/lock-free. External
crash capture (WER `LocalDumps` under `HKLM\...\Windows Error Reporting`) is still required for fail-fast
and stack-overflow cases.

## Package 5 — Completion pipeline routing (verified trace)

| Path | Status | Chain |
|------|--------|-------|
| **Ghost text** (`NativeGhostTextController`) | **WIRED end-to-end** | `onEditorChanged`→`WM_TIMER kGhostTimer`→`requestCompletion`→`m_request` (`GhostTextIntegration.cpp:49-134`)→`requestNativeGhostText` (Ollama `generateSync` / `generateResponseAsync`)→`PostMessage kGhostResult`→`showCompletion`→`accept()` `EM_REPLACESEL` (`GhostText.cpp:369-422`); cancel via `m_cancelActive` (`:333-367`) |
| **InlineCompletionEngine** | **DEAD** | `instance()`/`requestSuggestion`/`onModelResponse` have zero callers; `0xC001` timer has no handler |
| **Code-completion popup** | **KEYWORD-ONLY + dead trigger** | `requestHybridCompletion` returns static list (`CompletionHelpers.cpp:14-35`); `triggerCodeCompletion` only from `WM_TIMER 9999` (`Core.cpp:1405`) which is never armed |
| **RealTimeCompletionEngine** | **DROPS model output; not on Win32 path** | `getCompletions` overwrites with empty `postProcessCompletions` (`real_time_completion_engine.cpp:42-47,345-356`); used only by `benchmark_runner.cpp` + Qt |

**Conclusion:** model output is **not** dropped on the live (ghost-text) path. The popup is keyword-only and
unreachable; the only model-output drop is in the unused `RealTimeCompletionEngine`.

## Package 6 — Build integrity (classification; conversion needs build)

Root `CMakeLists.txt`: **179** `EXISTS` guard blocks (~8 REQUIRED, ~164 OPTIONAL, ~7 OBSOLETE) + **11**
`if(FALSE)` blocks. `src/CMakeLists.txt` is vendored GGML (0 guards). `RAWRXD_BUILD_TESTS` defaults **OFF**
(`:339`); `tests/` is referenced but CTest registration is off until `-DRAWRXD_BUILD_TESTS=ON`.

**Product-critical guards (fail-fast candidates):**
| Line | Guards | Class | Risk |
|------|--------|-------|------|
| 3247 | `deep2_engine_lib` / `Deep2Engine.cpp` | REQUIRED | **No else() → silent omit** |
| 3069 | `rawrxd_gpu_compute` / `vulkan_compute.cpp|.h` | REQUIRED | **No else() → silent omit** |
| 5925 / 6030 | `RawrXD-CLI-V2` | REQUIRED | silent CLI drop |
| 570 | ggml submodule | REQUIRED | only WARNING at 658 |
| 6204 | `rawr-reap` | REQUIRED | silent |
| 3575 | `deep2_openai_server` | REQUIRED | silent |
| 798 / 805 | `rawrxd_production_hardening` / `rawrxd_computer_use` | REQUIRED | STATUS only; IDE link skipped |
| 4305 | `RawrXD-ExtensionHost` | product-adjacent | silent |

**IDE target:** NOT silently droppable on MSVC — missing sources hit `FATAL_ERROR` at `4086-4091`. Residual:
no `else()` on the non-MSVC branch (`:3823`).
**Biggest silent-omission path:** Deep2 engine (stacked guards 3069+3247, no else, dependents all
`if(TARGET deep2_engine_lib)`-guarded → IDE/CLI build green without Deep2).
**Recommendation:** convert the 8 REQUIRED guards to `FATAL_ERROR` when the product is requested
(`RAWRXD_BUILD_DEEP2_ENGINE`/`RAWRXD_BUILD_WIN32IDE`), keep OPTIONAL as skip-with-STATUS. **Not applied**
(needs compile/link verification; ENABLE_VULKAN=OFF is a valid config so fail-fast must be conditional).

## Package 7 — Session persistence (integration spec)

Two writers, two files, divergent schemas:
- **Full (orphaned):** `Win32IDE_Session.cpp` → `%APPDATA%\RawrXD\session.json`, `version=2/schema 2.2`.
- **Shipped:** `Win32IDE_FileOps.cpp` `saveIdeSession`/`loadIdeSession` → `ide_session.json` (NativeProfile),
  atomic + 96 KB gate + corruption recovery.

**Capabilities only in full version:** cursor/scroll/first-visible-line, syntax prefs, annotations, theme/
transparency, loaded-model restore, working-directory, window geometry via SettingsManager.
**Capabilities only in shipped (must not regress):** unsaved document text, chat sessions/checkpoints/step
rows, atomic write + recovery.

**Blockers to wiring full version:** (1) `Session.cpp` references members/functions **not declared/defined**
in the current tree (`m_sessionRestored`, `m_windowX/Y/...`, `applyThemeToAllControls`, `setWindowTransparency`,
`getBuiltinTheme`, `ensureAgenticBridgeHasModel`) → cannot compile as-is; (2) **duplicate symbols**
`saveSessionPanelState`/`restoreSessionPanelState` in both `Session.cpp` and `FileOps.cpp` → LNK2005 if both
linked; (3) UTF-16LE vs UTF-8; (4) two sources of truth.
**Startup restore hook:** `Win32IDE_lifecycle.cpp:420` (`loadEditorSession`→`loadIdeSession`) is the live
site; `Core.cpp` `WM_APP_RESTORE_SESSION` is orphaned. Policy "never restore inside WM_CREATE" must be kept.
**Recommendation:** keep FileOps as the single owner; port only the *missing* blocks (editor state, annotations,
model reload) into FileOps with a `version` field; delete Session.cpp's duplicate panel-state pair. **Not applied.**

## Package 8 — Documentation vs ledger reconciliation

Ledger (`evidence/gate_ledger.json`, baseline `4213f56908`): G06/G08/G10 PARTIAL, G15 BLOCKED (~4.5 TPS),
G16 BLOCKED, G17–G20 OPEN, G07 BLOCKED. 13/23 is from `DEEP2_NATIVE_FORWARD_MATRIX_23MODELS.md:39`.

| Doc | Claim | Verdict | Action |
|-----|-------|---------|--------|
| `CERTIFICATION_COMPLETE.md` | "FULLY CERTIFIED", 22 VAL gates PASS | **CONTRADICTS** (G15/G16 BLOCKED, G17–20 OPEN) | **VOID** |
| `00-FINAL-DELIVERABLE-COMPLETE.md` | "PRODUCTION READY - SHIPPED", 2–3× AVX-512 | **CONTRADICTS** (no G-gate; 4.5 TPS) | **VOID** |
| `00-FINAL_DELIVERY_SUMMARY.md` | MASM editor "COMPLETE" (own table: pending) | **CONTRADICTS** (self-contradictory, `D:\` paths) | **VOID** |
| `AGENTIC_SYSTEM_COMPLETE.md` | "not production ready"; E2E not proven | **AGREES** | KEEP |
| `BRUTAL_TRUTH_REPORT.md` | 55%; perf unverified | **AGREES** | KEEP |
| `AUDIT_END_TO_END_2026-11-24.md` | 4.5 TPS/G15; 13/23; PROMOTE=0 | **AGREES** (cites ledger) | KEEP (canonical narrative) |

## Package 9 — GPU quantization dispatch coverage (inventory)

Product path = `QuantDot` (`runtime_graph_executor.cpp` `QuantKindOf:209-222`) + `deep2_qgemv.comp`.

| Quant | GPU kernel | Executor dispatch | Notes |
|-------|-----------|-------------------|-------|
| Q4_0 | Yes | kind 4 | GPU |
| Q4_1 | Shader yes (type 3) | **none → CPU** | `QuantKindOf` omits |
| Q5_0 | Yes | kind 2 | GPU |
| Q5_1 | Shader yes (type 7) | **none → CPU** | `QuantKindOf` omits |
| Q8_0 | Yes | kind 3 | GPU |
| Q8_K | **No (type 15 → NaN)** | **none → CPU** | shader max type 14 |
| Q2_K | Yes | kind 5 | GPU |
| Q3_K | Yes | kind 6 | GPU |
| Q4_K | Yes | kind 0 | GPU |
| Q5_K | Yes | kind 8 | GPU |
| Q6_K | Yes | kind 1 | **CPU registry forced FP32** (`QuantKernelRegistry.cpp:866-883`) |
| IQ4_NL | Shader yes (type 20) | **none → CPU** | `QuantKindOf` omits |
| NVFP4 | Yes | kind 7 | GPU |
| F16 | Yes (DotF16) | F16 branch | GPU |

**Gaps:** Q8_K (no kernel), Q4_1/Q5_1/IQ4_NL (shader exists, no executor mapping), Q6_K (CPU FP32 authority),
MoE router stub (`vulkan_compute.cpp:4438-4480` → CPU fallback). Two divergent type sets cause the mismatch.

## Package 10 — MSVC acceptance handoff (commands for the hardware env)

```bat
:: From a VS2022 x64 Native Tools prompt (cl + ml64 on PATH), at repo root:
cmake -S . -B build-msvc -G "Visual Studio 17 2022" -A x64 ^
  -DRAWRXD_BUILD_WIN32IDE=ON -DRAWRXD_BUILD_TESTS=ON -DENABLE_VULKAN=ON
cmake --build build-msvc --config Release --target RawrXD-Win32IDE-Native
:: Acceptance:
build-msvc\bin\Release\RawrXD-Win32IDE-Native.exe --term-smoke --term-quit
:: LSP: feed malformed Content-Length frames (Package 3 cases 1-10) -> no crash
:: Crash: fault-inject (Package 4 cases 1-5) -> IDE_CRASH.log + .dmp present
ctest --test-dir build-msvc -C Release --output-on-failure
```

**Handoff rule:** a task moves PATCHED→BUILT only after `cmake --build` succeeds; BUILT→TESTED only after the
relevant acceptance above passes; TESTED→CERTIFIED only with a commit-bound receipt. None of Packages 3–10 is
complete until then.

---
*Read-only analysis at HEAD f50ebd4ccb. No backlog closure, build, or certification performed by this document.*