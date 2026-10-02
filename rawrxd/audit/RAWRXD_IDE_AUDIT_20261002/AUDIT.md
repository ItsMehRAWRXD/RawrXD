# RAWRXD_IDE_AUDIT_20261002

**Mode** RawrAudit — read-only. No source was edited. No build product is certified here.
**Measured tree** `F:\~dev\rawrxd`
**Bound to** `4cfd4ab82a9be2cbc5871da1b1c003b657fa6426`, branch `beacon-residency-001`, 329 modified paths present
**Authority** a real `cmake` configure. Per the standing rule, the configure log outranks any static parse; where a static parse is used it is labelled as such and cross-checked against file bytes.
**Verdict** `FAIL_IDE_SOURCE_LIST_DOES_NOT_MATCH_TREE`

---

## 1. Two configure modes, both measured

| Mode | Exit | What CMake does |
|---|---|---|
| `-DRAWRXD_STRICT_SOURCES=ON` | **1** | `FATAL_ERROR` at `CMakeLists.txt:406` — 225 referenced sources do not exist |
| default | **0** | Drops the 225, prints `VERDICT=FAIL_DROPPED_SOURCE`, and continues to `Generating done` |

Both runs are in this package: `ide_strict_configure.log`, `ide_default_configure.log`.

```
-- [rawrxd_filter_missing_sources] WIN32IDE_SOURCES: dropped=225
-- RAWRXD_IDE_TARGET_CONFIGURED=1
-- RAWRXD_DROPPED_SOURCE_TOTAL=225
-- DROPPED_SOURCE_MEASUREMENT_VALID=1
-- VERDICT=FAIL_DROPPED_SOURCE
-- Configuring done (8.4s)
```

CMake computes the correct verdict and then exits 0. `RAWRXD_STRICT_SOURCES` defaults OFF, so the filtered path is the default path.

**Consequence, stated no further than the measurement supports:** a binary produced from the default configuration reflects the **filtered** source graph, not the full declared source graph. Receipts produced from that configuration describe a binary configured from the filtered source graph rather than from the full declared source graph.

This audit makes no claim about what any specific binary contains; that would require linking and inspecting the artifact.

## 2. Missing sources — 225

`MISSING_ENTRIES=225`, `MISSING_UNIQUE=225` (no duplicates). From the strict configure fatal.

| Area | Count |
|---|---|
| `src/win32app` | **154** |
| `src/sovereign` | 12 |
| `src/modules` | 12 |
| `src/ui` | 6 |
| `src/sovereign_autonomy` | 6 |
| `src/win32ide` | 5 |
| `src/lsp` | 4 |
| `src/security` | 3 |
| 26 other paths (`src/utils`, `src/terminal`, `src/thermal`, `src/memory`, `src/plugin_system`, `src/kernels`, and 20 top-level `.cpp`) | 1 each |

`src/win32app` contains **57 source files on disk**. The target's declared IDE surface is roughly three times that, and 154 of the declared units were never written.

Full inventory: `source_closure.csv`, 589 declared paths. The `provenance_missing_225` column distinguishes where each row's facts come from:

| Value | Rows | Meaning |
|---|---|---|
| `configure_log_missing_225` | 225 | absence is a configure-log fact (`CMakeLists.txt:406`) |
| `configure_log_stub_gate_only` | 2 | declared and empty per `CMakeLists.txt:395`; not in the missing list |
| `static_parse` | 362 | existence from the filesystem; absence not corroborated by any configure run |

Five rows are absent by static parse but not among the configure log's 225; they are labelled `static_parse` and deliberately kept out of the headline figure.

## 3. Empty-bodied translation units — 200 entries, 81 files

```
[rawrxd_stub_gate] WIN32IDE_SOURCES: 75 translation unit(s) are EMPTY-BODIED
```

**Correction to an earlier verbal report in this session.** I first reported "53 unique" and described the gate as disagreeing with itself by 21. That was a defect in my extractor, not in the gate: it captured only the first `stub_gate` block in the log. Measured per-list, the gate's counter equals its printed token count in every case. The delta is **duplicate list entries** — the same file named twice in one list, added to the target twice and counted twice.

| Gated list | Entries | Tokens | Unique | Duplicates |
|---|---|---|---|---|
| `WIN32IDE_SOURCES` | 75 | 75 | 68 | 7 |

This table is the **empty-bodied subset only**, and its duplicate column must not be read as
the list's redundancy. §16 measures the whole list: 53 duplicate paths, 54 redundant entries.

The gate is internally consistent in all four lists. **68** is the correct figure for the
*empty-bodied* entries of `WIN32IDE_SOURCES`; §16 measures the whole list and corrects the
duplicate count, which is far larger than the subset figure below suggests.

```
UNION_UNIQUE_EMPTY_TUS=81
  src=71   validation=7   tests=1   Ship=1   B014=1
```

Ten declared empty TUs live outside `src/`, including `tests/b009/b009_b_batched_gemm.cpp` — the trivial `int main(){ return 0; }` case the gate's own comment at `CMakeLists.txt:356` cites by name — and seven `validation/**` injectors.

The seven duplicated `WIN32IDE_SOURCES` entries:

```
x2  src/runtime/memory/WorkingSetPredictor.cpp
x2  src/runtime/memory/CapacityManager.cpp
x2  src/runtime/memory/TensorPlacementManager.cpp
x2  src/runtime/memory/ResidencyTracker.cpp
x2  src/runtime/TensorExecutionRouter.cpp
x2  src/runtime/StreamRouterAdapter.cpp
x2  src/runtime/memory/PredictiveMemoryManager.cpp
```

Duplicates are not confined to the IDE list: `RAWR_ENGINE_SOURCES` also names `src/vulkan_compute.cpp` twice, and `src/vulkan_compute.cpp` appears in more than one gated list.

Verified against bytes rather than against the gate, because both my scan and CMake's strip comments and their agreement would prove nothing:

```
src/agent/quantum_missing_impl.cpp            -> 1 line: "// quantum_missing_impl  stub"
src/logging/Logger.cpp                        -> empty
Ship/RawrXD_AutonomousAgenticPipeline.cpp     -> 1 line: "// Auto-generated stub for ..."
B014/build/b014_profiler.cpp                  -> empty
```

**Only one of the 68 explains itself.** An empty TU that documents why it is empty is a deliberate placeholder retained so a build does not break. An empty TU that does not is, to any reader and to any gate, indistinguishable from an implementation that was never written:

```
SELF_DOCUMENTED_INTENT=1     src/core/feature_registration.cpp
SILENT_NO_EXPLANATION=67
```

The single self-documenting case is explicit about being a placeholder:

```
// THIS FILE IS NOW DEPRECATED.
// The 631 lines of manual reg() calls have been replaced by a single loop ...
// This file is kept as a compilation unit to avoid build breakage.
// It compiles to zero code.
```

The filter **keeps** empty-bodied TUs (`CMakeLists.txt:359/363/367`) and warns. They become `FATAL_ERROR` only when `RAWRXD_RELEASE_CERT_BUILD=ON` (`CMakeLists.txt:388`), which is off by default — see §11, where running that flag is measured, and where the first version of this recommendation is found to be wrong about ordering.

```
-- [release_cert_source_closure] mode=0 dropped=0 empty_bodied=0 verdict=NOT_A_CERT_BUILD
```

## 4. A defect in the source list, not just in the tree

Two declared IDE sources live outside `src/`:

```
B014/build/b014_profiler.cpp                    exists, 2 bytes,   empty
Ship/RawrXD_AutonomousAgenticPipeline.cpp       exists, 60 bytes,  one "Auto-generated stub" comment
```

A build-output directory (`B014/build/`) and a shipping directory (`Ship/`) are inside a product source list, and both files are empty. `Ship/RawrXD_AutonomousAgenticPipeline.cpp` also carries exactly the banner text the tree's own stub conventions call out.

## 5. `RAWRXD_IDE_REQUIRED=1` is not enforced

Configuring with the IDE disabled entirely:

```
RAWRXD_IDE_REQUIRED=1
RAWRXD_IDE_TARGET_CONFIGURED=0
RAWRXD_DROPPED_SOURCE_TOTAL=0
DROPPED_SOURCE_MEASUREMENT_VALID=0
VERDICT=FAIL_IDE_NOT_BUILT          (message(WARNING), CMakeLists.txt:18471)
```

**This gate behaved correctly and is recorded as a non-defect.** It recognised that `DROPPED_SOURCE_TOTAL=0` describes a domain that was never exercised, refused to treat it as closure, and said so. It is the one link in this chain that caught its own vacuity. The only defect is that the verdict is still a warning.

This third configure also establishes that runs A and B in §1 are meaningful: in that run the `WIN32IDE_SOURCES` filter never executed, so a `dropped=0` there says nothing about source closure.

## 6. Instrument defects

**The project's IDE stub audit could not run here — REPAIRED in §15.**

```
_ide_stub_closure_recovery_001\rawrxd_ide_stub_closure_recovery\scripts\audit_ide_stubs.ps1:27
    $rel = [IO.Path]::GetRelativePath($RepoRoot, $f.FullName)

RuntimeError: invocation failed because [System.IO.Path] does not contain a
method named 'GetRelativePath'.
```

Measured on this host, not inferred from the PowerShell edition:

```
ps_version=5.1.26100.9549
ps_edition=Desktop
ps_has_Path_GetRelativePath=False
```

**A second, independent fault was found behind it** once the first was repaired:
`@($emptyList).Count` throws on this host too. The script had never produced evidence on
this machine, for two separate reasons, and §15 repairs both and records what it then found.

**My own extractor had one defect**, described in §3. It is corrected here rather than quietly dropped: the first figure I reported for this audit (53) was wrong. The correct figure is 68 for `WIN32IDE_SOURCES`, and 81 unique across all four gated lists once the other three lists are counted.

**My own recommendation had a second defect**, described in §10. The first draft asserted that `-DRAWRXD_RELEASE_CERT_BUILD=ON` would convert both the missing-source and empty-TU findings into configure failures. Run, it converts only the empty-TU finding, and at an earlier site than stated, so it never reaches the IDE finding at all.

## 7. Non-findings — excluded deliberately

**The IDE code that is present is clean.** Scan of `src/win32app`, 56 files (`.cpp/.h/.hpp/.asm/.rc`):

```
STUB_BANNER_AS_FIRST_NONBLANK_LINE = 0
HARDCODED_VERDICT_LITERAL         = 0   (no VERDICT=PASS|FAIL emitted as a printf literal)
SIMULATED_COUNTER                 = 0
```

The problem is **absence, not stubbing**. Calling this a stub problem would misdescribe it.

**17 files under `src/win32app` appear in no source list and are not dead.** `main_win32.cpp` `#include`s them, including `IdeChatAuthority`, `IdeResponseCompletionAuthority`, `W8LifecycleAuthority`, `launch_config`, `ide_agentic_gate`, `ide_inference_gate`, `ide_toolchain_gate`. A first pass comparing only against the source list would have reported them as orphans; they compile. Wiring status: **34 of 57** win32app files are named in `WIN32IDE_SOURCES`; 23 reach the target by inclusion.

## 8. Provenance

HEAD moved during this audit, from `b81d3f13` to `4cfd4ab8`. Per the single-writer verification-invalidation rule the measurement was re-run at the new HEAD rather than shipped from the old one.

**Re-bind result: identical.** Strict exit 1 with 225 missing and 75/68 empty; default exit 0 with `dropped=225` and `VERDICT=FAIL_DROPPED_SOURCE`. The finding is stable across the transition.

`F:\~dev\rawrxd` is not a separate repository — `git rev-parse --show-toplevel` from inside it returns `F:/~dev`.

Both commits carry uncommitted work; 329 paths are modified at bind time. No figure here characterises a clean tree.

## 9. Classification

```
IDE_SOURCE_CLOSURE                 = FAIL      225 declared sources absent
IDE_EMPTY_BODIED_TU                = FAIL      68 unique in WIN32IDE_SOURCES
TREEWIDE_EMPTY_BODIED_TU           = FAIL      81 unique across all 4 gated lists
IDE_SOURCE_LIST_DUPLICATES         = FAIL      7 entries named twice (8 tree-wide)
DECLARED_EMPTY_TUS_OUTSIDE_SRC     = FAIL      10 (validation/ tests/ Ship/ B014/)
BUILD_GRAPH_MATCHES_DECLARATION    = FAIL      default configure exits 0
IDE_TREE_STUB_HYGIENE              = PASS      0 banners, 0 hardcoded verdicts
MEASUREMENT_VALIDITY_GUARD         = PASS      refused its own vacuous reading
GATE_ENFORCEMENT_AVAILABLE         = PASS      RAWRXD_RELEASE_CERT_BUILD=ON does enforce
GATE_COVERAGE                      = FAIL      fail-fast; no single flag reports both
IDE_STUB_AUDIT_SCRIPT              = PASS      repaired, runs, produced receipts (§15)
TREEWIDE_PURE_STUB_FILES           = FAIL      338 in src/, 164 mentioned in CMakeLists
MARKER_METRIC_PRECISION            = FAIL      5/5 false positives in the IDE scan
RAWRXD_IDE_REQUIRED_ENFORCEMENT    = FAIL      warning only

SAFE_TO_CERTIFY_IDE_AS_DECLARED    = 0
SAFE_TO_BUILD_RAWRXD_WIN32IDE      = 0
SAFE_TO_SHIP                       = 0
```

## 10. Verifying this audit's own recommendation — it was wrong about ordering

Section 10 of the first draft recommended `-DRAWRXD_RELEASE_CERT_BUILD=ON` as the
lowest-friction next step, on the grounds that it "converts §2 and §3 from printed
verdicts into configure failures." A recommendation that was never run is not a
recommendation, so it was run. `ide_release_cert_configure.log`.

```
cmake -S F:\~dev\rawrxd -B <fresh> -DRAWRXD_RELEASE_CERT_BUILD=ON \
      -DRAWRXD_BUILD_WIN32IDE=ON -DRAWRXD_BUILD_CLI=ON -DCMAKE_BUILD_TYPE=Release

EXIT=1
[release_cert_source_closure] RAWRXD_RELEASE_CERT_BUILD=ON implies RAWRXD_STRICT_SOURCES=ON
CMake Error at CMakeLists.txt:388 (message):
  [release_cert_source_closure] RAWR_ENGINE_SOURCES: 54 declared source(s)
  are EMPTY-BODIED (no code survives comment stripping):
Call Stack (most recent call first):
  CMakeLists.txt:3788 (rawrxd_filter_missing_sources)
```

**Confirmed:** the flag does imply `RAWRXD_STRICT_SOURCES=ON` (`CMakeLists.txt:220-222`)
and does escalate empty-bodied TUs from warning to `FATAL_ERROR` (`:388`). Enforcement is
real and needs no implementation change.

**Corrected:** it does **not** reach the IDE. It aborts at the *first* filter call site in
the file — `CMakeLists.txt:3788`, `RAWR_ENGINE_SOURCES`, 54 empty TUs — and never reaches
`INFERENCE_ENGINE_LIBRARY_SOURCES` (`:5218`) or `WIN32IDE_SOURCES` (`:7307`). Under this
flag the 225 missing IDE sources are **not reported at all**.

### The gates fail fast and mask one another

| Flag | Exit | First fatal | What you learn |
|---|---|---|---|
| `RAWRXD_STRICT_SOURCES=ON` | 1 | `:406` on 225 missing `WIN32IDE_SOURCES` | the IDE finding; empty TUs only warn |
| `RAWRXD_RELEASE_CERT_BUILD=ON` | 1 | `:388` on 54 empty `RAWR_ENGINE_SOURCES` | empty TUs; the IDE finding never reached |

No single flag reports both, because `rawrxd_filter_missing_sources` raises `FATAL_ERROR`
at the first offending list instead of aggregating across all eight call sites. Surfacing
both requires two configures.

## 11. Next measurable step

No source edit is required for items 1 and 2.

1. Adopt `-DRAWRXD_RELEASE_CERT_BUILD=ON` for certification lanes. Enforcement is measured
   (§10) and it is a cache variable. Adopt it **and** `RAWRXD_STRICT_SOURCES=ON`, or run
   both configures, because neither alone reports both findings.
2. Make that policy the default for any lane that emits an IDE receipt, so the filtered
   path cannot be selected by omission.
3. Aggregate `rawrxd_filter_missing_sources` across all eight call sites before raising
   `FATAL_ERROR`, so one failure does not hide the other seven lists. This is the change
   that makes items 1 and 2 sufficient.
4. Resolve the source list: restore the 225 files or remove the entries. A declared surface
   the tree cannot satisfy is the defect; the drop count is the symptom.
5. Remove the duplicate entries — 7 in `WIN32IDE_SOURCES`, 1 in `RAWR_ENGINE_SOURCES`, and
   the cross-list repeat of `src/vulkan_compute.cpp`.
6. Reconcile `B014/build/`, `Ship/`, and `validation/**` out of a product source list, or
   implement them; all ten are declared empty TUs outside `src/`.
7. Rewrite `audit_ide_stubs.ps1` for .NET Framework, or gate its use on pwsh 7 and say so.

Until item 1 or 2 is adopted, every IDE receipt in this tree was produced through the
filtered path.

---

## 12. Prepared but NOT applied: `RAWRXD_GATE_AGGREGATION_001`

Section 11 item 3 asks for the gate to aggregate before raising `FATAL_ERROR`. That
patch is written, verified to apply, and shipped here **unapplied**.

```
RAWRXD_GATE_AGGREGATION_001.patch
  68 lines added, 2 lines changed (2 fatal sites)
  18,659 -> 18,727 lines
  git apply --check against a pristine copy:  EXIT=0
```

### Why it is not applied

`rawrxd/CMakeLists.txt` is **modified by another lane and grew 40 lines during this
audit** (18,619 → 18,659). Editing it in place risks a concurrent-write collision in a
tree that has already moved HEAD once, and the change is multi-site, so it cannot be
regression-tested here without applying it. A patch that is verified to apply but not
verified to configure is a proposal, and it is labelled as one.

```
live_sha256    =729d809eb82e6dee7d67e27d4fe2ea7dea4b811c14eff4a046d465dc15973279
snapshot_sha256=729d809eb82e6dee7d67e27d4fe2ea7dea4b811c14eff4a046d465dc15973279
BYTES_IDENTICAL=1   <- this audit did not modify CMakeLists.txt
```

The `M` on that path predates the audit and belongs to the other lane.

### The mechanism is verified in isolation, including the clean-tree case

`gate_harness/` reproduces `rawrxd_filter_missing_sources` with the same existence and
empty-bodied rules, in two modes, against fixtures. All four cases:

| Case | Mode | Fixture | Exit | Reported |
|---|---|---|---|---|
| 1 | `FAILFAST` (current) | VIOLATING | 1 | `LIST_B` only — `LIST_C` **never reported** |
| 2 | `AGGREGATE` (patched) | VIOLATING | 1 | `LIST_B` **and** `LIST_C`, `failed in 2 list(s)` |
| 3 | `AGGREGATE` (patched) | CLEAN | **0** | no violation; configure completes |
| 4 | `FAILFAST` (current) | CLEAN | 0 | no violation; configure completes |

Case 1 reproduces the real masking: a second, different defect in a later list is
completely invisible. Case 2 shows the patch surfaces both in one pass. Case 3 is the
falsification test — an aggregate gate that fired on a healthy tree would be worse than
no gate, because it would teach everyone to ignore it; it does not fire.

Logs for all four are in `gate_harness/*.log`.

### The patch

Adds two functions before `rawrxd_filter_missing_sources`:

- `rawrxd_declare_cert_violation(<message>)` — increments a counter, appends the message
  to a `CACHE INTERNAL` accumulator, and registers `cmake_language(DEFER)` exactly once.
- `rawrxd_raise_cert_violations()` — raises one `FATAL_ERROR` listing every offending list.

and replaces the two `message(FATAL_ERROR ...)` calls with calls to the accumulator, so
`rawrxd_filter_missing_sources` still filters and still records its per-list totals; only
the abort point moves.

`cmake_language(DEFER)` needs CMake ≥ 3.19 and this project requires 3.20, so it is
available. The `ID` option is deliberately unused because it needs 3.28 and would break
the declared minimum. The guard variable avoids registering the deferred call more than
once, since `ID` is unavailable.

### Three integration questions: answered

The three unknowns listed in the first version of this section are CMake *semantics*,
not project content, so they were answerable without the 18,727-line file. `defer_harness/`,
same generator and same CMake as the real configure.

| Q | Question | Answer | Evidence |
|---|---|---|---|
| U1 | Does `DEFER DIRECTORY` fire at end of directory scope? | **Yes.** Fires after the last top-level command, on every mode. | `MARK_LAST_TOP_LEVEL_COMMAND -> MARK_RAISE_ENTERED` |
| U2 | Does `FATAL_ERROR` inside a deferred call still abort? | **Yes.** Exit 1, "Configuring incomplete". | `fix_U2_FATAL_IN_DEFER.log` |
| U3 | Do empty-source `add_library` calls error before the deferred fatal? | **No.** The deferred fatal fires during configure and preempts them. | `fix_U3_EMPTY_TARGET.log` |

Two further risks nobody had named, also cleared:

| R | Risk | Answer | Evidence |
|---|---|---|---|
| R1 | `DEFER` is called from *inside a function* — is that legal? | **Yes.** Registration from function scope works. | U1, 2 lists aggregated |
| R2 | The once-only guard behind `CACHE INTERNAL` — zero fires, or eight? | **Exactly one**, counting 3. | U2: `MARK_RAISE_ENTERED` once, `failed in 3 list(s)` |

## 13. The harness found two defects in the proposed patch

Both were in the patch itself, not in the design. Both were caught only because U2's output
was read unfiltered, and both would have shipped a gate that reported a correct **count**
with an empty **body** — authoritative-looking and silent, which is worse than the current
behaviour because it appears to be working.

### D1 — `${ARGV1}` is empty on this CMake

```
NAMED   -> 'LIST_A violated'
ARGV1   -> ''                    <-- empty
ARGV_ALL-> 'LIST_A violated'  argc=1
```

`ARGC` is 1 and `${ARGV}` holds the argument, but `${ARGV1}` does not. The first version of
the patch used `${ARGV1}`, so every accumulated message was empty and the raise printed
`failed in 3 list(s):` followed by blanks. Isolated in `accumulator_diagnosis/`.

### D2 — `CACHE INTERNAL` truncates at the first embedded newline

Storing `"message with \n embedded newline"` yields a value ending at the newline. Every real
violation message contains one, so even with D1 fixed the first line would survive and the
**file list inside each message would be silently lost** — the exact information the gate
exists to produce.

### The fix, verified

Named parameter instead of `ARGV`; newlines encoded to `@@RAWRXD_NL@@` before the value
enters the cache and decoded at raise time. `accumulator_diagnosis/fixed_accumulator_CMakeLists.txt`.

```
[rawrxd_cert_violations] source closure failed in 3 list(s).
  LIST_A violated: 2 missing
    src/win32app/Win32IDE.cpp src/win32app/Win32IDE_Debugger.cpp
  LIST_B violated: 1 missing
    src/lsp/RawrXD_LSPServer.cpp
  LIST_C EMPTY-BODIED: 2 files
    src/logging/Logger.cpp src/vulkan_compute.cpp
```

Corrected patch: 68 lines added, 2 changed, 18,659 -> 18,727 lines, `git apply --check`
exit 0. Still **not applied**, still byte-identical live file.

### One correction of my own framing

U2's first run *looked* like it lost the messages in the deferred raise. It had not. I had
captured it through a PowerShell pipeline and then filtered the log with a pattern that
excluded the very lines containing the text. The blank body was a **capture artifact**. The
`${ARGV1}` defect was real and independent, and was found only after re-capturing raw and
then instrumenting the harness. A summary line is not evidence; the body is.

## 14. Closing the last open item: does the intervening span matter?

U3 put the competing command *adjacent* to the filter call. The real file has **11,346
lines** between the last filter call and the end of directory scope, so span length had to
be tested rather than assumed. `long_span_harness/`.

| Case | What was emitted after the violation | Deferred ran? | Aggregate printed? |
|---|---|---|---|
| `LONG_SPAN_HARMLESS` | 400 `add_library` + 400 `add_custom_target` + 401 messages | **Yes** | **Yes**, 2 lists |
| `LONG_SPAN_WARNING_AS_ERROR` | 50 messages, then `message(WARNING)` | Yes | Yes, 2 lists |
| `LONG_SPAN_INTERVENING_FATAL` | 100 messages, then `message(FATAL_ERROR)` | **No** | **No** |

Two conclusions, both measured:

1. **Span length and empty-source targets do not matter.** 400 source-less `add_library`
   calls between the violation and end of directory changed nothing. Those errors are
   generate-time, and `DEFER` fires at end of *configure*, before generate. The aggregate
   still reported both lists, led by `WIN32IDE_SOURCES: 225 referenced source(s) do not
   exist`.
2. **A configure-time `FATAL_ERROR` after the last filter call preempts the aggregate
   entirely.** The deferred callback never runs. This is the only preemption mechanism found.

### How much does that matter here? Four sites.

```
last rawrxd_filter_missing_sources() call : 7313  (_WIN32IDE_ASM)
intervening span                          : 11,346 lines
FATAL_ERROR sites in whole file           : 33
   before :7313                           : 29
   after  :7313                           :  4   -> 7733, 8041, 8076, 13525
```

All four are `[ProductionLane]` guards requiring `RAWRXD_PRODUCTION_STRIP_STUB_SOURCES=ON`:

```
7733  QuickJS not found and Win32IDE would require QuickJS stubs
8041  RAWR_ASAN=ON incompatible with RAWRXD_PRODUCTION_STRIP_STUB_SOURCES=ON
8076  RAWRXD_ENABLE_HEAVY_GATES=OFF incompatible with RAWRXD_PRODUCTION_STRIP_STUB_SOURCES=ON
13525 Python3 interpreter required when RAWRXD_PRODUCTION_STRIP_STUB_SOURCES=ON
```

**Under a default configure none of the four can fire**, so the aggregate is reached. Under
the production-strip lane it can be preempted — and in that lane these guards firing first is
arguably correct behaviour, so preemption is not obviously a loss.

If unconditional reachability is wanted anyway, the fix is to raise immediately after line
7313 rather than at end of directory. `:7313` is the last of the eight call sites, so
nothing would be dropped. The patch documents this rather than choosing it.

### Two more measurement defects, both mine

**A relative path read the wrong file.** `[IO.File]::ReadAllLines("CMakeLists.txt")` resolves
against `[Environment]::CurrentDirectory`, which PowerShell's `Set-Location` does *not*
change. It returned `total_lines=212` and `total_fatal_sites=0` for a file with 18,659 lines
and 33 fatal sites. Redone with an absolute path: 18,659 and 33. Every other line count in
this package came from either `rg` or an absolute path, so only this one reading was wrong.

**A stale patch nearly shipped.** After editing the patch generator I re-ran it, it failed with
a PowerShell parse error (a dropped quote and comma in an array literal), and I regenerated
the diff from the *previous* output and shipped it — reporting a patch that did not contain
the change I had just made. Caught only by asserting on the artifact's contents
(`PREEMPTION_NOTE_present`) rather than on the exit code, which looked fine.

That is the third time in this audit that a summary or an exit code agreed with me while the
underlying evidence did not. The check that catches all three is the same: read the artifact
and assert on what it actually contains.

## 15. The dead gate restored, and what it found when it ran

§6 recorded `audit_ide_stubs.ps1` as FAIL — cannot execute on this host. That is now
**repaired**, and it is the only source change this audit has made to the repository.

### Two independent PS 5.1 incompatibilities, not one

The script had **two** independent faults, so fixing the first did not make it run.

1. **`[System.IO.Path]::GetRelativePath` does not exist** on .NET Framework — the failure
   §6 measured. Replaced with a portable helper.
2. **`@($emptyList).Count` throws.** `@()` around an *empty*
   `System.Collections.Generic.List[object]` raises
   `ArgumentException: Argument types do not match` on this host. Three summary lines and
   the verdict line used that form, so the script would have failed again even with
   `GetRelativePath` repaired. Replaced with `$list.Count`, a direct property.

Isolated repro, since the second fault only appears once the first is past:

```
GetFullPath / EndsWith / StartsWith / Substring  -> all OK
@($emptyList[object]).Count                      -> ArgumentException
```

Diff: 31 insertions, 6 deletions, one file, tracked and previously clean, so `git checkout`
reverts it. Pristine and repaired copies are both shipped in `stub_gate_restored/`.

### It now runs, and the IDE-scoped result corroborates §7

```
SCAN_ROOT=F:\~dev\rawrxd\src\win32app
SOURCE_FILES_SCANNED=56
PURE_STUB_FILES=0
CMAKE_REFERENCED_PURE_STUB_FILES=0
STUB_OR_FALLBACK_NAMED_FILES=0
MARKER_FILES=5
VERDICT=PASS
```

`PURE_STUB_FILES=0` independently reproduces §7's `STUB_BANNER_AS_FIRST_NONBLANK_LINE = 0`
from a separate implementation. Two instruments, same answer.

**All 5 `MARKER_FILES` are false positives**, verified by reading each site:

```
cli_main_headless.cpp:221   // placeholder.
cli_main_headless.cpp:358   // succeed. Report the real text, not a placeholder.
Win32IDE_Commands.cpp:386   // DoEditFind used to hardcode g_findString = "TODO" ...
Win32IDE_LSP_AI_Bridge.cpp:62  return "// TODO: declare '" + ident + "' ...";   <- returns a TODO to the user
Win32IDE_Settings.cpp:203   // A real, observable ladder rather than a TODO.
Win32IDE_Sidebar.cpp:56,357 // synthetic placeholder child
```

The gate matches `TODO`/`placeholder` as raw substrings with no comment awareness, so it
cannot distinguish a real stub marker from prose explaining that something is *not* a stub.
Its `VERDICT` does not depend on `MARKER_FILES`, so the verdict is sound, but the marker list
must not be read as defects.

### Tree-wide, the stub surface is 338 files

```
SCAN_ROOT=F:\~dev\rawrxd\src
SOURCE_FILES_SCANNED=3246
PURE_STUB_FILES=338
CMAKE_REFERENCED_PURE_STUB_FILES=164
STUB_OR_FALLBACK_NAMED_FILES=51
MARKER_FILES=450
VERDICT=FAIL
```

**Independently reproduced at 338 by a second implementation**
(`stub_gate_restored/independent_crosscheck.ps1`, which does not share the gate's helper):

```
PURE_STUB=338   FILES_SCANNED=3246   TOTAL_BYTES=17258   MEAN_BYTES=51   MAX_BYTES=1241
```

`CMAKE_REFERENCED_PURE_STUB_FILES=164` is a weak claim and is labelled as one: the gate
tests `$cmakeText.Contains($rel)` over the whole of `CMakeLists.txt`, so it means "mentioned
somewhere in the file", not "in a target's source list".

### I nearly filed a false correction here

The receipt listed `src/deep2/GGUFLoader.cpp`, `src/deep2/ModelLoader.cpp`,
`src/deep2/KVCache.cpp`, `src/inference/Deep2Engine.cpp` as pure stubs. Those names read as
core engine files, and I was about to record that the gate had massive false positives.
Reading the bytes:

```
src/deep2/GGUFLoader.cpp   35 bytes, 1 line: // STUB: src/deep2/GGUFLoader.cpp
src/deep2/ModelLoader.cpp  36 bytes, 1 line: // STUB: src/deep2/ModelLoader.cpp
src/deep2/KVCache.cpp      32 bytes, 1 line: // STUB: src/deep2/KVCache.cpp
src/inference/Deep2Engine.cpp 40 bytes, 1 line: // STUB: src/inference/Deep2Engine.cpp
```

The gate was right and I was wrong, by inferring a fact about the tree from a filename. Same
error class as the `masm_factory_swap_quantization` claim in the Decoda verification.

### The 338 and the 68 are disjoint

Computed by sorted-file comparison (`Compare-Object -IncludeEqual -ExcludeDifferent`), after
two in-line extraction attempts disagreed with each other:

```
pure_stub_paths.txt          338
win32ide_empty_tu_paths.txt   68
INTERSECTION                  0
```

Reproducible, and two independent extractions of the 68-element list agreed exactly
(0 differing entries). The WIN32IDE empty TUs are empty files and explanatory-comment files
(`Logger.cpp` is empty; `feature_registration.cpp` documents itself as a deliberate
placeholder); the 338 are `// STUB:` banners and sit elsewhere in `src/`.

An earlier in-line check reported a non-zero overlap. It was a `Select-String -Quiet`
false positive on a substring match. The sorted-file comparison is the reproducible form.

### Scope note

This gate measures a different property from §2 and §3 — stub *banners* under a first-line
rule, not source-list closure or empty-bodied TUs. It has no view of whether a declared
source exists. A `VERDICT=PASS` from it is not evidence about source closure, which is the
same "a diagnostic that cannot disagree" limitation noted in §7.

## 16. Correcting §3: the duplicate-entry count was scoped to a subset

§3 reported **7 duplicates** in `WIN32IDE_SOURCES` and **1** in `RAWR_ENGINE_SOURCES`. Both
were correct — for the *empty-bodied entries only*, which is all the configure log reports.
The lists themselves are far more redundant than that.

### Measured over each whole declaration span

Counting only `list(...APPEND ...)` / `set(...)` membership, excluding comment lines and
`message`/`set`/`if` prose:

| Gated list | Span | Entries | Unique | Redundant | Duplicate paths |
|---|---|---|---|---|---|
| `WIN32IDE_SOURCES` | 5460–7307 | **639** | **585** | **54** | **53** |
| `RAWR_ENGINE_SOURCES` | 3442–3788 | 74 | 58 | 16 | 5 |
| `GOLD_UNDERSCORE_SOURCES` | 4152 | 16 | 16 | 0 | 0 |
| `INFERENCE_ENGINE_LIBRARY_SOURCES` | 5218 | 16 | 16 | 0 | 0 |

One path appears three times; the other 52 appear twice:

```
x3  src/runtime/TensorExecutionRouter.cpp     (lines 6433, 7008, 7254)
x2  src/deep2/TheDualityExample.cpp           (7107, 7272)
x2  src/runtime/StreamRouterAdapter.cpp       (7009, 7255)
x2  src/deep2/StreamEngine.cpp                (6403, 7084)
x2  src/deep2/test_real_gguf_load.cpp         (7139, 7288)
... 48 more at x2
```

The 8.5% redundancy in `WIN32IDE_SOURCES` is a build-graph defect independent of the 225
missing entries in §2, and it inflates the empty-TU counter too: the gate counts list
*entries*, so 7 of its 75 were double-counts.

### How three separate counting errors were caught

All three were mine, and all three produced confident numbers:

1. **Occurrence counting across the whole file.** `WorkingSetPredictor.cpp` appears 26 times
   in `CMakeLists.txt` and `CapacityManager.cpp` 27. Those are mostly legitimate — a file
   belonging to several different targets. Treating whole-file counts as in-list duplicates
   would have reported 52 duplicates instead of 7.
2. **An inverted filter.** `$p.StartsWith('/')` was meant to *skip* absolute-looking paths
   and instead kept only those, discarding every real `src/...` entry. It reported 3 entries
   for `RAWR_ENGINE_SOURCES`.
3. **Regex fragments counted as entries.** Four "paths" — `ssot_handlers.cpp`,
   `ssot_handlers_ext_isolated.cpp`, `ssot_missing_handlers_provider.cpp`,
   `link_stubs_gate.cpp` — are not list members. They come from a `message(STATUS ...)` at
   line 6562 that names them in prose, and from a `set(... FILE ...)` policy block at lines
   6848–6862. Counting only membership lines removed them.

Each was caught by opening the cited line numbers and reading them.

### A gap in a shipped artifact, declared

`source_closure.csv` has 589 rows. The span measure is 585 unique, and the two disagree in
both directions:

```
OMITTED   Ship/RawrXD_AgentCoordinator.cpp   line 5605 - a real WIN32IDE list member
INCLUDED  src/core/link_stubs_gate.cpp       not a list member anywhere in the span
```

The CSV's generator required a `src|include|tools|third_party` prefix, so `Ship/` was
dropped; and it recorded a `set(... FILE ...)` policy reference as a member.

**This does not affect the headline.** The 225 missing sources in §2 come from the configure
log at `CMakeLists.txt:406`, not from the CSV, and are unaffected by this gap. The CSV's row
count should be read as approximate; its `provenance_missing_225` column remains authoritative
for the 225.

### Not done, and why

§11 item 4 — restore the 225 files or remove the entries — is a product decision, because it
changes what the IDE claims to be, and it is not mine to make. Item 5, removing the 54
redundant entries, is provably a no-op for the build graph: each path would remain present
exactly once. Item 6, the out-of-src declarations, is **not** a no-op, because those entries
do compile today.

The prepared `RAWRXD_GATE_AGGREGATION_001.patch` remains the only proposal in this package,
and it is still unapplied: `CMakeLists.txt` is uncommitted work belonging to another lane.
It has not changed during this audit —

```
sha256 729d809eb82e6dee7d67e27d4fe2ea7dea4b811c14eff4a046d465dc15973279
mtime  2026-10-02 13:06:14   idle for the remainder of this audit
```

so the blocker is ownership of the file, not a moving target.

---

## Package contents
| `AUDIT.md` | this document |
| `ide_strict_configure.log` | full stdout, run A, HEAD `4cfd4ab8` |
| `ide_default_configure.log` | full stdout, run B, HEAD `4cfd4ab8` |
| `ide_release_cert_configure.log` | full stdout, run D, HEAD `4cfd4ab8` |
| `source_closure.csv` | 589 declared paths; existence from filesystem; `provenance_missing_225` column separates configure-log facts from static parse |
| `empty_tu_inventory.txt` | `WIN32IDE_SOURCES` empty list, 75 entries / 68 unique, with duplicate breakdown, per-file byte sizes, and the intent split |
| `configure_environment.txt` | toolchain, host, exact commands, exit codes for all runs, per-list and union empty-TU figures, package SHA-256s, HEAD-movement record |
| `RAWRXD_GATE_AGGREGATION_001.patch` | §12/§13. Corrected patch, verified to apply (`git apply --check` exit 0). **Not applied.** |
| `gate_harness/` | §12. Fail-fast vs aggregate, CLEAN and VIOLATING fixtures, four logs |
| `defer_harness/` | §13. U1–U3 and risks R1–R2; `fix_*.log` are the corrected runs |
| `long_span_harness/` | §14. Span-length and preemption experiments, three logs |
| `accumulator_diagnosis/` | §13. Isolates the `${ARGV1}` and newline-truncation defects and the fix |
| `stub_gate_restored/` | §15. Pristine + repaired `audit_ide_stubs.ps1`, both receipts, independent cross-check, and the two sorted path lists behind the intersection |

Run C (`RAWRXD_IDE_REQUIRED` without the IDE) is summarised in §5 and in
`configure_environment.txt` rather than shipped, since its purpose is to show that
`dropped=0` is vacuous there.