# RAWRXD_SESSION_DEFECT_LEDGER_001

Append-only record of every defect found while building the browser, shell,
agent, inference and build tranches.

Why this file exists: most of these defects were discovered, fixed, and then
discarded as narration. A defect that is fixed and forgotten has no value to
the next session except as a scar in a diff. Each entry below carries the
symptom, the root cause, the fix, and — critically — whether the fix is
**VERIFIED** or merely **believed**.

A defect observed in a probe is not a defect fixed. A defect fixed in source is
not a defect prevented. Only a regression case makes it the third.

---

## CLASS A — THE INSTRUMENT LIES (highest severity)

These are the ones that matter most. In each, the measuring apparatus produced a
confident, specific, wrong answer.

### A1. WebSocket read timeout reported as peer close
- **Symptom:** `MOVE_ERROR=peer closed while reading frame header` against a
  healthy Edge that was demonstrably still connected.
- **Root cause:** `recvAll()` returned `0` both when `recv()` returned 0 (real
  EOF) and when it returned `SOCKET_ERROR` on `SO_RCVTIMEO` expiry. A 250 ms
  quiet period and a disconnect were indistinguishable.
- **Why severe:** it blamed the peer for a local transport defect, pointing
  every reader at Edge instead of at this file.
- **Fix:** three-way status — bytes / clean close / timeout — via
  `recvAll(..., outError, isTimeout)`.
- **Status:** FIXED. Not regression-tested.

### A2. Response correlation destroyed replies
- **Symptom:** `Input.dispatchMouseEvent` appeared unanswered while the browser
  had replied.
- **Root cause:** `awaitResponse` *discarded* any frame whose id did not match
  the id being awaited. A reply arriving after its caller timed out was
  destroyed permanently; the connection then desynchronised.
- **Why severe:** silent, intermittent, and only visible under concurrency.
- **Fix:** `pending_` map + `pumpOnce()`. Unmatched replies are filed, never
  dropped.
- **Status:** FIXED. `UNMATCHED_RESPONSE_BUFFERED=1` asserted in code comments.

### A3. Non-terminating receipt parser truncated a good receipt to 0 bytes
- **Symptom:** `bowrain_receipt.txt` = 0 bytes, process hung, shell timeout.
- **Root cause:** quote-aware tokenizer used `i <= size` with an `i > size`
  guard that never fires at exactly `size()`. Loop re-entered forever. Worse,
  `writeBowRainReceipt` opened the file with `trunc` *before* rendering, so the
  hang destroyed the artifact it was producing.
- **Why severe:** verification destroyed evidence.
- **Fix:** bounded loop by construction; **render before truncate**.
- **Status:** FIXED. Not regression-tested.

### A4. Two parsers, one format, two verdicts
- **Symptom:** the product read `EXECUTION_DEVICE` as `"AMD`; the probe read
  `AMD Radeon AI PRO R9700` — same receipt, same instant.
- **Root cause:** the receipt parser lived in *both* the product header and the
  probe, with different tokenising.
- **Why severe:** the direct precedent for "two implementations of a proof
  system produce two verdicts about one artifact."
- **Fix:** one `parseReceipt` in the header; probe's duplicate deleted.
- **Status:** FIXED. F8 is a permanent regression case.

### A5. Collapse figure computed outside its regime

**CORRECTION — an earlier version of this entry was wrong in the opposite
direction, and the correction matters as much as the defect.**

These are VALID and must not be treated as suspect. **Both forms are frozen
explicitly below, because the written order of a division changes its UNITS and
this file previously got it wrong:**

```ini
# BUDGET  -- bytes available per token
  bandwidth / target_tps
  1200e9 B/s / 150 tok/s
  = 8.0e9 B/token
  = 8 GB/token

# CEILING -- tokens attainable at a given realized size
  bandwidth / active_bytes_per_token
  1200e9 B/s / 4.0e9 B/token
  = 300 tok/s

# The same ceiling written in the WRONG order, which is what an earlier
# version of this ledger contained. It is not wrong arithmetically -- it is
# wrong in UNITS, and reading it as a rate is how a seconds/token value gets
# quoted as a token/second value:
  active_bytes_per_token / bandwidth
  4.0e9 B / 1200e9 B/s
  = 0.003333 s/token
  1 / 0.003333 s/token
  = 300 token/s          <- same number, obtained by taking the reciprocal
```

The rule: **bytes-over-bandwidth is SECONDS. Bandwidth-over-bytes is TOKENS.**
A dimensional ambiguity in a receipt is a defect even when the magnitude is
right, because the next reader cannot tell which of the two was meant.

Both are regime-independent. The bandwidth-side budget is a direct consequence
of two inputs and nothing else, and the ceiling follows from a stated bandwidth
assumption. Neither was wrong, and dismissing them would have discarded correct
analysis along with the error.

The ONE invalid quantity was:

```ini
REDUCTION_REQUIRED_PCT = -486.54
```

and it is invalid for a specific, narrow reason: `REDUCTION_REQUIRED_PCT` is a
**comparison** of logical model scope against the per-token budget, and that is
the only regime-dependent figure in the set. A 1.36 GB model was fed a budget
derived for a 400 GB model. The model already FITS the budget, so no collapse
exists to quantify — and a comparison across incommensurate regimes returns a
negative "required reduction".

- **Why still severe:** a negative percentage is not a small number, it is a
  category error, and it was emitted by an instrument whose sibling numbers were
  all correct. That is the worst failure shape: wrong output surrounded by right
  output.
- **Fix:** `Regime` guard. `collapseRequired` / `collapseFactor` /
  `reductionRequiredPct` are populated only where a collapse can exist; otherwise
  they print `NA_NOT_BINDING`. `weightBudgetPerToken` and `tpsCeiling` are
  deliberately NOT gated, because they remain valid in every regime.
- **Status:** FIXED. Frozen as E5 and as probe section C.

**The generalisable lesson, stated symmetrically:** a defect adjacent to correct
work is harder to see than an isolated one, because the surrounding valid output
supplies false confidence. And the response to finding one wrong number is not to
distrust the neighbours — it is to work out precisely which quantities the error
could reach.

---

## CLASS B — THE GATE CANNOT PASS / CANNOT FAIL

A certification gate must have at least one physically reachable PASS state.

### B1. Universal trust requirement made navigation uncertifiable
- **Symptom:** `ACTION_1_NAVIGATE ... VERDICT=FAIL` on a successful navigation.
- **Root cause:** `deriveActionVerdict` demanded `trustedEventObserved` for
  *every* action. Navigation produces no input events, so it could never pass.
- **Fix:** per-action-class requirements (`requiresTrustedEvent`,
  `requiresTarget`).
- **Status:** FIXED.

### B2. `type()` never set `targetFound`
- **Symptom:** `ACTION_3_TYPE ... TRUSTED_EVENT=1 STATE_CHANGED=1` yet
  `VERDICT=UNPROVEN`.
- **Root cause:** the field was never assigned, so the derived verdict could
  never pass regardless of evidence.
- **Status:** FIXED.

### B3. `finish()` overwrote trust by string sniffing
- **Symptom:** receipt read `TRUSTED_EVENT=0` directly beside
  `EVENTS=input-trust:cdp-input-channel` — **contradicting itself**.
- **Root cause:** `finish()` recomputed trust with
  `eventsObserved.find(":trusted")`, a convention only the CLICK path
  satisfied. It silently discarded what `type()` had established.
- **Fix:** each action class sets its own trust evidence; `finish()` only
  computes the genuinely common parts.
- **Status:** FIXED.

### B4. Gate-integrity check manufactured its own defects
- **Symptom:** `UNCERTIFIABLE_REQUIREMENT=SURFACE_ALIVE` on a run where every
  surface was demonstrably alive.
- **Root cause:** the probe table paired a *requirement* field against another
  *requirement* field (`requiresSurfaceAlive` vs
  `requiresSurfaceInteractive`) instead of against an *observation*.
- **Why severe:** a self-check that always cries wolf trains the reader to
  ignore the line it prints.
- **Fix:** requirement pointer paired with observation pointer, on different
  types.
- **Status:** FIXED.

### B5. Project refused to build its own IDE
- **Symptom:** `[PRODUCTION POLICY VIOLATION] Found 1 stub/shim/mock files:
  src/core/monaco_core_stubs.cpp`.
- **Root cause:** link errors had been closed with a stub.
- **Why severe:** the recorded `COMPILE=PASS / LINK=PASS` was obtained *by the
  mechanism the gate forbids*.
- **Fix:** real gap-buffer implementation in `src/core/MonacoCore.cpp`.
- **Status:** FIXED. `-- RawrXD-Win32IDE: No stub policy violations`.

---

## CLASS C — LIES AND SHAPE-ONLY SUCCESS

### C1. Monaco stub discarded every byte written
- **Symptom:** none — it linked and ran.
- **Root cause:** `MC_GapBuffer_Insert` returned 0 while moving no bytes;
  `Length` always 0; `LineCount` always 1; `TokenizeLine` emitted no tokens.
- **Why severe:** an editor built on it accepts typing and discards it, while
  every link check passes.
- **Additional defect:** the stub declared `void* MC_GapBuffer_Init(unsigned)`
  against the header's `int MC_GapBuffer_Init(MC_GapBuffer*, uint32_t)`, and
  omitted `MC_GapBuffer_MoveGap` entirely. A symbol can satisfy the linker and
  still be the wrong function.
- **Status:** REPLACED with a real implementation. Stub deleted.

### C2. Prebuilt `.obj` blobs were not reproducible
- **Symptom:** `LNK1181: cannot open input file '...\ResidencyTrace.obj'` on a
  clean clone.
- **Root cause:** `InferenceEngine` linked `*.obj` from the source tree, and
  `.gitignore` excludes `*.obj`. The blobs existed only in developer trees.
- **Fix:** compile the tracked `.asm` sources via `enable_language(ASM_MASM)`.
- **Status:** FIXED. `Assembling ...\ResidencyTrace.asm`, `BUILD_EXIT=0`.

### C3. `.gitignore` excluded source directories named `build`
- **Symptom:** clean `git worktree add` failed to configure;
  `Cannot find source file` on 8 paths under `rawrxd/B01{2,3,4,5}/build/`.
- **Root cause:** `build*/` and `build/` were unanchored, matching any
  directory at any depth. Those eight are SOURCES referenced by
  `CMakeLists.txt`, and those targets bypass
  `rawrxd_filter_missing_sources()`, so absence is fatal there.
- **Note:** the eight files are 1-4 line **auto-generated stubs**. Committing
  them makes a clone configure; it does NOT mean the behaviour is implemented.
- **Status:** FIXED. `CFG_EXIT=0 MISSING_SOURCE_COUNT=0`.

### C4. `generateText` sampled from undefined state
- **Symptom:** a real 1.1B model answered a tool-call prompt with
  `1000000000000000000000000000000, 20.`; a *second* call returned `""`.
- **Root cause:** `generateText` called `generate()` directly and **never called
  `configureGeneration()`**. `generateStream` does. Output depended entirely on
  leftover state.
- **Why severe:** the model looked incapable of following instructions when the
  fault was the harness. "The model is weak" would have been the wrong
  diagnosis, reached for and acted on.
- **Fix:** configure before generating, mirroring `GenerationOptions`.
- **Status:** FIXED.

---

## CLASS D — MEMORY AND SAFETY

### D1. Buffer overrun in the PONG frame
- **Symptom:** MSVC C4789 — `buffer 'f' of size 2 bytes will be overrun`.
- **Root cause:** `unsigned char f[2]` written with 6 bytes.
- **Status:** FIXED. Compiler-caught, not reasoning-caught.

### D2. Quoting bug reported as a permissions error
- **Symptom:** `CreateProcessW failed, error=5` (ACCESS_DENIED) on a path that
  plainly existed.
- **Root cause:** `quoteArg` doubled *every* backslash, producing
  `C:"\"Program Files (x86)\...`.
- **Why severe:** a quoting bug that reports as ACCESS_DENIED points the reader
  at permissions instead of at the string.
- **Status:** FIXED.

### D3. Discovery mutated the machine
- **Symptom:** none — silent.
- **Root cause:** `findBrowser()`'s registry fallback called `ShellExecuteW`.
  *Asking where a browser was would start one.*
- **Status:** FIXED. Deleted.

---

## CLASS E — SHAPE MISTAKEN FOR CONTENT

### E1. Stale geometry dispatched to a moved element
- **Symptom:** click "did nothing"; then events landed on `<html>`.
- **Root cause:** geometry sampled, DOM mutated (a header rewrite changed
  layout), stale coordinates dispatched. Events were *trusted* and *correctly
  delivered* — to the wrong element.
- **Fix:** `resolveTarget()` re-resolves inside the dispatch call, and
  cross-checks `elementFromPoint` against the element's own identity.
- **Status:** FIXED, and promoted from convention to API shape:
  `CALLER_SUPPLIED_CLICK_COORDINATES=FORBIDDEN`.

### E2. URL colon-split as EXPR:VALUE
- **Symptom:** `ACTION_1_NAVIGATE VERDICT=FAIL`; readiness condition became the
  literal strings `"file"` and `"///F:/~dev/..."`.
- **Root cause:** `splitExpectation` split `file:///F:/...` at the first colon.
- **Fix:** `target` is always the object, `payload` always parameters; the page
  is opened before any action.
- **Status:** FIXED.

### E3. Relative profile path, wrong failure named
- **Symptom:** `devtools endpoint never answered on port 0`.
- **Root cause:** a relative `--user-data-dir` is resolved by the browser
  against *its own* CWD, so `DevToolsActivePort` landed where we did not look.
  The failure named the port; the fault was the path.
- **Fix:** `launch()` takes the path **by value** and canonicalises it.
- **Status:** FIXED.

---

## CLASS F — ARGUMENT AND SCOPE

### F1. Flag consumed its own successor
- **Symptom:** `rawrxd --agent --agent-replay <text>` reported no model path.
- **Root cause:** `--agent` consumed the next argument, swallowing
  `--agent-replay`.
- **Status:** FIXED. `--agent` is a bare marker; `--agent-model` names the model.

### F2. Instrumentation that could not compile
- **Symptom:** `error C3861: 'IdeBootMark': identifier not found` at
  `main_win32.cpp:2177`.
- **Root cause:** `IdeBootMark` was defined beside `WinMain` (~line 2790) but
  used in `WndProc` (~line 2177), which is earlier in the file.
- **Why listed:** the instrumentation *looked* correct and did not build. Same
  class as the receipt bugs — the thing you added to learn the truth was itself
  untrue.
- **Status:** FIXED (forward declaration added). Never executed.

---

## WHAT IS STILL OPEN

| Item | State |
|---|---|
| `RawrXD-Win32IDE` link | FAIL — 13 HexMag externals, nothing defines them |
| `IDE_LAUNCH` | NOT_REACHED |
| `ide_boot_trace.txt` | INSTRUMENTED_NEVER_EXECUTED |
| `MODEL_INTENT_EMISSION` | NOT_DEMONSTRATED (tinyllama emits no tool call) |
| `AUTH_SESSION_PERSISTENCE` | UNPROVEN |
| `MODELWEIGHTS_OWNS_MONOLITHIC_COPY` | RETRACTED — weights are mmap aliases |
| Eight `B01*/build/*` sources | 1-4 line auto-generated stubs |
| `rawrxd copy/`, `_n2_stage/` | untracked duplicate trees, unreachable |

---

## THE RECURRING CLASS

Four separate defects this session had one shape:

```
REQUIREMENT
   ↓
implemented as a UNIVERSAL predicate
   ↓
some valid case can never satisfy it
   ↓
gate reads as strict
   ↓
is actually impossible  (B1, B2)
```

and three had this one:

```
MEASURED NUMERATOR
   ↓
beside a MODELLED DENOMINATOR
   ↓
confident, specific, wrong number     (A1, A5, C4)
```

Both reduce to the same rule:

> **A number is not a measurement until its denominator was also measured, and
> a gate is not strict until at least one case is proven to reach PASS.**

Two of the entries above (A3, A5) were caught by their own probes. The rest were
caught by measurement failing to reproduce. That ratio — most defects found by
the instrument breaking — is the argument for keeping the instruments.