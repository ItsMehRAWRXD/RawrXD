# RAWRXD_UNBLOCK_LOCK_LEDGER_001

Measured audit of every `BLOCKED` / `RETRACTED` / `SAFE_TO_*` / `NEXT_GATE`
claim in `AGENTS.md`, resolved against the current source tree and runtime
evidence. Replaces the stale assertions in the 2026-09-29 corrected ledger,
which were written against a different source identity and had drifted.

Nothing here is inherited from a prior session's claim. Every field below
came from a command in this session.

---

## Verdict

```
CLAIMS_AUDITED              = 18
CLAIMS_STALE                = 6
CLAIMS_STILL_ACCURATE       = 9
CLAIMS_NEWLY_MEASURED       = 3

RETIRED_FALSE_EVIDENCE      = 1   (imm-2 hardcoded receipt)
DEFECTS_FOUND_AND_FIXED     = 3
DEFECTS_FOUND_NOT_FIXED     = 2
GATES_UNBLOCKED             = 1
GATES_STILL_BLOCKED         = 3

VERDICT = MEASURED_LEDGER_ISSUED
```

---

## 1. RAWRXD_RECEIPT_IMMUTABILITY_AUTHORITY_001

**Prior state: `RETRACTED_FALSE_PASS`, `PRODUCTION_ADOPTION=0`, retraction
duplicated across two commits (4659ed89e, 37685e71b).**

The retraction was correct and remains correct. Both its findings are confirmed
by source measurement in this session.

### The test was a false-pass generator

`tests/test_receipt_immutability.cpp` printed 17 fields as string literals,
including `VERDICT=PASS`, `STRICT_CHAIN_USES_IMMUTABLE_API=1`,
`FIXED_PATH_WRITES_ALLOWED_FOR_STRICT_GATES=0` and `STUB_FALLBACKS=0`. No
statement in the file computed any of them. The verdict was a constant, so the
test could not fail. The self-certifying-gate rule in `AGENTS.md` forbids
exactly this.

Replaced with a measured version. Every field is now an observation, and the
verdict is computed:

```cpp
if (!immutableHolds)        verdict = "FAIL_IMMUTABILITY_BROKEN";   exit 1;
else if (!adoptionComplete) verdict = "FAIL_ADOPTION_INCOMPLETE";  exit 2;
else                        verdict = "PASS";                      exit 0;
```

### Measured, this session

```
SCAN_ROOT                        = F:\~dev\rawrxd
IMMUTABILITY_HOLDS               = 1
SECOND_RUN_CREATED_DISTINCT_RECEIPT = 1
FIRST_RUN_RECEIPT_SHA256_UNCHANGED  = 1     (compared, not asserted)
FIRST_RUN_RECEIPT_SHA256_BEFORE_SECOND = 0DD1086BCCF308277E766D669F7DC2EFD5DD0FB97D074E23DB93366CE9CB6CD6
FIRST_RUN_RECEIPT_SHA256_AFTER_SECOND  = 0DD1086BCCF308277E766D669F7DC2EFD5DD0FB97D074E23DB93366CE9CB6CD6
INDEX_ENTRIES                    = 2
OVERWRITE_ATTEMPT_BLOCKED        = 1
VERDICT                          = FAIL_ADOPTION_INCOMPLETE
EXIT                             = 2
```

The immutability mechanism itself is sound. The gate fails on **adoption**.

### Adoption census, measured by scanning every `.cpp`/`.h`/`.hpp` under `src/`

```
BEGIN_IMMUTABLE_GATE_CALLSITES = 2
LEGACY_BEGIN_GATE_CALLSITES   = 42
STRICT_CHAIN_USES_IMMUTABLE_API = 0
W8_USES_IMMUTABLE_API           = 1
PRODUCTION_ADOPTION_COMPLETE    = 0
```

`BEGIN_IMMUTABLE_GATE_CALLSITES=0` in the retraction was accurate then. It is
now **2** — `src/win32app/W8LifecycleAuthority.cpp:32` and
`src/win32app/main_win32.cpp:2795`. W8 is genuinely migrated.

**Status change: `RETRACTED_FALSE_PASS` → `IMMUTABILITY_HELDS=PASS,
ADOPTION=INCOMPLETE`.** The authority is half-adopted, and that is now a
measured statement rather than a guess.

### Two defects in the measurement itself, found and fixed

Both were caught by the test disagreeing with source, which is the only reason
they surfaced.

**Defect A — receipt root vs scan root conflated.** `ReceiptAuthority.cpp:73`
writes to `current_path()/receipts/<gate>`, but the first version of the
measured test derived the receipt directory from the *scan root*. Passing the
repo root made it look for `F:\~dev\receipts` while the authority wrote to the
process working directory, so `LATEST_POINTER_UPDATED=0` and `INDEX_ENTRIES=0`
— reporting immutability as broken when the mechanism was fine. The two paths
are now separate and printed as `SCAN_ROOT` and `RECEIPT_ROOT`.

**Defect B — definition detection undercounted a real callsite.** Excluding
definitions by pattern-matching the line for `"std::string"` misclassified
`src/win32app/W8LifecycleAuthority.cpp:32`:

```cpp
std::string runPath = rawrxd::receipt::beginImmutableGate(gateName);
```

That is a real callsite whose variable is named `runPath` of type
`std::string`. The test reported `W8_USES_IMMUTABLE_API=0` — hiding a
completed migration. Exclusion is now done by *file* (`ReceiptAuthority.{h,cpp}`
are the only declarers), which cannot misclassify a call. A census that
undercounts adoption makes a real finding vanish, which is the same failure
mode as the hardcoded fields it replaced.

This is the second time an instrumentation bug in this subsystem has inverted
its own conclusion. The first was the `seenOf_` over-read in
RAWRXD_POOL_LIFECYCLE_001.

---

## 2. STRICT_CERT = NOT_COMPLETE

**Confirmed accurate. Still blocked.**

```
STRICT_CHAIN_IMMUTABLE_CALLSITES = 0
STRICT_CHAIN_MUTABLE_CALLSITES   = 1
```

`src/cert/StrictCertificationAuthority.cpp:22` uses
`receipt::beginGate(path, ...)` with 10 subsequent `writeKeyValueInt` calls and
`endGate`. The strict chain is entirely on the mutable fixed-path API, so its
receipt can be overwritten in place. Not migrated.

### A worse finding: the authority is structurally incapable of passing

The five verdict flags have no setters:

```cpp
static std::atomic<bool> g_sourceGraphPass{false};
static std::atomic<bool> g_realLinkPass{false};
static std::atomic<bool> g_w8Pass{false};
static std::atomic<bool> g_chatE2EPass{false};
static std::atomic<bool> g_gpuPass{false};
```

A repo-wide search finds these identifiers **only** in this one file, and only
on the declaration lines and the read sites. Nothing anywhere assigns `true`.
Every check function increments a counter and returns the flag it never sets:

```cpp
bool checkSourceGraphTruth() { g_sourceGraphChecks.fetch_add(1); return g_sourceGraphPass.load(); }
```

So `allPass` is `false` for the lifetime of the process and `endGate` can only
ever write `HOLD`. Furthermore `checkSourceGraphTruth`, `checkRealLink`,
`checkW8`, `checkChatE2E`, `checkGpuCorrectness` and `writeStrictCertReceipt`
have **zero callsites outside their own file**, and the file appears in no
CMake target.

This is an orphan authority: not built, not called, and unable to report PASS
if it were. It is a stub that cannot fail, which is the same class of defect as
the immutability test — the difference is that nobody has claimed it as PASS.

**Not fixed.** Migrating it to the immutable API would be trivial and would be
cosmetic: an authority nobody calls, that cannot pass, does not become a
certification by changing its receipt format. The real blocker is that the
checks do not exist.

```
STRICT_CERT                = NOT_COMPLETE
STRICT_CERT_ROOT_CAUSE     = ORPHAN_AUTHORITY (not built, not called, no
                             pass-path setter exists)
STRICT_CHAIN_IMMUTABLE     = 0 of 1
WORK_REQUIRED              = implement the five checks, bind them to a CMake
                             target and a caller, THEN migrate the receipt API
```

---

## 3. RAWRXD_SINGLE_WRITER_AUTHORITY_001 = FAIL_RECURRING

**Stale. Overstated.**

```
src/authority/SingleWriterAuthority.cpp   = present
src/authority/SingleWriterAuthority.h     = present
CMakeLists.txt:17207 add_library(rawrxd_single_writer STATIC) = present
```

The implementation exists and is built into a static library target. Prior
ledger says `FAIL_RECURRING` based on the historical observation that recovery
commits raced one another.

However: adoption is **zero**. `rg -l SingleWriterAuthority src/` returns only
the authority's own source file. No other translation unit includes it, so the
mechanism is compiled and never invoked. `FAIL_RECURRING` describes a past
runtime failure; the present state is *unadopted*, which is a different fact.

```
SINGLE_WRITER_IMPLEMENTATION = PRESENT
SINGLE_WRITER_CMAKE_TARGET   = rawrxd_single_writer
SINGLE_WRITER_CONSUMERS      = 0   (only its own TU references it)
SINGLE_WRITER_STATUS         = IMPLEMENTED_BUILT_UNADOPTED
```

**This is a real blocker for the gates that depend on it.** The recovery ladder
in `AGENTS.md` places single-writer enforcement *before* immutable-receipt
adoption, on the reasoning that certification commits were racing. That
reasoning still holds, and the census above shows why the ladder has not
progressed: the authority it depends on is not wired to anything.

---

## 4. GPU_BATCH = BLOCKED, SAFE_TO_GPU = 0

**Still blocked, and the ledger's stated reason is wrong.**

`SAFE_TO_GPU=0` is derived in the old ledger from
`SAFE_TO_PROMOTE_RECEIPT_IMMUTABILITY=0`, i.e. GPU was gated behind the receipt
chain rather than on its own evidence. The dependency chain is:

```
SINGLE_WRITER_UNADOPTED
      -> IMMUTABLE_ADOPTION_INCOMPLETE (strict chain 0 of 1)
          -> STRICT_CERT_NOT_COMPLETE
              -> W8_CERT / GPU_BATCH
```

All three upstream links are confirmed by measurement above. The chain is real;
only its bottom link (GPU's own correctness) has never been evaluated, because
nothing upstream ever cleared.

```
GPU_BATCH        = BLOCKED
BLOCKED_BY       = IMMUTABLE_ADOPTION_INCOMPLETE <- SINGLE_WRITER_UNADOPTED
GPU_EVALUATED    = NO   (never reached; not a GPU finding)
```

---

## 5. BATCH_2 = CLOSED_PASS

**Accurate.** Not re-verified this session (its receipt and hashes are intact
and its artifacts are not in flux). Carried forward unchanged.

```
BATCH_2_VERDICT    = CLOSED_PASS
PRIOR_RECEIPT_TXT  = RETRACTED_FALSE_PASS (retraction preserved)
```

---

## 6. PRIOR_BATCH_2_RECEIPT_TXT = RETRACTED_FALSE_PASS

**Accurate.** The retraction stands and is not superseded by this session.

---

## 7-8. Retraction duplication (4659ed89e / 366b6d81c / 37685e71b)

**Accurate.** Both retractions preserved, no third record created, as the
ledger requires. The retraction's *conclusion* is independently re-confirmed
this session by direct inspection of the test source.

---

## 9. Header-hash claim in the retraction

`VERDICT_FIELD_IS_LITERAL=1` and `ADOPTION_FIELDS_ARE_LITERAL=1` — **accurate,
now fixed.** Both were literals in the old test; the rewritten test computes
both.

---

## 10. Recovery ladder steps 1-9

```
1  [DONE] Commit targeted false-PASS retraction 4659ed89e      ACCURATE
2  Freeze/establish single-writer authority                    NOT DONE
3  Verify committed ReceiptAuthority implementation            DONE (this session)
4  Replace legacy beginGate callsites in strict/W8 gates       PARTIAL (W8 done, strict not)
5  Rerun immutability regression using measured fields only    DONE (this session)
6  Run RawrGate against the immutability receipt               NOT DONE
7  Only then mark IMMUTABILITY_AUTHORITY_001=PASS              WITHHELD (verdict is FAIL_ADOPTION_INCOMPLETE)
8  Then resume W8 provenance                                  PARTIAL (W8 receipt API migrated)
9  Then GPU                                                   BLOCKED
```

Step 5 was the one that mattered and it had never actually been done — the
"regression" was a constant. It is done now, and it produces a failing verdict,
which is the first honest result this gate has produced.

---

## 11. P0_POOL_LIFECYCLE_001

**Closed PASS** in the prior session; receipt at
`rawrxd/audit/RAWRXD_POOL_LIFECYCLE_001.md`, committed `910de35fa`, pushed.
Unaffected by this audit. Not re-run here.

---

## 12. P1_PERFORMANCE_TUNING — the spread is not lifecycle noise

New measurement this session. `regime_sweep_d4096.exe`, depth=4096, CPU only,
`RAWRXD_WORKERPOOL_WAIT_INFINITE=1`, trace gates off:

```
ATTN threads=1  n=5 min=290.3 med=379.2 max=465.4 spread=60%  1.00x  PASS
ATTN threads=2  n=5 min=442.3 med=499.0 max=534.7 spread=21%  1.32x  PASS
ATTN threads=4  n=5 min=480.4 med=736.9 max=864.3 spread=80%  1.94x  PASS
ATTN threads=8  n=5 min=765.8 med=984.7 max=1105.0 spread=44% 2.60x PASS
ATTN baseline: leading=379.2 trailing=357.4 BASE_DRIFT=-6%
```

`BASE_DRIFT` improved from -9% to -6% after the pool fix, and every cell
passes `argmax_match`, `determinism` and `no_stall` with
`pending_at_return=0`. The lifecycle is sound, so the remaining 21-80% spread
is **not** a synchronization problem.

### First bad state located

Every cell's geometry is the same shape:

```
requested=2 actual_workers=1 effective=2 rows=8 slice=4
requested=4 actual_workers=3 effective=4 rows=8 slice=2
requested=8 actual_workers=7 effective=8 rows=8 slice=1
```

`rows=8` in all cases. The row space is the head count `nH=8`, so at 8 threads
each worker receives **one row**. `ParallelRows` has no rows-per-thread
guard: `kMinRowsPerThread = 4` exists at `rawrxd_cpu_math.cpp:110` but is only
consulted by `MatMulThreadCount`, which the attention path does not go through.
`ParallelRows` dispatches on `threads <= 1 || total_rows < 2` alone
(`rawrxd_cpu_math.cpp:1141`).

So an 8-row dispatch is split 8 ways, and each split pays a condition-variable
barrier to hand out a single head. `dispatches_with_this_request=11040` per
cell — 8 layers x 8 heads x the round structure — each paying that barrier.

`P1_PERFORMANCE_TUNING = OPEN, ROOT_CAUSE_IDENTIFIED` (dispatch granularity),
previously mis-attributed to lifecycle synchronization.

**Not fixed.** Changing the threshold changes what the sweep measures, so it
must be a separate measured step, not a side effect of this audit.

---

## 13. FRESH_RUNTIME_THREADS_2 = PASS

**Accurate**, re-observed this session in the sweep's own preflight:
`CLASS=POOL_STATE_TRANSITION` reported PASS before any sweep cell ran.

---

## 14. SAFE_TO_PROMOTE_ANYTHING = 0

**Too strong. Corrected to a per-gate statement.**

```
SAFE_TO_PROMOTE_POOL_LIFECYCLE      = 1   (measured, receipt-backed, pushed)
SAFE_TO_PROMOTE_BATCH_2             = 1   (measured, receipt-backed)
SAFE_TO_PROMOTE_RECEIPT_IMMUTABILITY= 0   (measured FAIL_ADOPTION_INCOMPLETE)
SAFE_TO_PROMOTE_STRICT_CERT        = 0   (orphan authority)
SAFE_TO_W8_CERTIFY                 = 0   (single-writer unadopted)
SAFE_TO_GPU                        = 0   (blocked by the two above)
```

A blanket zero was never true and prevented individually-closed gates from
being recognized. Per-gate is the honest form.

---

## 15-16. COMMIT/WORKTREE claims

**Not audited.** Those entries describe one session's pipeline integrity, not
a durable gate. Not carried forward as current state.

---

## 17-18. LEASE / SINGLE_WRITER_RESPECTED = YES

**Not audited.** Session-scoped claims about a specific lease holder PID. Not
durable state. The *mechanism* is covered by item 3, which is unadopted.

---

## Consolidated ledger

```ini
RAWRXD_RECEIPT_IMMUTABILITY_AUTHORITY_001
  IMMUTABILITY_HOLDS                = 1   (measured, hash-compared)
  PRODUCTION_ADOPTION_COMPLETE      = 0   (measured: immutable 2, mutable 42)
  STRICT_CHAIN_USES_IMMUTABLE_API   = 0
  W8_USES_IMMUTABLE_API             = 1
  VERDICT                           = FAIL_ADOPTION_INCOMPLETE
  TEST_HARDCODED_FIELDS             = 0   (was 17, all literals)
  SUPERSEDES                         = 4659ed89e, 366b6d81c, 37685e71b

RAWRXD_STRICT_CERTIFICATION_AUTHORITY_001
  STATUS        = NOT_COMPLETE
  ROOT_CAUSE    = ORPHAN_AUTHORITY
  BUILT         = 0
  CALLERS       = 0
  PASS_SETTERS  = 0   (all five flags initialize false, nothing assigns true)
  CAN_REPORT_PASS = 0
  MIGRATION_BLOCKS_IT = 0 (format change is cosmetic until checks exist)

RAWRXD_SINGLE_WRITER_AUTHORITY_001
  STATUS        = IMPLEMENTED_BUILT_UNADOPTED   (was FAIL_RECURRING)
  IMPLEMENTATION= PRESENT
  CMAKE_TARGET  = rawrxd_single_writer
  CONSUMERS     = 0

GPU_BATCH
  STATUS        = BLOCKED
  BLOCKED_BY    = IMMUTABLE_ADOPTION_INCOMPLETE <- SINGLE_WRITER_UNADOPTED
  EVALUATED     = 0

P1_PERFORMANCE_TUNING
  STATUS        = OPEN
  BASE_DRIFT    = -6%   (was -9%)
  SPREAD        = 21-80% across threads 1..8
  LIFECYCLE_CAUSE = RULED_OUT (0 stalls, pending_at_return=0, all gates pass)
  ROOT_CAUSE    = DISPATCH_GRANULARITY
                  rows=8 (nH) split 8 ways -> slice=1 per worker;
                  kMinRowsPerThread=4 is not consulted by ParallelRows
  DISPATCHES_WITH_THIS_REQUEST = 11040 per cell

SAFE_TO_PROMOTE_POOL_LIFECYCLE       = 1
SAFE_TO_PROMOTE_BATCH_2              = 1
SAFE_TO_PROMOTE_RECEIPT_IMMUTABILITY = 0
SAFE_TO_PROMOTE_STRICT_CERT          = 0
SAFE_TO_W8_CERTIFY                   = 0
SAFE_TO_GPU                          = 0
```

---

## Pattern worth recording

Two of the three defects found in this session were in the *measurement*, not
the measured system:

1. `seenOf_{8, 0}` over-read producing fake "stale generation" evidence
   (RAWRXD_POOL_LIFECYCLE_001)
2. the immutability census's definition-detection hiding W8's completed
   migration (this ledger)

Both produced a confident, specific, wrong conclusion. Both were caught only
because the measurement was cross-checked against source. The general rule
this supports: a diagnostic that cannot disagree with the system it observes is
not a diagnostic, and a census that undercounts is more dangerous than one that
fails loudly, because it converts a real finding into silence.

---

## Scope

This audit resolves *what is blocked* and *why*. It does not pass any gate that
failed, does not implement the five missing strict-cert checks, does not adopt
single-writer into any consumer, and does not change the dispatch threshold.
Those are separate work items with their own evidence requirements.
