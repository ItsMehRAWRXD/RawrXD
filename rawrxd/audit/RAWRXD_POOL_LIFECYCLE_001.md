# RAWRXD_POOL_LIFECYCLE_001

Gate: the persistent `WorkerPool` completion protocol and cross-config geometry
stability, exercised in one process across a warm/cold thread-count sweep.

## Verdict

```
POOL_LIFECYCLE            = PASS
HEAD_TRACE_GATE           = RAWRXD_TRACE_ATTN_HEAD  DEFAULT = OFF
POOL_STATE_DUMP_GATE      = RAWRXD_TRACE_POOL_STATE  DEFAULT = OFF
STALLS                    = 0
DISPATCHES                = 264
HARNESS_FAILURES          = 0
VERDICT                   = PASS
```

## Binary and sources

```
binary  build\bin\Release\b015_pool_microbench.exe
target  b015_pool_microbench  (CMakeLists.txt:16202, EXCLUDE_FROM_ALL)
harness tests/b015/b015_pool_microbench.cpp   (was `int main(){return 0;}`)
under   src/rawrxd_cpu_math.cpp               (WorkerPool, anonymous namespace)
```

Build: `MSBuild b015_pool_microbench.vcxproj /p:Configuration=Release`
Result: `Build succeeded. 0 Warning(s) 0 Error(s)`

## What was wrong before this run

The previous session reported the pool instrumentation as blocked by a
concurrent writer on `src/rawrxd_cpu_math.cpp`. That blocker is resolved: the
other lane's symbols are present at `src/rawrxd_cpu_math.cpp:607`
(`WaitInfinite`), `:625` (`last_pending_at_return_`), `:626`
(`last_active_at_return_`). No semantics were guessed and none needed to be --
the definitions landed intact. The TU compiles clean.

`tests/b015/b015_pool_microbench.cpp` was a one-line stub, so the CMake target
that already links the pool had no driver. It now runs the sweep.

## First bad state found

The garbage watermarks were not stale generations. They were a heap over-read
in the diagnostic itself.

`src/rawrxd_cpu_math.cpp:826` (before the fix):

```cpp
std::vector<uint64_t> seenOf_{8, 0};
```

Brace-init selects `vector(initializer_list<uint64_t>)`, so this built a
**two-element** vector holding `{8, 0}` -- not eight zeros. Two consequences:

1. `Worker()` guards its mirror write with `id < seenOf_.size()`
   (`src/rawrxd_cpu_math.cpp:778`), so every worker with id >= 2 never
   published a watermark at all.
2. `DumpState()` iterated `w < threads_.size()` and read `seenOf_[w]`
   unconditionally (`src/rawrxd_cpu_math.cpp:693`), running off the end of a
   two-element heap buffer.

Measured evidence, before the fix: workers 0 and 1 reported sane watermarks
(`seen=83`, `seen=84`); workers 2-6 reported heap residue, stable across the
whole run:

```
POOL_WORKER worker=2 seen=27303570963497028
POOL_WORKER worker=3 seen=9799848659912978135
POOL_WORKER worker=4 seen=5719380509202404686
POOL_WORKER worker=5 seen=6000276086503530310
POOL_WORKER worker=6 seen=15253788203044691
```

That pattern -- the first two entries correct, everything after garbage -- is
the signature of reading past a 2-element buffer, and it is what the earlier
162 "eligible worker with stale generation" hits were. The dump was
manufacturing the symptom it was built to detect.

## Fix

`src/rawrxd_cpu_math.cpp:847`:

```cpp
std::vector<uint64_t> seenOf_ = std::vector<uint64_t>(8, 0);
```

Three changes were needed, not one:

- Count-then-value initialisation, so the mirror is actually eight elements.
  The bare `seenOf_(8, 0)` form is a *function declaration* inside a class
  body; MSVC rejects it with C2059 and then reports every subsequent
  `seenOf_.` use as C3867. The `= std::vector<uint64_t>(8, 0)` form is
  unambiguous.
- `DumpState()` now bounds the read by `seenOf_.size()` and prints `seen=NA`
  when a worker has no published watermark, so a diagnostic can never report
  out-of-bounds memory as pool state.
- The mirror is grown under `m_` at the moment each worker id is assigned
  (`src/rawrxd_cpu_math.cpp:418`). A fixed size of 8 excluded every worker with
  id >= 8, and this host has 16 logical cores, so the 9th through 16th workers
  would have published no watermark at all. Growth happens before the thread
  is constructed, so the index is always valid.

## Verification

Same command, same binary shape, before and after:

```powershell
$env:RAWRXD_WORKERPOOL_WAIT_INFINITE = "1"   # wait cannot expire; a nonzero
                                           # pending-at-return is a real break
$env:RAWRXD_TRACE_POOL_STATE       = "1"    # PRE/PUBLISH/POST + per-worker seen
.\build\bin\Release\b015_pool_microbench.exe
```

Sweep: requested threads 1..8 x rows {8, 17, 64, 512, 1376, 4096}, twice
(warm, then cold) in the same process. The pool is a process-wide leaked
singleton with `threads_` parked at the high-water mark and `generation_`
monotonic, so the cold phase is the reachable case: the same cell re-run after
other thread counts have passed through the same pool.

After the fix:

```
STATES                             = 253
WORKERS                            = 1379
NA_LINES                           = 0
POST_BLOCKS                        = 84
ELIGIBLE_SEEN_NE_GENERATION        = 0
POST_WHERE_ELIGIBLE_COUNT_NE_ACTIVE= 0
MAX_PARKED                         = 7
STALLS                             = 0
DISPATCHES                         = 264
HARNESS_FAILURES                   = 0
VERDICT                            = PASS
```

Widened to cover the 16-logical-core host (requested threads 1..16, so worker
ids 0..14 exist and the mirror-growth path is exercised):

```
WORKERS                            = 3363
NA_LINES                           = 0
POST_BLOCKS                        = 108
ELIGIBLE_SEEN_NE_GENERATION        = 0
POST_ELIGIBLE_COUNT_NE_ACTIVE      = 0
MAX_PARKED                         = 15
MAX_WORKER_ID                      = 14
STALLS                             = 0
DISPATCHES                         = 336
HARNESS_FAILURES                   = 0
VERDICT                            = PASS
```

Assertions and what each one rules out:

| Assertion | Result | Rules out |
|---|---|---|
| `pending_at_return == 0` on every dispatched cell | 84/84 | Run() returning early; workers still writing into the caller's buffer |
| every row written exactly once, no sentinel left | 84/84 | surplus-worker double decrement; empty-slice budget debit |
| eligible worker `seen == generation` at every POST | 0 mismatches | stale-generation class |
| eligible count == `active` at every POST | 0 mismatches | geometry-publish class; surplus worker consuming a generation it is not budgeted for |
| warm and cold geometry identical per cell | 84/84 stable | cross-config contamination |
| row-coverage identical warm vs cold | 84/84 | same, measured through output rather than counters |
| stalls == 0 | 0 | bounded-wait expiry; fail-closed poisoning path never entered |

Both candidate classes are now discriminated by measurement rather than
assumption, and neither is present.

## Trace discipline

`RAWRXD_TRACE_ATTN_HEAD` is narrow, default OFF, read once. It emits no output
without the env var, so the ~782k-`fprintf` cost that was poisoning throughput
measurement is gone from the default path. The old `RAWRXD_ATTN_TRACE` name has
no active product effect. `RAWRXD_TRACE_POOL_STATE` is likewise default OFF;
it fires only on the three bracketed boundaries plus one line per parked worker.

Verified, not assumed: with both env vars cleared, a full sweep run produced
`STDERR_BYTES = 0` and exit 0. The instrumentation costs nothing when off.

## Logs

```
audit\pool_lifecycle_A_20261001_172110.log   baseline, trace OFF
audit\pool_B_stdout_20261001_172152.log      B-side, pre-fix
audit\pool_B_stderr_20261001_172152.log      B-side, pre-fix (garbage watermarks)
audit\pool_C_stdout_20261001_1722*.log       C-side, post-fix, threads 1..8
audit\pool_C_stderr_20261001_1722*.log       C-side, post-fix (clean watermarks)
audit\pool_D_stdout_*.log                    trace gates OFF, stderr empty
audit\pool_E_stdout_20261001_172625.log      threads 1..16, mirror growth
audit\pool_E_stderr_20261001_172625.log      threads 1..16 (worker id up to 14)
```

## Ledger

```
P0_POOL_LIFECYCLE
  STATUS                 = PASS
  FIRST_BAD_STATE        = src/rawrxd_cpu_math.cpp:826
                           vector<uint64_t> seenOf_{8,0} selected
                           initializer_list<uint64_t> -> 2 elements,
                           not 8; Worker's mirror-write guard excluded
                           id >= 2 and DumpState over-read the buffer
  SECOND_DEFECT          = mirror fixed at 8 entries on a 16-core host;
                           ids >= 8 published no watermark
  FIX                    = count-then-value init; bounded read in DumpState;
                           mirror grown under m_ at id assignment
  COMPILED               = YES (0 warnings, 0 errors)
  RUNTIME_EVIDENCE       = YES (108 POST blocks, 0 mismatches, 0 stalls,
                           worker id 14 observed, stderr 0 bytes with
                           trace gates off)
  HARDCODED_VERDICT      = NO
  SELF_CERTIFYING        = NO
  RECEIPT                = audit/RAWRXD_POOL_LIFECYCLE_001.md

P0_ATTENTION_NUMERICS
  STATUS                 = DEMOTED
  REASON                 = FRESH_RUNTIME_THREADS_2=PASS; pool lifecycle is
                           now proven, so the pool is no longer a candidate
                           explanation for the attention divergence

P1_PERFORMANCE_TUNING
  STATUS                 = OPEN
  BLOCKER_REMOVED        = pool lifecycle no longer unresolved
  REMAINING              = spread 11-68%, BASE_DRIFT -9% -- a distribution
                           problem across thread counts, which this receipt
                           does not address

P2_STALE_CANONICAL_BUILD_TREE  = OPEN
P1_SAME_SESSION_MODEL_TOOL_OBSERVATION = OPEN
```

## Scope note

This receipt covers the pool lifecycle only. It does not claim attention
numeric correctness, throughput parity, or any downstream inference result.