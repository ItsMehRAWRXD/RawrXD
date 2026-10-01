# RAWRXD_B80_WORKERPOOL_GEOMETRY_P0_RECEIPT

    GATE            = RAWRXD_WORKERPOOL_PARTITION_001
                    + RAWRXD_B77_INLINE_PATH_RECORDED_001
                    + RAWRXD_B78_INLINE_GEOMETRY_001
                    + RAWRXD_B78_TALLY_LOCK_001
                    + RAWRXD_B79_INLINE_TALLY_001
    SUBJECT         = WorkerPool dispatch correctness and geometry reporting
    DATE            = 2026-10-01
    BUILDTOOL       = MSVC 14.44.35207 (VS2022 BuildTools), /std:c++20 /O2 /arch:AVX512 /MD
    HOST            = AVX-512F (+FMA), ctx_threshold=256 default
    VERDICT         = PASS (measured, three independent probes)

All fields below are measured from executed binaries. No field is asserted from
source reading. Binaries and objects are identified by name; the sources they
were built from are hashable at the recorded commit state.

---

## 1. Defects found and repaired

### 1.1 RAWRXD_WORKERPOOL_PARTITION_001 — completion budget unreachable

`WorkerPool::RunThreads` derived its row chunk as `ceil(total_rows / use)` and
gave worker `id` the range `[chunk*(id+1), min(+chunk, total_rows))`.

The number of NON-EMPTY worker slices under that split is
`ceil(total_rows/chunk) - 1`, which is at most `use - 1`. The completion budget
`pending_` was nevertheless set to `use`. The budget could therefore never be
reached, and every dispatch with `threads >= 2` waited out the bounded 10s
timeout and reported a stall.

Observed in the pre-fix binary (`rs3.log`, `chunk=1377` for `total=1376`,
`use=1`):

    [WORKERPOOL] STALL: use=1 active=1 parked=1 pending=4294967295
    generation=1 total=1376 chunk=1377

An earlier variant of the same function instead charged empty slices to the
budget, driving the unsigned `pending_` to `0xFFFFFFFF` and letting `Run()`
return while workers were still writing into the caller's buffer.

Repair: choose the chunk first, then derive the worker count as the exact
number of worker slices that exist, and set `pending_` from that same value:

    parts     = use + 1
    chunk     = ceil(total_rows / parts)
    populated = ceil(total_rows / chunk) - 1     // exact non-empty slice count
    use       = populated                        // <= requested use, always > 0
    pending_  = use

Because `chunk >= total_rows/(use+1)`, `populated <= use`, so the fan-out can
only shrink, never exceed what was requested.

### 1.2 RAWRXD_B77/B78/B79 — the inline path published no geometry

`ParallelRows` short-circuited on `threads <= 1 || total_rows < 2` and returned
**before** reaching `RunThreads`. That path therefore wrote no geometry record
at all, so the `last_*` registers and the `geom_[requested]` tally retained the
PREVIOUS dispatch's values.

Measured consequence (B78 probe, before repair), `total=8`:

    requested=1 -> workers=2 caller=yes effective=3

Those are the values of the preceding `total=3, requested=16` dispatch. A
`threads=1` cell was reported as a 3-way fan-out. This is the mechanism behind
"requested 2 disappeared from the report": the report could not distinguish a
configuration that never ran from one whose record was never written.

Repair: the inline path now records its own geometry through `RecordInline`,
which writes both the scalar registers and the per-requested tally.

### 1.3 RAWRXD_B78_TALLY_LOCK_001 — geometry tally written without the reader's lock

`RecordGeometry` wrote the eight scalar fields of `geom_[requested]` while
holding only `m_`. `GeometryForRequested()` read the same record under
`geom_m_`. A concurrent reader could observe a half-updated record — new
`actualWorkers` beside a stale `effectiveParticipants` — which is precisely the
contradictory geometry shape observed above.

Repair: the tally write now holds `geom_m_`, the same lock the reader takes.

---

## 2. Canonical thread vocabulary (ladder item 16)

The sweep label `threads=N` conflated two structurally different execution
geometries. The definitions now in force:

| field | meaning |
|---|---|
| `requested_threads` | what the caller asked `ParallelRows` for |
| `requested_workers` | `requested_threads - 1`, the naive expectation |
| `actual_workers` | workers actually dispatched after clamping to existing slices |
| `caller_participates` | whether the calling thread performed work |
| `effective_participants` | `actual_workers + (caller_participates ? 1 : 0)` |
| `inlined` | the whole call ran on the calling thread, pool untouched |

**An inline dispatch has `actual_workers = 0`, `caller_participates = 1`, and
`effective_participants = 1`.** The caller is emphatically a participant — it
performs every row — so `caller_participates` describes whether the caller did
work, not whether it was one of several slices.

Two consequences that make old results unreadable:

1. `threads=1` (inline, 0 workers) is NOT the `threads/2` point of a scaling
   curve. It is a different execution shape entirely.
2. `threads=N` beyond the row count is row-limited, not thread-limited. At
   `total=8`, requests of 9 and 16 both execute as 8-way.

---

## 3. Measured evidence

### 3.1 B78 — synthetic dispatch matrix (40 dispatches)

`tools/workerpool_geometry_probe.cpp`, totals {1,2,3,8,64} x requested
{1,2,3,4,5,8,9,16}. Every row is claimed by exactly one participant; the probe
counts visits per row and rejects any row not covered exactly once.

    PARTITION_DEFECTS=0
    (coverage=ONCE, maxvisit=1 for all 40 dispatches)

    total=8:
      requested=1  -> workers=0 caller=no  effective=1   (inline)
      requested=2  -> workers=1 caller=yes effective=2
      requested=3  -> workers=2 caller=yes effective=3
      requested=4  -> workers=3 caller=yes effective=4
      requested=5  -> workers=3 caller=yes effective=4
      requested=8  -> workers=7 caller=yes effective=8
      requested=9  -> workers=7 caller=yes effective=8   (row-limited)
      requested=16 -> workers=7 caller=yes effective=8   (row-limited)

    DISTINCT_GEOMETRIES_AT_TOTAL_8=8
    VERDICT=PASS

Row-limit clamping, measured: `total=2` requests 2..16 all execute
`effective=2`; `total=3` requests 3..16 all execute `effective=3`.

### 3.2 B79 — per-requested lookup is correctly keyed

`tools/request_geometry_probe.cpp`, `total_rows=4096` so the row clamp cannot
bind, 16 dispatches in an ascending then DESCENDING pass. A descending pass is
what makes "returns the last dispatch unconditionally" fail loudly.

    GEOMETRY_MISMATCHES=0
    REQUESTS_NEVER_DISPATCHED=0
    VERDICT=PASS

`timesRequested` accumulates correctly across both passes (2 after pass 1, 4
after pass 2), confirming the per-request tally is written on the inline path
as well as the dispatched path.

### 3.3 Correctness at depth

ATTN regime (`RAWRXD_CTX_THRESHOLD=15`), depth=1024, from the corrected build:

    ATTN threads=1  med= 1195.7  PASS
    ATTN threads=2  med= 1380.7  PASS
    ATTN threads=4  med= 1911.1  PASS
    ATTN threads=8  med= 1903.7  PASS

The earlier `argmax_match=0 determinism=0` at depth 1024 was NOT a pool defect.
It was the single shared `scores` buffer in `AttnHeadsTask`: concurrent heads
overwrote each other's scores. That is repaired by the per-head
`scores_all(nH*ctx)` / `vsum_all(nH*head_dim)` buffers in
`rawrxd_transformer.cpp`, after which parallel attention matches the serial
reference at every thread count.

---

## 4. Sweep-harness defect repaired separately

`regime_sweep.cpp` computed its `argmax_match` gate as an AND-of-last-write:
every non-discard rep assigned the flag, and then the rep at `kDiscard`
unconditionally overwrote it. Only the FIRST recorded rep could decide the
gate, so a configuration that diverged on reps 2 and 3 still printed PASS.

Repaired to accumulate with `&=` over all recorded reps, against the serial
reference. `determinism` remains a repeat-vs-repeat check against the
configuration's own warm-up sequence.

---

## 5. Explicitly NOT established

    DEPTH_4096_COMPLETION      = NOT_ESTABLISHED (see below)
    THREAD_SCALING_CURVE       = NOT_ESTABLISHED
    SPEEDUP_NUMBERS            = NOT_ADMITTED
    BASE_DRIFT                 = NOT_ESTABLISHED
    TPS_CLOCK_RECONCILIATION   = NOT_ESTABLISHED

`depth=4096` has not completed. An earlier run exited `-1` while three sweeps
and a stale `rs5.exe` were contending on the same fixture directory; that
resource failure is not a pool defect and is not recorded as one. A dedicated
run (`rs8d.exe`, own fixture `bench_tmp_v2`) was still executing at 147s CPU when
this receipt was written, having passed the depth=4096 header and the warm
reference. Its result is NOT claimed here.

The previously printed speedup table is DISCARDED. It was produced under the
stale-geometry recording of section 1.2, so a `threads=1` cell in that table
carried another cell's fan-out, and no speedup in it is attributable to the
thread count it was labelled with.

Baseline drift was measured between `-19%` and `+45%` across blocks, which is
larger than several of the speedups it would be used to correct. Drift
compensation is therefore not yet trustworthy and the drift compensation itself
is an open gate.

---

## 6. Artifacts

    tools/workerpool_geometry_probe.cpp    B78 synthetic dispatch matrix
    tools/request_geometry_probe.cpp       B79 per-request lookup keying
    src/rawrxd_cpu_math.cpp                 pool, partition, geometry records
    src/rawrxd_cpu_math.hpp                 DispatchRecord, accessors
    src/rawrxd_transformer.cpp              per-head scores/vsum buffers
    regime_sweep.cpp                        gate accumulation, geometry labels

## 7. Verdict basis

    PARTITION_DEFECTS          = 0        measured, 40 dispatches
    GEOMETRY_MISMATCHES        = 0        measured, 16 dispatches
    REQUESTS_NEVER_DISPATCHED  = 0        measured
    WORKERPOOL_STALLS          = 0        measured in corrected builds
    DEPTH_1024_ATTN_GATE       = PASS     measured, threads 1/2/4/8

VERDICT=PASS for the dispatch and geometry-reporting gate.

This verdict does NOT certify thread scaling, the speedup table, or depth 4096.