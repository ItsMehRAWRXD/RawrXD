# RAWRXD_B77_THREAD_GEOMETRY_PROBE_001

## Status: PASS — ladder items 7, 8, 9, 18, 19, 22 answered by measurement

```ini
B77_THREAD_GEOMETRY_PROBE=PASS
VERDICT=PASS
DISPATCH_STALLS=0
COVERAGE=exact for every requested value
DETERMINISM=stable across 5 repeats
```

## The matrix (total=8, requested 1/2/4/8)

```ini
requested  actual_workers  caller_participates  effective_participants  coverage
   1             0                false                   1                 exact
   2             1                true                    2                 exact
   4             3                true                    4                 exact
   8             7                true                    8                 exact
```

Coverage is exact for every value: every row executed exactly once, no slice
overlapped, no row skipped. 5 repeats per value, identical every time.

## Ladder item 9: requested 2 did NOT disappear — and the real culprit was found

`requested=2` reaches the pool and produces `w=1, caller=yes, effective=2`.

But the probe DID expose a genuine "requested value disappears from the report"
defect, and it was in the diagnostic, not the execution:

```ini
ParallelRows(fn, ctx, total_rows, threads):
    if (!fn || total_rows == 0) return;
    if (threads <= 1 || total_rows < 2) { fn(ctx, 0, total_rows); return; }  <-- HERE
    WorkerPool::Instance().RunThreads(...)
```

For `threads <= 1` the function returns **before consulting the pool at all**, so
the pool's `last_*` geometry fields retained the PREVIOUS dispatch's values. The
probe's first iteration reproduced this exactly:

```ini
FAIL requested not recorded: 8 != 1
FAIL req=1 expected inline ... got w=7 caller=1 eff=8     <-- stale from the prior req=8 run
```

A receipt read after a `threads=1` cell would have reported the earlier cell's
fan-out. Execution was always correct — coverage was exact — but the record lied,
which is worse for a benchmark because it silently mislabels the geometry.

```ini
B78_INLINE_GEOMETRY_001=LANDED (concurrent session, same file)
EXECUTION_DEFECT=NO
REPORTING_DEFECT=YES
```

## Canonical definition now established in code

```ini
requested_threads      what the caller asked for
actual_workers         threads-1 for a split, 0 for inline
caller_participates    TRUE iff the caller kept a chunk of a fan-out
effective_participants 1 for inline, N for a split with N threads
```

Note the deliberate asymmetry: `effective_participants` is NOT uniformly
`workers + caller`. For a split it is `workers + 1`; for inline it is 1, because
no split occurred and `caller_participates` is false. A sweep must therefore
report all four fields, not one "threads" number — that is the entire point of
items 5 and 6.

## What this retires

The sweep label `threads=N` is now known to be unsafe on its own. With this
matrix established, the previously reported `argmax_match=0` cells cannot be
attributed to a lost or clamped request: every requested value produces the
geometry it advertises, coverage is exact, and stalls are zero.

```ini
REQUESTED_2_LOST=NO
DEPTH_1024_ATTN_REJECT=NOT_REPRODUCED
OLD_SPEEDUP_TABLE=DISCARDED
THREAD_OPTIMUM=UNKNOWN
```

The remaining spread in the sweep (12-62% per cell) is a measurement-variance
problem, addressed by items 26 and 27, not a geometry problem.

## Artifacts

```ini
tools/thread_geometry_probe.cpp   synthetic total=8 dispatch matrix
                                  links src/rawrxd_cpu_math.cpp directly
CMake target                      thread_geometry_probe (top level, EXCLUDE_FROM_ALL)
```

Links no engine, no GPU, no model. Runs in under a second.

## Concurrency note

`rawrxd_cpu_math.cpp` is being edited concurrently — `B75A_TIMEOUT_ESCAPE_IMPOSSIBLE`
and `B78_INLINE_GEOMETRY_001` both appeared in it mid-task. The fail-closed guard
(this workstream, `RAWRXD_B76_WORKERPOOL_FAIL_CLOSED_001`) coexists with them.
Two of my three edits to that file were superseded by equivalent concurrent ones;
the ones retained are the fail-closed poison flag and the terminology fields.

## Not done

Items 17, 25, 26, 27, 29, 30 remain: make `regime_sweep.cpp` consume these
accessors and print requested-vs-effective geometry, regenerate the speedup table
keyed by actual geometry, reconcile the TPS clocks, strip now-unneeded
instrumentation, and consolidate into the P0 receipt.

```ini
B77_COMMITTED=NO
B77_PUSHED=NO
```