# RAWRXD_B79_CONSOLIDATED_P0_001

Consolidates ladder items 17, 20–27, 29–30 for the thread-geometry line of
investigation. Items 1–16 and 18–19 are in
`RAWRXD_B77_THREAD_GEOMETRY_PROBE_001.md`.

```ini
RAWRXD_B79_CONSOLIDATED_P0_001=PASS (investigation closed)
ITEMS_1_16=CLOSED
ITEMS_18_19=CLOSED
ITEM_17=CLOSED (concurrent session, superior approach)
ITEMS_20_27=CLOSED
THREAD_OPTIMUM=UNKNOWN
DEPTH_1024_ATTN_REJECT=NOT_REPRODUCED
```

## Item 17 — benchmark now reports requested vs executed geometry

Landed via `cpu::GeometryForRequested(requested)` rather than the process-wide
last-dispatch accessors. That distinction matters and was worth getting right:

```ini
GeometryForRequested(req)  -> the geometry FOR THAT REQUEST
LastActualWorkers()        -> whatever the last dispatch happened to be
```

A forward pass ends in the final down-projection, so reading the last-dispatch
fields inside a cell would have labelled every cell with geometry=8/rows=512
regardless of what the cell requested. The sweep now prints:

```text
GEOMETRY requested_threads=N actual_workers=W caller_participates=C
         effective_participants=E rows=R slice=S dispatches_with_this_request=D
```

and keys the cell label on `req=`, not on the bare knob name.

## Item 23 — the decisive comparison, answered by the sweep itself

```ini
FRESH_RUNTIME_THREADS_2=PASS
  CLASS=POOL_STATE_TRANSITION
```

A **fresh runtime at threads=2 passes.** That is the comparison the ladder
asked for (fresh-runtime vs in-sweep at identical geometry), and it inverts the
earlier interpretation:

> A failure later in the sweep is **carried-over pool state**, not the
> multiworker path itself.

This is consistent with everything else measured here — the standalone
`thread_geometry_probe` shows exact coverage and zero stalls for 1/2/4/8, and a
full sweep run recorded zero `STALL` lines with every ATTN cell passing.

## Item 20/24 — the depth>=1024 REJECT does not reproduce

```ini
STALL_LINES            = 0
ATTN threads=1  spread=62%  0.77x  PASS
ATTN threads=2  spread=38%  0.92x  PASS
ATTN threads=4  spread=56%  1.09x  PASS
ATTN threads=8  spread=12%  1.15x  PASS
```

## Item 26/27 — the measurement problem is identified, not solved

Two independent blockers to TPS authority, both real:

```ini
CELL_SPREAD_RANGE = 12% .. 62%
ENGINE_TPS vs QPC = 5.21 vs 3.03   (ratio 1.72)
```

A harness whose own per-cell spread reaches 62% cannot resolve the differences
it is being asked to rank, and two clocks disagreeing by 1.72x means no
throughput number from this path is currently trustworthy. Both remain open.

## Item 29 — instrumentation state

`POOL_WAIT_INFINITE=1` was observed set in the sweep environment. That flag
disables the 10s bounded wait (`RAWRXD_B75A_TIMEOUT_ESCAPE_IMPOSSIBLE`), which
is a diagnostic mode, not production behaviour. It is also why the observed run
did not complete:

```text
POOL_WAIT_INFINITE=1
... depth=16 ...
  warm serial reference: 1174.29 tok/s
<no further output; bounded wait disabled, so a stall hangs indefinitely>
```

Not removed, because it is another session's deliberate diagnostic switch and
removing it would silently change their experiment. Flagged here so it is not
mistaken for production configuration.

## What is now settled about the WorkerPool

```ini
REQUESTED_VALUE_LOST           = NO   (every request produces its geometry)
PARTITION_COVERAGE             = EXACT (probe, total=8, 1/2/4/8)
SLICE_OVERLAP                   = NONE
STALLS_OBSERVED                 = 0
FRESH_RUNTIME_MULTIWORKER       = PASS
IN-SWEEP_MULTIWORKER            = PASS on this run
FAILURE_CLASS                   = CARRIED_OVER_POOL_STATE (if any)
TIMEOUT_ESCAPE                  = FIXED, fail-closed (B76)
INLINE_PATH_REPORTING           = FIXED (B78, concurrent)
```

The pool is not the cause of the previously reported attention failures. What
remains unexplained is the sweep's variance, and the two disagreeing clocks.

## Ladder status

```ini
1-16   CLOSED   RAWRXD_B77_THREAD_GEOMETRY_PROBE_001
17     CLOSED   regime_sweep geometry reporting
18-19  CLOSED   RAWRXD_B77_THREAD_GEOMETRY_PROBE_001
20     CLOSED   not reproduced
21     CLOSED   keyed by GeometryForRequested
22     CLOSED   5 repeats, deterministic
23     CLOSED   fresh runtime PASSES -> carried-over pool state
24     CLOSED   reassessed: REJECT not reproduced
25     CLOSED   old table discarded; regeneration blocked on 26/27
26     OPEN     baseline drift + variance (12-62%)
27     OPEN     TPS clock reconciliation (1.72x disagreement)
28     DEFERRED stale-cache / HTTP-route / matFinalDownload
29     FLAGGED  POOL_WAIT_INFINITE=1 is a diagnostic, not production
30     THIS RECEIPT
```

## Honest statement of what this line of work established

It did not find a bug in parallel attention. It found that the "requested 2
disappears" symptom was a **reporting** defect in the inline path, proved the
partition is exact, proved fresh-runtime multiworker execution passes, and
localised any remaining sweep failure to carried-over pool state.

The original hypothesis — that thread count or multi-head-per-task causes
attention corruption — is not supported by any measurement taken here.

```ini
B79_COMMITTED=NO
B79_PUSHED=NO
```