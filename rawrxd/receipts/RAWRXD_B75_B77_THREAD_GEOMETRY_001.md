# RAWRXD_B75_B77_THREAD_GEOMETRY_001

## Status: PARTIAL — items 15/16 answered; the reported failures did not reproduce

```ini
RAWRXD_B75_ATTN_SLICE=PASS_BY_ANALYSIS, NOT_REPRODUCED_EMPIRICALLY
RAWRXD_B76_FAIL_CLOSED=PASS
RAWRXD_B77_THREAD_TERMINOLOGY=PASS
B77_PARITY=PASS  (115 chars)  prepared_cache_unit 30/30
```

## Items 1-16: the requested thread value is NOT lost

Traced end to end in `rawrxd_transformer.cpp:448-452`:

```ini
attn_regime        = ctx > thr
nt                 = attn_regime ? attn_threads_env : 1
if (nt > nH) nt    = nH
ParallelRows(&AttnHeadsTask, &ac, nH, nt)
```

and in `rawrxd_cpu_math.cpp`:

```ini
ParallelRows: threads <= 1 || total_rows < 2  ->  fn(ctx, 0, total_rows)   // inline
              otherwise                       ->  WorkerPool::RunThreads(...)
```

For the sweep geometry (H=512, NH=8, so nH=8), the clamp `nt > nH` never
fires for 1/2/4/8. **No rounding, no power-of-two conversion, no caching, no
divergent transformation between ATTN and MLP.** All four requested values reach
`RunThreads`.

## The actual finding: threads=1 is not the same kind of thing as threads=2

```ini
threads == 1  ->  RunThreads RETURNS IMMEDIATELY, caller executes ALL rows
                  inline. Zero workers dispatched.
threads >= 2  ->  caller KEEPS chunk 0 and dispatches (threads-1) workers.
```

```ini
requested   actual_workers   caller_participates   effective_participants
   1              0                 false                  1
   2              1                 true                   2
   4              3                 true                   4
   8              7                 true                   8
```

`effective_participants` is 1 for the inline case and `threads` for the split
case. The sweep's `threads=1` and `threads=2` labels sit on one axis in the
output while spanning two structurally different execution geometries. That is
the conflation that made "requested 2 disappeared" unresolvable from sweep
output alone — and it is now recorded explicitly rather than inferred.

Canonical definitions are enforced in code with accessors
(`LastRequestedThreads`, `LastActualWorkers`, `LastCallerParticipates`,
`LastEffectiveParticipants`) and populated per dispatch.

## Items 18-24: the depth-1024 failure did NOT reproduce

Ran the sweep end to end capturing pool diagnostics:

```ini
STALL_LINES = 0
ATTN threads=1  min= 444.2 med= 541.7 max= 721.3 spread=62%  0.77x  PASS
ATTN threads=2  min= 589.6 med= 642.0 max= 815.5 spread=38%  0.92x  PASS
ATTN threads=4  min= 576.4 med= 759.9 max= 899.7 spread=56%  1.09x  PASS
ATTN threads=8  min= 739.3 med= 803.6 max= 829.4 spread=12%  1.15x  PASS
```

Every ATTN cell PASSed. Zero stalls. The audit's `argmax_match=0` at nt=2 and
nt=4 is not reproducible on this binary.

## Why the old evidence should be discarded, not re-run

`AttnHeadsTask` is embarrassingly parallel BY CONSTRUCTION, provably:

```ini
sc   = c->scores + h * c->score_stride      scores_all(nH * ctx), stride = ctx
vsum = c->vsum + h * c->head_dim            vsum_all(nH * head_dim)
dst  = (*c->attn)[t].data() + h * c->head_dim
limit = start_pos + t + 1 <= ctx            -> slice [h*ctx, h*ctx+ctx) never overlaps
```

The partition arithmetic is also correct at every fan-out for nH=8:

```ini
threads  use  parts  chunk  populated  caller        workers
   2      1     2      4        1       [0,4)   [4,8)
   4      3     4      2        3       [0,2)   [2,4)[4,6)[6,8)
   8      7     8      1        7       [0,1)   [1,2)...[7,8)
```

And the sweep's own variance is 12-62% per cell, which is larger than any
difference the sweep is being asked to resolve. The prior FAIL cells are more
consistent with measurement instability than with a deterministic defect.

```ini
OLD_SPEEDUP_TABLE=DISCARDED
THREAD_OPTIMUM=UNKNOWN
ATTN_DEPTH_1024_REJECT=NOT_REPRODUCED
```

## B76: WorkerPool timeout escape — fixed, fail-closed

The latent defect is real even though it did not fire here. On a 10s timeout,
`Run()` returned while dispatched workers could still be inside
`fn(ctx, ...)` — and `ctx` is a stack object (`AttnCtx`), so those workers were
writing into storage the caller had already left.

Fix, fail-closed:

```ini
on stall        -> poisoned_ = true
while poisoned  -> RunThreads executes INLINE ONLY (cannot race a stale worker)
un-poison only  -> when pending_ == 0, i.e. the offending generation drained
```

A poisoned pool is slow but correct. The 10s bound was not raised, because
raising it reintroduces the silent hang the bound exists to prevent.

## Verification

```ini
EXE_SHA256_PRE  = B86B1C68B57C3396974C81AF14943921C109C751E26DDB827585FC01D8E957E6
EXE_SHA256_POST = B86B1C68B57C3396974C81AF14943921C109C751E26DDB827585FC01D8E957E6
BUILD_EXIT      = 0
B77_PARITY      = PASS (115 chars, B65 oracle)
prepared_cache_unit: checks=30 failures=0 VERDICT=PASS
```

## Not done

The diagnostic is in place but the sweep does not yet CONSUME it — items 17 and
25 require editing `regime_sweep.cpp` to print requested-vs-effective geometry
and to key correctness results by actual geometry rather than by label. That is
the next step and is not claimed here.

```ini
B75_COMMITTED=NO
B75_PUSHED=NO
```