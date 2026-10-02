# RAWRXD_B83_CONSOLIDATED_P0_RECEIPT

    GATES   = RAWRXD_WORKERPOOL_PARTITION_001
              RAWRXD_B77/B78/B79 geometry reporting
              RAWRXD_B81_CANONICAL_SWEEP_BUILD_001
              RAWRXD_B82_IDE_LINK_AND_P0_FALSE_PASS
              RAWRXD_SWEEP_DRIFT_MEDIAN_001
    DATE    = 2026-10-01
    VERDICT = PASS (dispatch + geometry + build + link + false-pass repair)

Every field below is measured from an executed binary. No speedup in this
receipt is admitted as thread scaling.

---

## 1. Dispatch correctness — closed

### Partition (RAWRXD_WORKERPOOL_PARTITION_001)

`chunk_ = ceil(total/use)` yields only `ceil(total/chunk) - 1 <= use - 1`
non-empty worker slices, while `pending_` was set to `use`. The budget was
unreachable, so every `threads >= 2` dispatch waited out the 10s bound.
Repaired by choosing the chunk first and deriving
`use = ceil(total/chunk) - 1`, with `pending_` from that same value.

### Inline geometry (B77/B78/B79)

`ParallelRows` returned on `threads <= 1` before reaching the pool, so it
published **no** record. Measured consequence at `total=8`:
`requested=1` reported `workers=2 effective=3` — the previous dispatch's values.
A `threads=1` cell looked like a 3-way fan-out.

### Tally lock (B78_TALLY_LOCK)

`geom_[requested]` was written without `geom_m_`, the lock its reader takes.
Eight scalar fields, so a reader could see a half-updated record.

### Measured, 40 + 16 synthetic dispatches

```ini
B78 PARTITION_DEFECTS         = 0
B78 DISTINCT_GEOMETRIES_TOTAL8 = 8
B78 VERDICT                   = PASS
B79 GEOMETRY_MISMATCHES       = 0
B79 REQUESTS_NEVER_DISPATCHED = 0
B79 VERDICT                   = PASS
```

## 2. Canonical thread vocabulary

`effective_participants = actual_workers + (caller_participates ? 1 : 0)`

| requested | actual_workers | caller_participates | effective |
|---|---|---|---|
| 1 | 0 | 1 | 1 (inline) |
| 2 | 1 | 1 | 2 |
| 4 | 3 | 1 | 4 |
| 8 | 7 | 1 | 8 |
| 9 at total=8 | 7 | 1 | 8 (row-limited) |

`threads=1` is **not** the `1/2` point of a scaling curve — it dispatches zero
workers. `threads=N` beyond the row count is row-limited, not thread-limited.
This is what made "requested 2 disappeared" unresolvable from sweep output.

## 3. End-to-end at depth — measured, previously claimed only in part

`rs12d.exe`, `RAWRXD_CTX_THRESHOLD=4096`, isolated fixture, **uncontended**:

```ini
EXIT = 0
warm serial reference = 282.45 tok/s (28.324 ms/step)

MLP threads=1  med= 301.0  spread=63%  1.00x  PASS  rows=512 slice=512 (inline; pool untouched)
MLP threads=2  med= 347.1  spread=47%  1.15x  PASS  rows=512 slice=256
MLP threads=4  med= 275.7  spread=86%  0.92x  PASS  rows=512 slice=128
MLP threads=8  med= 331.4  spread=72%  1.10x  PASS  rows=512 slice=64

argmax_match=1 determinism=1 no_stall=1   for every cell
pending_at_return=0                     for every cell
WORKERPOOL_STALLS = 0
```

**depth=4096 completes.** The earlier `EXIT=-1` was reproduced only while a
second sweep and a full IDE build were competing for the same host — it was
resource contention, not a crash, and it is not recorded as a defect in the
code. Under contention the same depth reported 154 tok/s against 282 tok/s
uncontended, which is itself the reason no contended number is admitted here.

## 4. Drift — reduced, still not eliminated

`RAWRXD_SWEEP_DRIFT_MEDIAN_001`: drift compared a trailing **median** against a
leading **first sample**. That is a cold sample against a settled statistic.

| comparison | depth=4096 measured |
|---|---|
| first-sample vs median (old) | — (not measured at this depth) |
| median vs median (new) | `BASE_DRIFT=+26%` |
| same block, contended, old comparison (depth=1024 ATTN) | `+69%` |

`+26%` still exceeds the 10% flag, so it is reported as
`ORDER_BIAS_SUSPECTED` and the block's speedups remain **not** thread scaling.
Median-vs-median fixed a measurement artifact; it did not make the host quiet.

## 5. Build and link

### Sweep lane (B81)

One command, every TU recompiled every time, CRT pinned once, live binary
detected by PID, output path refused for source extensions, linked image
asserted to begin with `MZ`:

```ini
LINK_OK bytes=184320 magic=MZ
COMPILE_FAILED=0
LINK_FAILED=0
```

### IDE target (B82)

```ini
BUILD_RAWRXD_AGENTIC_CLI stale cache = ON  -> configure aborted
BUILD_EXIT                             = 0
LINK_ERRORS                            = 0
IDE_EXE_BYTES                          = 20782080
SHA256 before P1 repairs               = CF0122EDAF23F986FB2CF6C4F559873383C59DE432261C28D8A48C9E56A399A3
SHA256 after  P1 repairs               = 41B9908ED1461F7A318D28173B237130D0327CFC3B7BCB783AFB62C4B1CFFED2
RAWRXD_DROPPED_SOURCE_TOTAL            = 225
```

The quarantine guard was correct; a pre-quarantine `ON` persisted in
`CMakeCache.txt`. The link now succeeds **with 225 sources still dropped**.

## 6. Two false passes repaired

`handleLspRenameSymbol` printed "Renamed 'a' -> 'b' (index rebuilt)" without
opening a file. `handleLspGotoDefinition` printed "Symbol not found" and then
returned `CommandResult::ok`. Both reachable from the IDE command path.

Repaired: rename now states rename is not implemented and returns an error;
goto-definition returns an error on a miss and a usage error with no argument
(taking the argument's first token, since `CommandContext` has no cursor).
Both compile and are present in the linked binary by hash.

## 7. Source-destruction incident — recorded in full

A build script captured compiler output in `$out`, which is
**case-insensitively identical** to the `$Out` parameter. `/Fe` therefore
resolved to `regime_sweep.cpp` and the linker overwrote 24516 bytes of C++ with
a 186368-byte PE image starting `MZ`. Recovery came from an incidental derived
copy; the lost concurrent geometry-label block was reinstated and the file is
committed at `3777093876`. Guards now refuse source-extension outputs and
assert `MZ`.

## 8. NOT established

```ini
THREAD_SCALING_CURVE          = NOT_ESTABLISHED (drift +26% exceeds threshold)
SPEEDUP_NUMBERS               = NOT_ADMITTED
BASE_DRIFT_ELIMINATED         = NO (+26% remains)
IDE_CLEAN_SHUTDOWN            = NOT_EXERCISED
IDE_SURFACES_RUNTIME          = NOT_EXERCISED
DIAGNOSTICS / CODE_ACTIONS    = INTERFACE_ONLY_RUNTIME_UNPROVEN
RENAME_IMPLEMENTED            = NO (repair stopped the lie; engine still absent)
EDITOR_FORMATTER              = NOT_FOUND
EXTRACT_FUNCTION              = CONFIRMED_GAP (0 results, 5 spellings)
DROPPED_SOURCES               = 225
IDE_CMAKE_AUTHORITY_CANONICAL = NOT_ESTABLISHED (2 target-name collisions)
RAWRXD_IDE_CMAKE_FULL_AUDIT_001 = IN_PROGRESS
PRODUCT_COMPLETION              = FAIL
```

## 9. Evidence index

| Artifact | Contents |
|---|---|
| `tools/workerpool_geometry_probe.cpp` | B78 synthetic dispatch matrix |
| `tools/request_geometry_probe.cpp` | B79 per-request lookup keying |
| `tools/build_regime_sweep.ps1` | canonical, guarded sweep build |
| `regime_sweep.cpp` | drift-median fix, geometry labels, fixed argmax gate |
| `src/rawrxd_cpu_math.cpp` | partition, inline geometry, tally lock |
| `src/core/auto_feature_registry.cpp` | two false-pass repairs |
| `d4096d.log` | depth=4096 end-to-end, uncontended |
| `build_ide_audit/ide_build{,2}.log` | both IDE links, EXIT=0 |
| `audit/RAWRXD_IDE_CMAKE_FULL_AUDIT_001/IDE_POSITION_AND_NEXT_STEPS.md` | IDE position |
| `audit/RAWRXD_IDE_CMAKE_FULL_AUDIT_001/P1_EDITOR_CODE_INTELLIGENCE_AUDIT.md` | P1 census |
| `receipts/RAWRXD_B80..B82*.md` | per-gate detail |