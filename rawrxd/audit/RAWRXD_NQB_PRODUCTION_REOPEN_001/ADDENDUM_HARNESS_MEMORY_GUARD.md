# RAWRXD_NQB_HARNESS_MEMORY_GUARD_001 — 2026-10-05

Resource governance for `nqb_first_bad_state`. Not a change to what the harness
measures — a refusal to start when starting would starve the machine.

## The hazard, measured

```ini
nqb_first_bad_state working set peak   28,776 MB per run
FreePhysGB during concurrent -j6 build     0.8 GB
"CL.exe" exited with code -1          (no diagnostic emitted)
same build at -j1                     BUILD_EXIT=0
```

```ini
BUILD_FAILURE_CLASS=CAPACITY_PRESSURE_STRONGLY_SUPPORTED
COMPILER_DEFECT=NOT_ESTABLISHED
```

The 28 GB peak is not a harness defect. It materialises a 12.85 GB payload, which
is the thing under measurement. It *is* a hazard to everything else, and a
resource failure that prints nothing is indistinguishable from a broken source
file unless you know the memory number.

`nqb_first_bad_state` pre-edit identity:
`SHA256=235B74E7B43233DB246E663F035C13CCD78509C1CED5F87F466069DCB49A4368`
(git-tracked, so recoverable regardless).

## Progression followed

```ini
1. PREFLIGHT_HEADROOM        implemented
2. EXPLICIT_PEAK_BUDGET      implemented
3. FAIL_CLOSED_REFUSAL       implemented
4. OPTIONAL_STRESS_OVERRIDE  implemented
5. REDUCE_MATERIALIZATION    deliberately NOT done
```

Step 5 is skipped on purpose. Chunking changes the behaviour being measured and
could destroy the reproduction. A Job Object memory ceiling is likewise **not**
the primary mechanism: an arbitrary kill turns a real harness result into "Windows
terminated the process at a ceiling of our choosing". If added later it belongs
after the preflight as an accident barrier, not instead of it.

## Contract

```ini
GATE=RAWRXD_NQB_HARNESS_MEMORY_GUARD_001

EXPECTED_PEAK_BYTES            = 30198988800   (28.125 GiB, measured)
MIN_SYSTEM_HEADROOM_BYTES      =  8589934592   (8 GiB)
SAFE_TO_START = avail >= EXPECTED_PEAK + MIN_SYSTEM_HEADROOM

if SAFE_TO_START=0:
    MODEL_LOAD_ATTEMPTED=0
    VERDICT=REFUSED_INSUFFICIENT_MEMORY
    exit 2

NQB_HIGHMEM_MODE=STRESS:
    HIGH_MEMORY_OVERRIDE=1
    VERDICT=PROCEED_OVERRIDDEN
```

Both figures are env-overridable (`NQB_HARNESS_EXPECTED_PEAK_BYTES`,
`NQB_HARNESS_MIN_SYSTEM_HEADROOM_BYTES`). A malformed or zero override falls back
to the default rather than silently disarming the guard.

The guard runs after argument validation and before any model load, so a refusal
costs nothing and cannot leave a half-materialised 12.85 GB array behind.

## Three states, all measured

```ini
1  SAFE, real headroom
   AVAILABLE_PHYS=48025939968  REQUIRED_TOTAL=38788923392
   SAFE_TO_START=1  MODEL_LOAD_ATTEMPTED=1  VERDICT=PROCEED
   -> ran to completion: VERDICT=DIVERGENCE_AT_NON_LAYER_RECORD

2  SAFE, headroom removed (peak declared 90 GB)
   AVAILABLE_PHYS=47932674048  REQUIRED_TOTAL=98589934592
   SAFE_TO_START=0  MODEL_LOAD_ATTEMPTED=0
   VERDICT=REFUSED_INSUFFICIENT_MEMORY
   REFUSAL_ELAPSED=0.1s        <- no model load occurred
   exit=2

3  STRESS override, same low headroom
   SAFE_TO_START=0  HIGH_MEMORY_OVERRIDE=1
   OVERRIDE_REASON=explicit NQB_HIGHMEM_MODE=STRESS
   WARNING=this run may starve a concurrent build; a previous -j6 build died at FreePhysGB=0.8
   MODEL_LOAD_ATTEMPTED=1  VERDICT=PROCEED_OVERRIDDEN
   exit=1   (the harness's own downstream verdict, not the guard's)
```

An override nobody can see is not an override, it is an unlabelled 28 GB
allocation — hence `HIGH_MEMORY_OVERRIDE=1` and the reason line.

## Receipt precision correction

`RAWRXD_GGUF_ZERO_EXPANSION_RESIDENCY_001` reported
`WEIGHTS_ARE_MAPPED_NOT_EXPANDED=1`, derived from `peakPriv < diskGB`. That
overclaimed: low private commit refutes persistent private F32 expansion, but does
not prove the implementation mechanism is file mapping. Shared memory, or any
mapping not backed by the model file, produces the same number.

```ini
LOAD_COMPLETED=1
CHILD_PEAK_PRIVATE_GB=0.647
PRIVATE_COMMIT_OVER_F32_EQUIVALENT=0.0540
PERSISTENT_PRIVATE_F32_EXPANSION=REFUTED
WEIGHTS_MECHANISM=NOT_DIRECTLY_OBSERVED
WEIGHTS_NONPRIVATE_OR_FILE_BACKED=SUPPORTED
VERDICT=PASS
```

Certifying the mechanism would need a direct observation of mapped regions
(`VirtualQuery` for `MEM_MAPPED`, or the Memory Working Set counters), which this
probe does not take. Source corroborates file mapping — `bindTensor` points
`WeightTensor::data` at the loader's mapped bytes and the token profile reports
`DEQUANT_*=UNAVAILABLE_FUSED_IN_KERNEL` — but corroboration is not measurement.

## Kept negative control: a real launch failure, not a constructed fixture

The probe's first run returned `INVALID_NO_RESULT`. The cause was a defect in the
probe: it appended `2>&1` to a `CreateProcessA` command line, which does not go
through a shell, so the child received it as a literal argument.

```text
[server] Unknown option: 2>&1
LOAD_COMPLETED=0  VERDICT=INVALID_NO_RESULT  exit 2
```

This is worth preserving as a regression case rather than only fixing. It proves
the readiness gate catches an actual process-launch failure, not just a synthetic
negative fixture — and it demonstrates the exact false certification the gate
exists to prevent:

```text
child used almost no memory  ->  therefore the loader is efficient
```

when in truth the child never loaded a model.

Two falsification modes remain verified:

```ini
NC1  readiness marker absent -> INVALID_NO_RESULT, exit 2
NC2  ratio over 0.50 of F32 equivalent -> FAIL, exit 1
```

## Two separate memory stories, not contradictory

```ini
GGUF_SHIPPING_LOAD
  LOAD_COMPLETED=1
  FILE_SIZE_GB=1.270   F32_EQUIVALENT_GB=11.968
  PEAK_PRIVATE_GB=0.647
  PERSISTENT_PRIVATE_F32_EXPANSION=REFUTED

NQB_FIRST_BAD_STATE
  TRANSIENT_PEAK=28.1_GB
  PROCESS_EXITS_NORMALLY=YES
  ZOMBIE=NO            RESPAWN_LOOP=UNPROVEN
  CONCURRENT_BUILD_HAZARD=YES
  MEMORY_GUARD=IMPLEMENTED   RAWRXD_NQB_HARNESS_MEMORY_GUARD_001
```

The first proves the shipping GGUF path does not retain an F32-sized private
model image. The second proves a diagnostic NQB harness can transiently consume
~28 GB. Both are true and they are about different code.

## State

```ini
rawr-server.exe        BUILD_PASS
RawrXD-Win32IDE.exe    BUILD_PASS
AGENTPANEL_LIFECYCLE  3 transitions under one gate, ownership taken at handler top
NQB_HASH_CHUNK_PARTITION_INVARIANCE  PASS
NQB_CHAIN_SELFTEST                   PASS
NQB_FIRST_BAD_STATE_MEMORY_GUARD     PASS (3/3 states)
```

Production code untouched in this tranche.