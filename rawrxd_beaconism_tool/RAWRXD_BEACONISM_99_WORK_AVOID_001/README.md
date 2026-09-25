# RAWRXD_BEACONISM_99_WORK_AVOID_001

Dependency-free C++20 source drop for **verified deterministic segment replay**.

## What it does

This implementation makes the "99% effective work avoided" target concrete without
pretending that arbitrary novel transformer states can magically skip 99% of inference.

It caches the exact output state of a deterministic Deep2 segment under:

- model identity
- model revision
- segment range
- runtime/config identity
- a 128-bit hash of the exact input state
- an independent input checksum
- an output checksum

On a verified hit, the segment output is copied directly and the real layer work is
not dispatched.

On a miss, collision, size mismatch, corrupt payload, model change, quant/config
change, or state change, the cache **fails closed** and Deep2 executes the real work.

## Why this can report >=99% avoided work

For a repeated deterministic state:

1. first occurrence executes real work and commits the result;
2. subsequent occurrences replay it;
3. after 100+ identical occurrences the amortized avoided work exceeds 99%.

That is real avoided work for repeated states. It is **not** evidence that 99% of the
math can be skipped for unrelated new tokens.

## Deep2 wiring

```cpp
BeaconReplayCache cache(2ull * 1024 * 1024 * 1024);

SegmentDesc d{};
d.model_id = modelIdentity;
d.model_revision = weightRevision;
d.segment_begin = 4;
d.segment_end = 25;
d.config_id = runtimeGeometryHash;
d.nominal_work_units = estimatedSegmentCost;

bool replayed = execute_or_replay(
    cache, d,
    layerInput, layerInputBytes,
    layerOutput, layerOutputBytes,
    [&] {
        deep2RunLayers(4, 25, layerInput, layerOutput);
    });
```

## Recommended production key material

`config_id` should include every item that can change deterministic output:

- architecture
- quant type / tensor packing revision
- context position
- attention mask mode
- RoPE parameters
- KV-cache generation/version
- active adapter/LoRA identity
- sampler-independent forward flags
- device kernel revision if numerical output differs

If context position or KV state differs, do not replay unless the input key fully
captures those differences.

## Build

From an MSVC x64 Native Tools prompt:

```bat
build_beaconism_99.bat
```

No CMake, Vulkan SDK, Python, package manager, or third-party library is needed for
this standalone certification harness.

## Receipt

The demo emits:

```text
=== RAWRXD_BEACONISM_99_WORK_AVOID_001 ===
LOOKUPS=
HITS=
MISSES=
HIT_RATE_PCT=
NOMINAL_WORK_UNITS=
EXECUTED_WORK_UNITS=
AVOIDED_WORK_UNITS=
WORK_AVOIDED_PCT=
COLLISION_REJECTS=
VALIDATION_REJECTS=
VERDICT=
```

## What to do next in Deep2

For actual transformer acceleration, place replay boundaries only at state points you
can certify. Good initial candidates are repeated prompt/prefix segments, agent-loop
system prompts, immutable tool schemas, repeated static document prefixes, and exact
KV/prefix states.

Do **not** use approximate angle/magnitude similarity as authority for skipping 99% of
layers until a separate logit/token parity gate proves it safe.
