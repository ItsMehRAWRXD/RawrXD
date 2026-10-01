# RAWRXD_DEEP2_EXPERT_CONTROL_PLANE_CERT_001

## Claim

The Deep2 expert control plane — `Deep2PredictiveRouter`, `ExpertScheduler`,
`Deep2MultiGpuExpertCache`, `Deep2ExpertCacheBridge`, per-device `ExpertCache` —
now compiles, links into the canonical `InferenceEngine` static library, and
executes under real routing traffic.

## What changed

### Build adoption (`rawrxd/CMakeLists.txt`, `INFERENCE_ENGINE_SOURCES`)

These translation units existed, were self-contained, and appeared in **zero**
CMake targets before this change:

| Source | Prior CMake refs |
|---|---|
| `expert_cache/ExpertScheduler.cpp` | 0 |
| `expert_cache/PackedExpertSlicer.cpp` | 0 |
| `expert_cache/ExpertTensorCatalog.cpp` | 0 |
| `expert_cache/Deep2ExpertCacheBridge.cpp` | 0 |
| `expert_cache/Deep2MultiGpuExpertCache.cpp` | 0 |
| `Deep2RooflineGovernor.cpp` | 0 |
| `Deep2DualGpuBalancer.cpp` | 0 |
| `Deep2ExpertResidency.cpp` | 0 |
| `Deep2PredictiveRouter.cpp` | 0 |
| `Deep2PersistentDecode.cpp` | 0 |
| `Deep2CommandBatch.cpp` | 0 |
| `Deep2RooflineCert.cpp` | 0 |
| `Deep2RooflineRatchet.cpp` | 0 |
| `Deep2RooflineRuntime.cpp` | 0 |

`Deep2MultiGpuExpertCache` and `ExpertScheduler` were additionally referenced
only by `win32ide_strict/CMakeLists.txt`, so they never reached the product
link even though the IDE build compiled them.

### Runtime wiring (`Deep2Engine.h`, `Deep2Engine.cpp`)

`Deep2PredictiveRouter` is now constructed as a member and fed from the real
MoE route in `computeMoEFFN` (`Deep2Engine.cpp:3747+`):

- `observe(layer, ids)` on every valid route
- `ExpertCache::notePrediction(key, route.expertWeights[k], token)` — the real
  router probability now drives `EmaLfu` eviction scoring, which previously saw
  recency only
- `predict(layer, K)` issued per round, with overlap measured against the route
  actually used

Counters live in `ExpertPredictorCounters` and are exposed through
`getExpertPredictorTelemetry()` / `resetExpertPredictor()`. `reset()` clears only
generation-scoped counters; the learned heat map survives generation boundaries
because clearing it would destroy the state the predictor exists to build.

### Certification harness

`tools/deep2_expert_control_plane_cert.cpp` + target
`deep2_expert_control_plane_cert` (`EXCLUDE_FROM_ALL`).

### Census tool

`tools/deep2_build_graph_census.ps1` — measures adoption across every
`src/deep2` translation unit.

## Measured evidence

Build: `InferenceEngine.lib`, Release, MSVC 14.44.35207, C++20. `BUILD_EXIT=0`.
All 14 adopted sources produced objects.

Cert output: `audit/RAWRXD_DEEP2_EXPERT_CONTROL_PLANE_CERT_001/cert_output.txt`

```
TOTAL_EXPERTS_IMPORTED=128        CATALOG_BYTES=6291456
ACQUIRES=800                      ACQUIRE_HITS=800
ACQUIRE_FAILURES=0                SCHEDULER_DECISIONS=1600
SCHEDULER_REJECTED_NO_CAPACITY=0  PREFETCH_ACCEPTED=800
PREDICTIVE_ROUTER_ROUNDS=400      PREDICTIVE_ROUTER_KEYS=784
PREDICTIVE_ROUTER_MATCHES=436     PAYLOAD_INTEGRITY_CHECKS=800
TRANSPORT_UPLOAD_CALLS=32         TRANSPORT_UPLOAD_BYTES=1572864
BYTES_PER_UPLOAD=49152            EXPECTED_BYTES_PER_UPLOAD=49152
DEVICE0_RESIDENT_BYTES=786432     DEVICE0_CACHE_HITS=408
DEVICE1_RESIDENT_BYTES=786432     DEVICE1_CACHE_HITS=392
STRICT_GPU_VIOLATIONS=0           CPU_EXPERT_COMPUTE=0
VERDICT=PASS                      RUN_EXIT=0
```

Notable derivations rather than assertions:

- `BYTES_PER_UPLOAD == kExpertBytes` proves the cache accounts for the
  concatenated gate/up/down triple (3 × 16 KiB), not a single tensor. A cache
  that under-counted would over-admit experts past its own budget.
- `ACQUIRE_FAILURES == 0` with `SCHEDULER_REJECTED_NO_CAPACITY == 0` at 800
  demands is the load-bearing result. An earlier run of this same harness
  measured `ACQUIRE_FAILURES=777 / STRICT_GPU_VIOLATIONS=777` because the
  per-device budget was below the live working set — the scheduler correctly
  refused. That failure was a harness parameter error, not a code defect, and
  it is recorded here because it demonstrates the fail-closed path is real.
- `DEVICE0_CACHE_HITS=408 / DEVICE1_CACHE_HITS=392` over 800 acquires shows both
  devices served traffic from residency, not just one absorbing everything.
- `TRANSPORT_ALLOC_CALLS=32` against 800 acquires: 32 real uploads, 768 cache
  hits. Residency is doing work.
- `PREDICTIVE_ROUTER_MATCHES=436` of 784 predicted keys matched the route the
  router actually selected, predicted **before** observation. Predicting after
  observing would match trivially and would measure nothing.

## Build graph census

`audit/RAWRXD_DEEP2_BUILD_GRAPH_CENSUS_001/census_summary.txt`

```
TOTAL_DEEP2_CPP=480
REACHABLE_FROM_BUILD=257
UNREACHABLE_FROM_BUILD=223
UNREACHABLE_PCT=46.5
UNREACHABLE_STUB_FILES=135
UNREACHABLE_IMPLEMENTATIONS=88
VERDICT=MEASURED
```

The census is measured against both `CMakeLists.txt` and
`win32ide_strict/CMakeLists.txt`, so a file reachable from only the IDE build
counts as reachable.

Note the count moved from 413 to 480 between audits: the earlier figure counted
`src/deep2/*.cpp` non-recursively, this one includes subdirectories
(`lavapath/`, `expert_cache/`, `kernels/`, `speculative/`, `streaming/`,
`trailforge/`, `mars/`, `execution_policy/`, `special_graph/`).

135 of the 223 unreachable files are `// STUB` one-liners — quarantine targets,
not lost implementations. **88 are real implementations**, including
`Deep2B21`–`Deep2B75` (the entire batch plan/seal/cert series),
`K2ShardIo.cpp`, `KvPrefixAuthority.cpp`,
`SpeculativeGenerationAuthority.cpp`, `TokenReplayCacheAuthority.cpp`,
`Deep2QuantGemvRoofline.cpp`, `Deep2WaveOccupancy.cpp`,
`Deep2KvMlaTraffic.cpp`, `TrailForge`, `FleetSpecialGraph`.

## Scope limits

Stated so this receipt cannot be read as a stronger claim than it is:

- This cert does **not** prove `Deep2Engine` drives the control plane in
  production. It proves the units compile, link, and execute under routing
  traffic. The engine wiring at `Deep2Engine.cpp:3747` is compiled and
  instrumented but has **not** been observed running against a real MoE model:
  no MoE GGUF exists on this machine (only llama/gemma/phi3/tinyllama, all
  dense). `PREDICTIVE_ROUTER_RUNTIME_HITS` from the engine accessor therefore
  remains **unmeasured**, not passing.
- No GPU or NVMe bandwidth is measured. The transport is a host-memory
  simulator so placement decisions are attributable to the scheduler rather
  than device timing noise.
- No semantic parity claim for any model.
- `PREDICTIVE_ROUTER_MATCHES` measures overlap with a synthetic skewed
  distribution. It does not predict real model router behavior.

## Remaining work, in dependency order

1. **Close the runtime evidence gap.** Obtain an MoE GGUF, run the engine
   accessor, and record `PREDICTIVE_ROUTER_RUNTIME_HITS > 0` plus
   `PREDICTIVE_ROUTER_MATCHES > 0` from a real router. Until then the engine
   wiring is adopted-but-unobserved.
2. **Triage the 88 unreachable implementations** into
   `ADOPT / QUARANTINE / OBSOLETE`. The `Deep2B21`–`Deep2B75` series is the
   largest single block and needs a per-file decision, not a bulk add — many
   are `*Seal.cpp` cert stubs whose `Plan` structs are trivially constructible
   and would add link weight without runtime behavior.
3. **Quarantine the 135 stub files** so they stop inflating the census.
4. Only then: `model.deep2profile` persistence feeding the existing
   `ExpertCache::warmStart()`, multi-NVMe striping, persistent KV.

Item 4 stays last deliberately. `ExpertCache::warmStart()` already accepts a
caller-supplied hot-key list, so profile persistence is a writer in front of an
existing interface rather than a new subsystem.