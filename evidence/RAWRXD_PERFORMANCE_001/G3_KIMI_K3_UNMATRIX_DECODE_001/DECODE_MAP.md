# G3_KIMI_K3_UNMATRIX_DECODE_001 — DECODE_MAP

```text
PROMOTE=0
TIP_CLIMB=HOLD
NO_ADOPT_RUNTIME=1
NO_VENDOR_CHECKPOINT=1
```

Universal **un-matrix decode**: the matrix/model may be terabytes on disk; decode only needs a
bounded resident working set whose **next consumer** is known or predicted, moved async while
**current** computes. kimi-k3-in-c is the capacity oracle for that law. Deep2 already owns most
subsystem *names*; the product gap is wiring them under HOST_DECODE ProductRun without forcing
full residency.

---

## 1. Decode dataflow (kimi-k3-in-c)

```text
checkpoint (96 safetensors shards, ~1.56 TB)
        │
        ├─ pack_trunk.py → trunk.bin + trunk.json (~109 GB dense trunk runs)
        │
        ▼
k3_run forward(L=0..92):
  k3_trunk_bind(L)          ← pin prefix OR ring-slot resident
  k3_trunk_prefetch(L+1)    ← FIXED next consumer; async reader thread
  MoE: top-16 of 896        ← k3_cache LRU + batch prefetch (data-dependent)
  MXFP4 matmul in-place     ← no full expert dequant residency
  KDA state / MLA KV        ← fixed-size KDA; MLA ~2.37 MB/pos
        │
        ▼
greedy / incremental tokens   PEAK RSS dialed by --trunk-gb / --cache-gb
```

Architecture constants (v0.1.0 / built-in K3Cfg in `k3_run.c`):
93 layers · 69 KDA + 24 Gated MLA · 896 experts top-16 · SiTU-GLU · native MXFP4 experts.

---

## 2. kimi subsystems → Deep2 analogues (file:line)

| kimi mechanism | Public locus | Deep2 analogue | Local locus | Status vs un-matrix decode |
|---|---|---|---|---|
| Trunk / checkpoint reader | `src/io/k3_trunk.c`, `k3_trunk.h`; `k3_load.c` safetensors | GGUF mmap + sliding window + NVMeStream | `rawrxd_model_loader.cpp:580` `InitializeSlidingWindow`; `:1269` `MapPrefetchWindow`; `Deep2/NVMeStream.cpp`; `Deep2Engine.cpp:9076+` | **Partial.** Window/mmap exist; LAA:NO caps window (`:627`). ProductOpenSession still wants embed/lmHead resident (`ProductRuntime.hpp:67-79`). |
| Memory budget / bounded WS | `--trunk-gb` / `--cache-gb` / presets in `k3_run.c` (~403+) | FreeToken fixed zones + FutureConsumer physical pool | `FreeTokenMicroZone.hpp:10-15` (8×64 MiB default); `FutureConsumerLaw.hpp:12-16` `PHYSICAL_PAGE_POOL_GROWS=0`; `FutureConsumer_Space.cpp:38-56` | **Law present.** Pool size tiny vs kimi GB dials; not yet product-budgeted per model. |
| Pin prefix + stream ring | `K3Trunk` pin[] + arena ring; anti-LRU for sequential trunk | DualStick / FreeToken sticks + recycle Past→Future | `FreeTokenMicroZone.hpp:28 stick`; `BatchD_UnifiedAsyncMove.hpp:20-24`; DualStick **HOLD** on product HOST_DECODE (`ProductStreamerPrep.hpp:32-46`) | **Concept present; DualStick sealed HOLD.** HOST_DECODE arms FreeToken+FutureConsumer without DualStick. |
| Expert select + load | router top-16; `src/cache/k3_cache.c` LRU + prefetch | MoERouter + MoEWeightProxy + NVMeStream | `Deep2Engine.cpp:8175` `computeMoEFFN`; `:8237-8291` router→PrefetchAsync; `MoEWeightProxy.hpp:88-110`; `NVMeStream.cpp:158-338` | **Present on MoE/GPU path.** Sync Prefetch fallback when no Vulkan. HOST_DECODE disables GPU ICD → async Vulkan path cold. |
| MXFP4 native experts | `k3_ops.c` MXFP4 matmul; no full dequant | GGUF Q4_K / Q_K_M etc. + B015 FP32 materialize | `rawrxd_model_loader.cpp:2997` B015→WeightResidencyPool; MoE Q4_K handles in `MoEWeightProxy.hpp:27-35` | **Different format.** Deep2 GGUF quant path exists; MXFP4 K3-native not in R1 GGUF scope. |
| KDA fixed state | `k3_run.c` incremental carry; GATE 3 oracle | MLA / CKV / layer scratch (Deep2 K2 MLA) | `K2MLAWeights.hpp/cpp`; HOST_DECODE sanitizes elastic/ckv/mars (`Deep2Engine.cpp:6274+`) | **Partial analogue.** K3 KDA ≠ Deep2 MLA; both avoid unbounded growth vs full KV on all layers. |
| Tensor indexing | safetensors index + trunk.json offsets | GlobalTensorIndex + GGUF tensor table | `Deep2Engine.cpp:2121-2144`, `:3189`, `:11130`; `K2GlobalTensorIndex.hpp` | **Present** for multi-shard MoE. |
| Expert-history / cache traces | `--dump-cache-trace` → `expert_hist.json` / `expert_trace.bin`; `tools/sim_cache.py` | RouterPrefetchTelemetry + MoEPackHudMetrics | `RouterPrefetchTelemetry.hpp`; `rawrxd_inference.h:89+` MoEPackHudMetrics; `cpu_inference_engine.cpp:709` | **Telemetry exists;** kimi offline sim_cache replay is richer RE tool. |
| Correctness / oracle | tiny oracle GATE1–3; 93-layer conformance; byte-identical across budgets | ProductReceipt / StreamCorrupt / streamer parity / MoE validators | `ProductRun.hpp:70-85`; `StreamerParity_Post.cpp`; `moe_validation_test.cpp` | **Different contract.** kimi: identical tokens across RAM budgets. Deep2: product PASS receipt + fail-closed open. |
| CLI memory presets | `k3_run.c` ultra/laptop/desktop/workstation/server/max | ProductStreamerPrep + env floors | `ProductStreamerPrep.hpp:15-74`; `RAWRXD_HOST_DECODE` | Deep2 has host floor, not GB trunk/cache dials. |
| Async next-layer trunk | `k3_trunk_prefetch(L+1)` while compute L — **1.70× measured** | FutureConsumer `next` + UnifiedAsyncMove + MapPrefetchWindow | `FutureConsumerSpace.hpp:33-38` PhysicalPage.next; `FutureConsumer_Advance.cpp:8-44`; `ElasticResidencyManager.cpp:1209+` `EnqueueUnifiedAsyncMove`; `BatchD_UnifiedAsyncMove.hpp` | **Largest product gap:** law + enqueue exist; HOST_DECODE ProductRun decode loop does not yet *drive* L+1 host moves from FutureConsumer schedule like `k3_trunk_prefetch`. |
| Product session | n/a (CLI weights) | ProductOpenSession / ProductRun | `product_deep2_infer.cpp`; `ProductRuntime.hpp:54-103`; `ProductRun.hpp:17-96` | Open fails if tensors not resident — **anti-pattern vs kimi capacity law** under LAA:NO multi-GB. |

---

## 3. Deep2 already-on-disk inventory (exhaustive enough for next dissection)

### Fixed zones / recycle
- `src/deep2/lavapath/FreeTokenMicroZone.hpp` — fixed overwrite slots; `model size ≠ residency` comment L2
- `src/deep2/lavapath/FreeTokenMicroZone.cpp` (+ `_Query.cpp`)
- `src/deep2/lavapath/FutureConsumerLaw.hpp` — PHYSICAL_PAGE_POOL_GROWS=0; REUSE_REQUIRED=1
- `src/deep2/lavapath/FutureConsumerSpace.hpp` — Register / AdvanceOwnership / NotePrefetch*
- `src/deep2/lavapath/FutureConsumer_*.cpp` — Space, Register, Advance, Notes, Emit, EmitExec

### Unified async move / hierarchy
- `src/deep2/lavapath/BatchD_UnifiedAsyncMove.hpp` — Router→IDs→UnifiedAsyncMove→GPU; B011 hit_rate ref ~79.96%
- `src/deep2/ElasticResidencyManager.hpp:222` `UnifiedAsyncMove`; `.cpp:1209` Enqueue / `:1214` Execute
- `src/deep2/NVMeStream.h` / `.cpp` — registerExpert / acquireExpert / prefetchExpert / prefetchPredicted / evictLRU
- Hierarchy comment: VRAM → RAM → NVMe (`BatchD_UnifiedAsyncMove.hpp:39-42`)

### MoE / pack / swarm
- `src/deep2/MoERouter.*`, `MoEWeightProxy.*`, `MoEWeightsLoader.*`
- `src/core/moe_plan_row_mixture_pack_cache.hpp` — MoEMixturePlanPackCache
- `src/core/swarm_scheduler.hpp` + `rawrxd_inference.h` swarm scheduler bind
- `Deep2Engine.cpp:8242` BATCH_D / B011 comment on fetch-cost frame

### Product / HOST_DECODE floor
- `ProductStreamerPrep.hpp:24-54` — LAA:NO or HOST_DECODE → force host floor, DualStick=0, FreeToken+FutureConsumer init
- `ProductRun.hpp` / `ProductRuntime.hpp` / `ProductRunDecode.hpp`
- `HeadlessIDE.cpp:1766+` LocalOnly ProductOpenSession + HOST_DECODE

### Sliding window / residency
- `rawrxd_model_loader.cpp:573-700` sliding window; `:1253-1342` prefetch view
- `runtime/memory/WeightResidencyPool.hpp`
- `ResidencyManager.*`, `TensorResidencyCache.hpp`, `HostResidencyManager.hpp`

### Prefetch overlap gates / certs (exist; do not promote)
- `K2PrefetchOverlapGate.hpp`, `VwaPrefetchOverlap.hpp`, `deep2_vwa_*_prefetch_*.cpp`
- B011 refs in BatchD header only — historical cert numbers, not this gate's promote

---

## 4. Capacity proof vs latency/async gap

### A. Capacity proof (external — sealed as REFERENCE)
| Claim | Source |
|---|---|
| 2.78T / 1.56 TB / 8.24 GB peak RSS | kimi-k3-in-c README |
| RAM dial changes clock only (byte-identical) | README ladder 8→128 GB |
| Experts never fully resident (~1.45 TB sleep on disk) | `k3_run.c` header comments |
| Trunk streaming turns floor into dial | `k3_trunk.h` |
| Oracle GATE1–3 + incremental ≡ full recompute | README / `k3_run.c` DECODE STRATEGY |

### B. Latency / async gap (Deep2 value proposition)
| Observation | Implication for Deep2 |
|---|---|
| 8GiB wall ~78–83% I/O (Rust port) | Kernel polish ≠ primary; move overlap is |
| Trunk L+1 prefetch alone → **1.70×** | Fixed FutureConsumer schedule is enough for large win |
| 26.5→5.6 s/tok via more RAM | Pinning reduces bytes; async hides remaining |
| Metal 1.9–2.9× (Exorust/kimi-k3-metal) | Accelerator helps *after* or *beside* I/O hide; still not capacity |
| kimi expert LRU weak vs flat router | Prediction quality caps expert-side overlap |

### C. What Deep2 has vs missing for FutureConsumer-driven prefetch
| Have | Missing / blocked |
|---|---|
| FutureConsumer registry + AdvanceOwnership + stall counters | Decode loop does not schedule NVMe reads from `nextUse` tiers on HOST_DECODE |
| UnifiedAsyncMove Cold→Hot | Requires elastic residency + often Vulkan; HOST_DECODE blocks ICD |
| MoE PrefetchAsync + pendingPrefetches_ | Same GPU dependency; sync Prefetch only on CPU fallback |
| Sliding MapPrefetchWindow | Not driven by FutureConsumer; LAA:NO 256 MB cap |
| ProductStreamerPrep arms FreeToken+FutureConsumer | ProductOpenSession still fail-closed without resident embed/lmHead |
| B011 fetch-cost framing | Not measured on current R1 HOST_DECODE product wall |

---

## 5. R1 light tie-in

```text
G3_R1_TEN_GGUF_MATRIX_001: FAIL_CLOSED PASS=7/10
LAA:NO → ProductOpenSession cannot reserve multi-GB Deep2 tensors (~2GB VA)
kimi streaming authority validates the CORRECT capacity law for that failure class
DO NOT claim R1 10/10 or PROMOTE from this RE gate
DUALSTICK_ARM remains 0 on product HOST_DECODE floor
```

Evidence: `G3_R1_TEN_GGUF_MATRIX_001/KEY_LINES.txt`, `G3_R1_TEN_GGUF_LIFECYCLE_001/RECEIPT.txt`,
`G3_R1_CAPABILITY_CERT_001/PHASE0_AUTHORITY.txt`.

---

## 6. Next Deep2 dissection targets (exact symbols)

Priority order for **latency/async** (not DualStick climb):

1. **`Deep2::future::Register` / `AdvanceOwnership` / `NoteStallNs`**
   - Wire from ProductRunDecode / generateStream layer walk to emit Current vs Future1.
2. **`k3_trunk_prefetch` analogue on host**
   - `RawrXDModelLoader::MapPrefetchWindow` + dedicated reader OR `NVMeStream::prefetchExpert`
   - Must run under `RAWRXD_HOST_DECODE=1` without Vulkan.
3. **`ProductRuntime::OpenSession` false-arm / residency gate** (`ProductRuntime.hpp:67-79`)
   - Align with MODEL_SIZE≠RESIDENT: open = index+authority, not full materialize.
4. **`Deep2Engine::computeMoEFFN` prefetch block** (`Deep2Engine.cpp:8237-8291`)
   - Ensure CPU/HOST path uses host Prefetch, not only `PrefetchAsync(vulkan)`.
5. **`ElasticResidencyManager::EnqueueUnifiedAsyncMove`**
   - Confirm HOST_DECODE can enqueue host-tier moves (RAM←NVMe) without GPU.
6. **`FreeToken::Overwrite` / dual stick zones**
   - Measure Current+Next dual residency like kimi 2-slot trunk ring (without reopening DualStick GPU arm).
7. **Telemetry parity**
   - Emit I/O share of wall like kimi `k3_run` end banner; compare to B011 hit_rate.

kimi subsystems to keep reading (public only):
- `src/io/k3_trunk.c` (prefetch worker / ring)
- `src/cache/k3_cache.c` (LRU + batch prefetch)
- `src/core/k3_ops.c` (MXFP4 / KDA / MLA / MoE)
- `src/cli/k3_run.c` `forward()` L572-580 bind+prefetch
- `tests/` oracle gates; `tools/sim_cache.py`

---

## 7. Cited URLs

- https://github.com/FareedKhan-dev/kimi-k3-in-c
- https://github.com/FareedKhan-dev/kimi-k3-in-c/blob/main/src/cli/k3_run.c
- https://github.com/FareedKhan-dev/kimi-k3-in-c/blob/main/src/io/k3_trunk.h
- https://github.com/undeemed/kimi-k3-in-rust
- https://github.com/Exorust/kimi-k3-metal (description: 1.9–2.9× Metal backend)

No 1.56 TB checkpoint vendored. Small header/CLI excerpts used for citation only.
