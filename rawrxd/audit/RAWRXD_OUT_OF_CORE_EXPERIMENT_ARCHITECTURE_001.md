# RAWRXD_OUT_OF_CORE_EXPERIMENT_ARCHITECTURE_001

Experiment architecture, written from scratch, for the question:

> On this host, does explicit Direct I/O into a fixed compute arena beat
> `mmap` + OS page cache for models whose working set exceeds physical RAM?

Everything below is designed so that a result cannot be reinterpreted after it
is observed, and so that a harness bug cannot be reported as a model property.

---

## 1. Evidence already in hand

Two real runs, both from harnesses that link the actual engine
(`InferenceEngine.lib` → `Deep2::Deep2Engine::loadModel` + `generateStream`).
Neither uses a phantom C-API.

**Run A — TinyLlama 0.62 GB, 32 tokens, `VERDICT=STREAM_TELEMETRY_OK`**

```text
loadModel            78.0 ms      read_MB=0.00 on every token
resident_MB          728 (flat)   file 0.62 GB
faults  token 0      154,203      faults tokens 1..31   0-2 each
output               " the city of Paris, which is the capital of France."
```

Interpretation: the working set fits in 63 GB RAM. Token 0 faulted the entire
model in from the page cache; every later token was pure compute. **Zero
storage reads occurred at any point.** In this regime `mmap` is unbeatable and
direct I/O can only add cost.

**Run B — Kimi K2 shard 00001, 43.12 GB, 1 token**

```text
loadModel            966.0 ms      read_MB=0.00
callbacks=0  generatedTokens=0  status=4
VERDICT              STREAM_TELEMETRY_MISMATCH
```

Interpretation: load succeeded as VMA construction (966 ms, zero bytes read) —
which is already the out-of-core signature — but **no token was produced**. The
thrashing question was never reached.

### What we do not know, and must not assume

1. `status=4` is undecoded. It may be admission rejection, MLA topology, or a
   forward-pass failure. **UNKNOWN.**
2. Kimi K2's full working set was never exercised. **UNMEASURED.**
3. Whether Deep2 can stream *any* model larger than RAM. **UNMEASURED.**

---

## 2. Experiment 0 — GATING. Decode `status=4` before anything else

**RESOLVED 2026-10-02. Gate 0 outcome: PASS on viability, with a newly
discovered blocker that redirects the ladder.**

`GenerationStatus` (`Deep2Engine.h`) is `Completed=0, EndOfSequence=1,
Cancelled=2, InvalidInput=3, ForwardFailure=4, InternalError=5`. So `status=4`
is **`ForwardFailure`** — not an admission rejection and not an architecture
refusal. The model loaded, was admitted, and failed inside the forward pass:

```text
MLA_METADATA arch=deepseek2 layout=split numHeads=64 kvLoraRank=512
               qLoraRank=1536 qkNopeHeadDim=512 qkRopeHeadDim=64 vHeadDim=512
               keyLength=576 valueLength=512 geometryValidated=1
admission OK   arch=deepseek2 family=MLA moe=1 mla=1 quant=Q4_K tensors=1096
MLA_ELIGIBLE   layersBound=61/61 useMLA=1
[INIT]         hiddenDim=7168 vocabSize=163840 numLayers=61 numHeads=64
[FWD_ALL]      seqLen=1 numLayers=61 isMoE=1 useMLA=1 vulkan=0/0
forward failed: attention: GPU MLA path failed or unsupported
failureDetail: prefill forward failed at token 0 stage=cpu_forward_exception
```

**ROOT CAUSE: Deep2 has no CPU MLA attention implementation.** The MLA path
falls through to a GPU-only branch and throws when Vulkan is disabled
(`vulkan=0/0`). Every MLA-family model is therefore blocked at the first forward
pass regardless of size, quantisation, or I/O strategy.

Consequences, both immediate:

1. **No I/O architecture can route around this.** Arena design, direct I/O and
   prefetch are all downstream of a forward pass that throws. This is a missing
   compute path, not a memory-management problem.
2. **E1 MUST NOT use MLA models.** The RAM-boundary sweep has to be built from
   non-MLA architectures or every cell will fail identically at token 0 for a
   reason that has nothing to do with memory.

### Screening rule adopted for all subsequent experiments

Before any model is admitted to the ladder, its forward path must be proven to
exist on CPU. Concretely: a candidate is eligible only if it streams at least
one token. This is the same discipline applied to the fused gate+up split today
— the engine's consumption had to be proven before the gate was relaxed, and
the difference between "loader binds a tensor" and "forward pass uses it" is
exactly what Kimi just demonstrated.

```text
GATE 0 PASS  = status decoded, failure is NOT an admission rejection
               -> ladder may proceed, on non-MLA models only
GATE 0 RESULT = PASS (viability), BLOCKER FOUND (no CPU MLA attention)
```

---

## 3. The experiment ladder

Each rung isolates one variable. No rung may be reported before its controls pass.

### E1 — Locate the RAM boundary empirically

Do **not** begin with a 578 GB model. Locate the regime boundary using models we
already have, which requires no new capability.

```text
sweep model sizes:   0.62 GB -> 3.3 GB -> 8.5 GB -> 43.1 GB (shard)
measure per model:   loadModel ms, read_MB total, faults, resident_MB peak,
                     time-to-first-token, tokens/sec

THE BOUNDARY IS WHERE read_MB BECOMES NON-ZERO.
```

Deliverable: a measured curve, and the size at which the OS page cache stops
absorbing the working set. This converts "out-of-core is untested" into a number,
using models that already stream.

```text
GATE 1 PASS = read_MB > 0 observed at some tested size, and the curve is
              monotonic enough to extrapolate
GATE 1 FAIL = read_MB stays 0 across the whole sweep -> this host's page cache
              absorbs everything tested; the >RAM regime needs a bigger model
              than we can test, and that is a finding, not a failure
```

### E2 — Demand paging vs explicit prefetch, at the boundary

Once E1 finds a size where storage is genuinely involved, compare the two
scheduling policies over identical bytes:

```text
A) current    demand paging, whatever the OS chooses (this is production today)
B) sequential touch of the whole mapped region before decode (explicit prefetch,
               but still mmap — keeps the page cache, just orders it)
```

This isolates *ordering* from *mechanism*. It is the cheapest possible win if
prefetch beats demand, and it does not require abandoning `mmap`.

### E3 — Direct I/O A/B, same bytes, same process

`certs/direct_io_probe_001.cpp` (written, not yet built) does exactly this:
`mmap`+residency versus `FILE_FLAG_NO_BUFFERING` into a 4096-aligned arena over
an identical byte range of a real GGUF.

```text
THE COMPARISON MUST BE:
  same file, same offset, same length, same buffer size
  both cold (drop caches or use a range not recently touched)
  report MEASURED bytes, not inferred faults
```

Note the alignment constraint discovered while writing it: unbuffered reads
require offset, length **and** buffer address all sector-aligned, so the real
unit of transfer is an aligned block, never a tensor. That is a permanent
property of the design and must be stated in any result.

### E4 — Random access, which is the actual MoE workload

E3 measures a contiguous read. Real MoE decode is **random per-expert access**,
and that is where `mmap`'s sequential readahead stops helping. Measure both
schemes under a random 4 KB-block access pattern derived from an actual routing
trace, not a synthetic uniform one.

This is the rung most likely to change the conclusion, and the one most likely
to be skipped. Do not skip it.

### E5 — Full out-of-core on a >RAM model

Only reachable if Gate 0 passes and E1 shows a real boundary. The 578.58 GB
Kimi K2 set is the target. Expect: heavy page-cache eviction, minutes-scale
first token, and a visibly unresponsive machine during the read. That last part
is a real cost to the user, not just to the benchmark, and should be agreed
before starting rather than discovered mid-run.

---

## 4. Instrument status

| instrument | state | notes |
|---|---|---|
| `certs/rawr_dog_harness.cpp` | **BUILT, RUNNING** | real engine; per-token latency, faults, measured `read_MB`, resident |
| `certs/direct_io_probe_001.cpp` | written, **UNBUILT** | the E3 A/B |
| `deep2_streamer_cert` | built | 4 models stream; `STREAMER_CORRUPT=0` |
| receipt with per-model numbers | **MISSING** | `streamer_cert.txt` is 570 B, one `TOTAL_BYTES` line |

### Defects in the instruments that must be fixed before their results count

1. **Shard-set size mislabel (mine, confirmed).** `rawr_dog_harness` reports the
   entry shard's size. For Kimi it printed `file_size = 43.12 GB` for a model
   whose set is 578.58 GB. Any bandwidth or capacity arithmetic keyed off that
   number is wrong by 13x. Must report summed shard bytes and shard count.
2. **Receipts carry no measurements.** Until per-model load time, TTFT, TPS,
   token ids and callback counts land in a receipt, no verdict is certifiable.
   Console output is not evidence.
3. **`stream_contiguous`** now scores callbacks == reported tokens. It must never
   return to "no repeated consecutive ids", which is satisfied by any model that
   legitimately repeats a token and so can only agree with itself.

---

## 5. Pre-registered falsification criteria

Fixed in advance. A result that violates one of these is not a result.

```text
F1  If measured read_MB == 0, NO claim about storage or direct I/O may be made.
    The disk was not involved. This is not a judgement call.

F2  Page-fault count x 4096 may NEVER be reported as bytes or I/O rate.
    PageFaultCount includes cache-served minor faults, COW, guard pages and
    instruction fetches. Run A would have reported ~590 MB of "NVMe traffic"
    at token 0 against a measured 0.00 MB. That column is retired.

F3  loadModel duration may NEVER be credited as I/O or as load completion.
    It is VMA construction. Proven: 966 ms for 43.12 GB with read_MB = 0.

F4  A DIRECT_IO_WINS verdict requires, on the same bytes and the same machine:
      - correctness unchanged (identical tokens vs the mmap path), AND
      - measured disk bytes reduced or wall-clock latency improved, AND
      - measured under a working set larger than RAM, AND
      - replicated across >= 3 model sizes.
    Any one missing -> verdict is INCONCLUSIVE, not WIN.

F5  A model may not be declared broken, and a harness may not be declared
    broken, from a run whose own controls did not pass. Every run reports
    callbacks vs engine-reported tokens; a mismatch is a harness defect until
    proven otherwise.

F6  One shared input may never produce N identical per-model verdicts and be
    read as N results. (The "Count:" tokenizer bug produced 182/182 identical
    MODEL_LOAD_FAILED from one defect.)
```

---

## 6. Confound register

Each of these already cost real time this session. They are pre-declared so a
future reader can discount a result that fell foul of one.

| confound | control |
|---|---|
| Q2_K is unusable as a control (degenerate repetition, invalid UTF-8) | use Q4_K_M or better for any capability claim |
| A second GGUF parser can disagree with the production one | one parser; header inspection must delegate to `GGUFLoader` |
| Metadata-only geometry invariants can be false (gated gemma3: `numHeads*headDim != hiddenDim` is legitimate GQA) | validate against real tensors, not metadata equality |
| Fused-layout models get silently computed wrong (`silu(up)` instead of `silu(gate)*up`) | proven split + order falsification probe before admitting |
| Shared harness input failing → N model-shaped failures | per-run input validation; report input provenance |
| Instruments that cannot disagree | every metric must have a defined falsifying value |
| Concurrent writers mutating files mid-experiment | snapshot before edit; verify hashes before/after a run |

---

## 7. Execution order

```text
GATE 0   decode status=4 for Kimi                     seconds     BLOCKING
E1       RAM-boundary sweep, 4 sizes                 ~1 hour
         -> converts "out-of-core untested" into a measured boundary
E3       build + run direct_io_probe_001             ~30 min
         -> first real A/B on identical bytes
E2       prefetch vs demand at the boundary          ~1 hour
E4       random-access MoE pattern                   ~2 hours
E5       >RAM model, if and only if GATE 0 passes    hours, disruptive

TRACKED IN PARALLEL (cheap, unblocked):
  - shard-set size mislabel fix
  - per-model numbers into the receipt
  - gemma3 GQA verification (fix is written, unverified — build was red)
```

The parallel items are cheap, do not contend for the same measurement, and each
converts a currently-false or missing verdict into a measured one. They should
not wait on E5.

---

## 8. What this architecture does not claim

```text
NOT CLAIMED  that direct I/O will win
NOT CLAIMED  that Kimi K2 streams today
NOT CLAIMED  that out-of-core works at all on this engine
NOT CLAIMED  that Deep2 has an MLA attention path
NOT MEASURED any >RAM working set
```

The honest current position: **in-RAM streaming is proven** (4 models, real
callbacks, measured zero disk I/O); **out-of-core is entirely unmeasured**; and
the one attempt at it was blocked before the first token by an undecoded status
code that Gate 0 will resolve in seconds.
