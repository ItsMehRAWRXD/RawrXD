# VAL-051.7 Streamer Completion Program — Next 15 Systematic Gates

**Date:** 2026-08-22  
**Branch:** main  
**Commit:** 264d6a492  
**Status:** Baseline committed, B3 failure preserved as golden fixture

---

## Immediate Baseline — Finish What Is Already Underway

### Gate 1: Freeze the current B3 failure as a golden fixture
- [x] Preserve exact `test_val_051_3_multi_token` invocation
- [x] Record exit code, token count, position, hidden-state norm, attention norm, FFN norm
- [x] Preserve failing `pos=5` trace
- [ ] SHA-256 the executable and fixture output
- [ ] This becomes the **pre-residency baseline**

### Gate 2: Temporarily bypass only the B3 early-return
- [ ] Keep all B3 diagnostics active
- [ ] Do **not** delete or weaken the validation condition itself
- [ ] Replace termination with diagnostic continuation mode
- [ ] Mark build explicitly `B3_CONTINUE_FOR_RESIDENCY_BASELINE`
- [ ] After baseline capture, restore hard gate

### Gate 3: Capture ResidencyCounters without changing residency behavior
- [ ] `forwardCount`
- [ ] `layerCount`
- [ ] `remapCount`
- [ ] map/acquire count
- [ ] evict/release count
- [ ] bytes mapped
- [ ] bytes unmapped
- [ ] peak resident bytes
- [ ] active window
- [ ] layer transitions
- [ ] per-forward totals

### Gate 4: Establish deterministic baseline output
- [ ] Same model
- [ ] Same prompt
- [ ] Same token count
- [ ] Same sampler
- [ ] Same seed
- [ ] Same build configuration
- [ ] Run at least 3 times
- [ ] Require identical structural counters even if timing varies

---

## Next 15 Systematic Completion Gates

### Gate 5: Define the residency ownership contract
Every weight/tensor access needs an unambiguous owner:

```
GGUF file
   ↓
Tensor metadata
   ↓
Mapped window
   ↓
Resident tensor view
   ↓
Forward operation
   ↓
Release/eviction
```

Document exactly:
- who maps
- who owns the mapping
- who may retain a pointer
- when the pointer becomes invalid
- who releases it
- whether an operation may span remaps

**Acceptance:** no raw mapped pointer survives beyond its residency lease.

---

### Gate 6: Build the Tensor Residency Fixture
Create a tiny deterministic fixture independent of generation:

```
acquire tensor A
verify bytes
release A
acquire A again
verify bytes
```

Then:
```
A → B → C → A
```
with a deliberately small residency budget.

**Acceptance:** every reacquired tensor matches the original GGUF bytes exactly.

---

### Gate 7: Add explicit residency leases
Do not let `float*`, `uint8_t*`, or mapped tensor pointers implicitly represent ownership.

Use a logical concept equivalent to:

```cpp
ResidencyLease {
    tensor
    address
    mappedOffset
    mappedBytes
    generation
}
```

The generation/version is important because it allows stale-pointer detection.

**Acceptance:** stale lease detection fires deterministically instead of silently dereferencing invalid memory.

---

### Gate 8: Implement bounded-window mapping
Establish the actual streaming window:

```
GGUF
────────────────────────────────────────────
        [ resident window ]
────────────────────────────────────────────
```

The window must have:
- configurable size
- alignment
- offset
- length
- current generation
- resident-byte accounting

**Acceptance:** resident bytes never exceed configured capacity except for explicitly documented alignment overhead.

---

### Gate 9: Implement acquire → use → release
Make this the canonical forward-path primitive.

```
Acquire
  ↓
Validate
  ↓
Compute
  ↓
Release
```

No forward operation should independently call `mmap`, `MapViewOfFile`, or equivalent mapping primitives.

**Acceptance:** one centralized residency API owns all map/remap/release activity.

---

### Gate 10: Implement deterministic eviction
Start with the simplest policy: **LRU / oldest eligible tensor.**

Do not optimize policy yet.

Required states:
```
UNMAPPED
RESIDENT
IN_USE
EVICTABLE
EVICTED
```

An `IN_USE` tensor must never be evicted.

**Acceptance:** zero evictions occur while a tensor has an active lease.

---

### Gate 11: Add remap correctness validation
Force pathological remapping:

```
A
B
C
D
A
C
B
D
```

with a residency capacity deliberately smaller than the working set.

For every reacquisition:
```
source bytes == resident bytes
```

**Acceptance:** 100% byte-identical tensor reconstruction after arbitrary eviction/remap cycles.

---

### Gate 12: Integrate residency at the layer boundary
Only after tensor-level correctness is proven should the transformer use it.

Target:

```
BeginLayer(L)

    acquire Wq
    acquire Wk
    acquire Wv
    acquire Wo

    attention

    release attention weights

    acquire FFN weights
    FFN

    release FFN weights

EndLayer(L)
```

This is where the existing `BeginLayer/EndLayer` counter structure becomes valuable.

**Acceptance:** every layer has balanced acquisition/release accounting.

---

### Gate 13: Add forward-level residency accounting
For every generation step:

```
BeginForward(pos)

    layer 0
    layer 1
    ...
    layer N

EndForward(pos)
```

Capture:

| Counter | Requirement |
|---------|-------------|
| forwardCount | exact |
| layerCount | `forwards × layers` |
| acquireCount | deterministic |
| releaseCount | equals eligible releases |
| remapCount | measured |
| evictionCount | measured |
| peakResidentBytes | bounded |
| staleLeaseCount | 0 |
| residencyErrors | 0 |

**Acceptance:** accounting invariants pass automatically.

---

### Gate 14: Add autoregressive position invariants
The streamer now needs to prove:

```
position = 0
position = 1
position = 2
...
position = N-1
```

and that residency activity does **not** alter:
- KV-cache position
- RoPE position
- token position
- layer index
- cache sequence length

**Acceptance:** 15-token generation has exactly 15 monotonically increasing positions.

This connects directly to the already-established VAL-051.6 autoregressive milestone.

---

### Gate 15: Separate residency failures from inference failures
This is critical.

Every failure needs a classification:

```
[B3]
[RESIDENCY]
[TENSOR]
[KV]
[ATTENTION]
[FFN]
[TOKENIZER]
[SAMPLER]
[STREAMER]
```

For example:
```
[RESIDENCY_FAIL] stale lease tensor=...
```
must never be confused with:
```
[B3_FAIL] hidden state invalid...
```

**Acceptance:** a failing inference numerical invariant cannot be reported as a residency failure unless residency instrumentation proves causality.

---

### Gate 16: Restore the B3 hard gate
Once the counters are captured, remove the continuation-only behavior.

Run the original hard gate again.

This creates the essential A/B pair:

```
BASELINE_CONTINUE
        ↓
Residency implementation
        ↓
B3_HARD_GATE
```

**Acceptance:** no production validation executable retains the temporary bypass.

---

### Gate 17: Create the residency A/B matrix
Run identical workloads:

#### A — residency disabled
```
mapping = baseline
residency = OFF
```

#### B — residency enabled
```
mapping = bounded
residency = ON
```

Measure:
- correctness
- token count
- hidden-state finiteness
- logits finiteness
- latency
- map count
- remap count
- peak mapped memory
- bytes read
- eviction count

Do **not** declare a performance win merely because mapped memory decreases.

**Acceptance:** ON and OFF produce equivalent numerical behavior within the defined tolerance.

---

### Gate 18: Stress the streamer beyond the 15-token gate
After the 15-token test:

```
1 token
3 tokens
5 tokens
15 tokens
32 tokens
64 tokens
128 tokens
```

Then repeated sessions:
```
prompt → generate → reset → prompt → generate
```

Then:
```
long prompt → decode
```

Then forced residency pressure.

**Acceptance:** no counter drift, stale leases, mapping leaks, or position corruption across repeated runs.

---

### Gate 19: Build the final streamer certification harness
At this point `test_val_051_3_multi_token` should stop being merely a debugging executable.

Turn it into a complete certification gate:

```
VAL-051.7
 ├── Fixture integrity
 ├── GGUF tensor integrity
 ├── Residency acquire
 ├── Residency release
 ├── Remap correctness
 ├── Eviction correctness
 ├── Layer accounting
 ├── Forward accounting
 ├── KV position
 ├── 15-token autoregression
 ├── hidden-state finiteness
 ├── logits finiteness
 ├── tokenizer correctness
 ├── sampler correctness
 ├── output-token validity
 └── teardown/leak integrity
```

---

## Final Architecture

```
                    GGUF
                     │
              ┌──────▼──────┐
              │ GGUF Index  │
              └──────┬──────┘
                     │
              Tensor Metadata
                     │
              ┌──────▼──────┐
              │  Residency  │
              │   Manager   │
              └──────┬──────┘
                     │
           ┌─────────▼─────────┐
           │ Residency Lease   │
           └─────────┬─────────┘
                     │
             ┌───────▼───────┐
             │ Transformer   │
             │     Layer     │
             └───────┬───────┘
                     │
          ┌──────────┼──────────┐
          ▼          ▼          ▼
       Attention    FFN       KV Cache
          │          │          │
          └──────────┼──────────┘
                     ▼
                 Hidden State
                     │
                   Logits
                     │
                 Sampler
                     │
                   Token
                     │
              next position
                     │
                     └──────────────►
```

---

## Critical Ordering

**Do not jump directly into optimizing residency.**

The correct sequence is:

```
B3 failure fixture
      ↓
baseline counters
      ↓
tensor residency correctness
      ↓
lease correctness
      ↓
bounded mapping
      ↓
eviction/remap correctness
      ↓
layer integration
      ↓
forward integration
      ↓
autoregressive integration
      ↓
A/B equivalence
      ↓
stress
      ↓
performance
      ↓
CERTIFICATION
```

The **3.9e20 attention explosion remains a separate defect**. It should be preserved as a golden numerical failure until its root cause is fixed; residency work must not silently make that evidence disappear.

---

## End State Definition

The end state for the streamer is therefore not merely **"it generates 15 tokens."** It is:

> **Every tensor access has deterministic residency ownership, every mapping/remap is observable, every lease is valid, every layer is balanced, every forward is accounted for, KV positions remain correct, and the residency-enabled streamer is numerically equivalent to the frozen baseline.**

That gives VAL-051.7 a clean certification boundary and leaves the attention/FFN numerical defect independently actionable rather than entangled with the residency implementation.
