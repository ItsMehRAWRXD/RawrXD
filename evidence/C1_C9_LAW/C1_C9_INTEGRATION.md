# RawrXD C1 -> C9 source-drop integration

This drop does **not** claim these files already exist in the working tree. It is additive source for the next climb.

The recovered project artifacts prove:
- `K2LogitsClimb.cpp` is the current packed Q6_K logits climb.
- live output projection reaches `output.weight` as Q6_K.
- Elastic's `ExecuteNvmeToRam` still falls back to zero-fill when `sourceData==nullptr`.
- Elastic's `ExecuteRamToVram` still sets `gpuData=nullptr` while marking `Hot`.

Therefore C4/C5 are deliberately fail-closed until real backends are attached.

---

## C1 — K2_LOGITS_GPU_RANGE_ATTRIBUTION_001

At the already-resolved/finalized `PhysicalTensorRange[]` seam:

1. Normalize each resolved range into `VwaLineageRange`.
2. Fulfill those exact ranges.
3. Pass the fulfilled packed buffer to the existing live GPU logits path.
4. The GPU wrapper records the **same source ranges** supplied by the caller.
5. `K2ValidateLineage()` must PASS.

Do not let TryGpuHot:
- look up `output.weight` by name,
- recalculate GGUF offsets,
- recalculate quant geometry.

Minimum witnesses:

```text
GPU_DISPATCH=1
FULFILLED_RANGE_COUNT=N
GPU_SOURCE_RANGE_COUNT=N
FULFILLED_BYTES=...
GPU_SOURCE_RANGE_BYTES=...
FULFILLED_RANGE_HASH=...
GPU_SOURCE_RANGE_HASH=...
RANGE_SET_EQUAL=1
ARGMAX_PARITY=1
K2_LOGITS_GPU_RANGE_ATTRIBUTION_001=PASS
```

### Q6_K output row conversion

Use the mounted geometry. For K2 Q6_K, only if `cols % blockElements == 0`:

```cpp
K2RowBlockRequest req{
    firstRow,
    rowCount,
    cols,
    blockElements
};
K2BlockRangeOut br{};
if (K2RowsToBlockRangeX64_Fixed(&req, &br) != 0) fail();

// THEN call existing ResolveQuantBlockRange(desc,
//     {br.firstBlock, br.blockCount}, physicalRange)
```

`K2RowsToBlockRangeX64_Fixed` never creates a physical address.

---

## C2 — K2_LOGITS_RANGE_SWEEP_001

Five arms:
- 0% GPU
- 25%
- 50%
- 75%
- 100%

`K2BuildCutLadder(vocabRows, arms)` gives logical row counts.
Each nonzero GPU arm must:
- lower its rows to block coordinates,
- resolve with the existing VWA resolver,
- fulfill exact packed bytes,
- dispatch those exact rows,
- retain argmax parity,
- retain `HOT_ALLOC=0`,
- retain `SHARD_IO=0` after warm.

Populate per arm:

```text
CPU_US
GPU_US
JOIN_US
WALL_US
GPU_DISPATCH
LINEAGE_PASS
ARGMAX_PARITY
HOT_ALLOC_ZERO
SHARD_IO_ZERO
```

Then `K2ChooseCut()` selects the minimum **wall**, not the smallest GPU kernel.

---

## C3 — K2_LOGITS_RANGE_FREEZE_001

Freeze the C2 winner by the existing model/shape authority.

Do not A/B every token.

A frozen record minimally contains:

```text
TensorId
model/shard generation
cols
vocabRows
gpuRows
cpuRows
winnerWallUs
```

A generation/model mismatch invalidates the record.

PASS requires three repeated windows with:
- same winning split,
- parity=1,
- no hot alloc,
- post-warm shard I/O=0,
- no CPU rescue inside a claimed GPU range.

---

## C4 — VWA_ASYNC_FILE_RANGE_001

Replace the false Elastic cold-load behavior.

Recovered current behavior is effectively:

```cpp
if (t.sourceData)
    memcpy(...);
else
    memset(..., 0);   // not physical fulfillment
```

C4 must route an already-resolved range to the existing IOCP/file backend.

Use `VwaAsyncReadOps` as the stateless seam:
- `submit` = existing IOCP absolute-offset read submission
- `wait` = existing IOCP completion path

Required:

```text
BACKEND=FILE_IOCP
SOURCE_DATA_SHORTCUT=0
REQUEST_OFFSET=<resolved absolute offset>
REQUEST_BYTES=<resolved bytes>
COMPLETED_BYTES=REQUEST_BYTES
BYTE_PARITY=1
VWA_ASYNC_FILE_RANGE_001=PASS
```

### Elastic patch law

`ExecuteNvmeToRam` may decide lifecycle and destination allocation, but it must receive the already-resolved physical range from the registered tensor/RMV lineage. It must not create a second range resolver.

On failed/short read:
- free reservation,
- transition to `Failed` or `Cold` according to existing state law,
- never transition to `WarmCompressed`.

Zero-fill is forbidden.

---

## C5 — VWA_GPU_TRANSFER_001

Recovered Elastic code currently reserves `Hot`, leaves `gpuData=nullptr`, and marks `Hot`.
That must be removed.

Bind `VwaGpuTransferOps` to the existing Vulkan transfer path:
- allocate/create real device object,
- submit transfer,
- wait/fence completion,
- only then publish `gpuData` and `Hot`.

A host memcpy cannot return C5 success.

Required:

```text
GPU_UPLOAD_SUBMITS>0
GPU_UPLOAD_COMPLETIONS==GPU_UPLOAD_SUBMITS
GPU_DEVICE_OBJECT_NON_NULL=1
GPU_TRANSFER_BYTES==FULFILLED_BYTES
HOT_WITH_NULL_GPU=0
VWA_GPU_TRANSFER_001=PASS
```

On transfer failure:
- release reserved hot bytes,
- do not publish Hot.

---

## C6 — VWA_K2_EXPERT_SELECTIVE_001

Do not synthesize per-expert tensor names.

Existing K2 expert indexing supplies:
- canonical stacked TensorId,
- `expertRelativeOffset`,
- `expertBytes` / stride.

Call:

```cpp
K2ExpertSlicePlan p{};
auto s = K2PlanExpertSlice(
    expertRelativeOffset,
    expertBytes,
    blockBytes,
    &p);
if (s != K2C_OK) fail();
```

Then feed `{p.firstBlock, p.blockCount}` into existing `ResolveQuantBlockRange`.

Required:

```text
STACKED_TENSOR_ID_STABLE=1
SYNTHETIC_EXPERT_MOUNT=0
SELECTED_EXPERTS=<router top-k>
UNSELECTED_EXPERT_READ_BYTES=0
GATE_RANGE_PARITY=1
UP_RANGE_PARITY=1
DOWN_RANGE_PARITY=1
VWA_K2_EXPERT_SELECTIVE_001=PASS
```

---

## C7 — VWA_K2_PREFETCH_OVERLAP_001

Pipeline:

```text
compute current expert/layer
        ||
IOCP read next resolved ranges
        ||
GPU transfer once next read completes
```

Measure real timestamps.

Use:

```cpp
K2OverlapWitness w{};
K2ComputeOverlap(readUs, computeUs, overlappedWallUs, &w);
```

PASS is **not** `PREFETCH=1`.

PASS requires:

```text
OVERLAPPED_WALL_US < READ_US + COMPUTE_US
HIDDEN_US>0
BYTE_PARITY=1
ARGMAX_PARITY=1
```

Also report stall:

```text
STALL_US = overlappedWall - max(read, compute), clamped at 0
```

---

## C8 — VWA_BOUNDED_K2_001

Elastic/Residency is still the only lifecycle/eviction authority.

Declare before the run:

```text
RAM_BUDGET
VRAM_BUDGET
OUTSTANDING_IO_BUDGET
```

Record actual peaks and validate via `K2ValidateBounded()`.

Required:

```text
RAM_PEAK<=RAM_BUDGET
VRAM_PEAK<=VRAM_BUDGET
OUTSTANDING_IO_PEAK<=OUTSTANDING_IO_BUDGET
SECOND_RESIDENCY_FSM=0
ARGMAX_PARITY=1
K2_TOKENS_REAL>0
VWA_BOUNDED_K2_001=PASS
```

Do not treat a synthetic memory backend as C8.

---

## C9 — VWA_K2_FULL_E2E_001

C9 is a closure gate, not another implementation.

Populate `K2C9Witness` only from the sealed evidence of C1..C8.

Required final state:

```text
C1_LINEAGE=1
C2_CUT_SWEEP=1
C3_FREEZE=1
C4_REAL_ASYNC_READ=1
C5_REAL_GPU_TRANSFER=1
C6_EXPERT_SELECTIVE=1
C7_OVERLAP=1
C8_BOUNDED=1

ARGMAX_PARITY=1
SECOND_MOUNT_API=0
NAME_RELOOKUP=0
SHARD_IO_AFTER_WARM=0
HOT_ALLOC=0
GPU_DISPATCH_SEEN=1
SOURCE_SHORTCUT=0

VWA_K2_FULL_E2E_001=PASS
```

`K2ValidateC9()` fails if any bit is absent.

---

# Exact live patch points recovered from artifacts

## `src/deep2/K2LogitsClimb.cpp`

This file is already the packed Q6_K logits owner. Do not replace the Q6×Q8_K/VNNI work.
Attach row-range execution above the existing packed dot implementation and retain its counters.

## live output projection

Recovered live logs show:

```text
RunTokenForward: output projection
Final Projection using tensor: output.weight (Q6_K, type=14)
ExecuteGEMV complete
```

The C1 GPU wrapper belongs at that existing projection dispatch seam.

## `src/deep2/ElasticResidencyManager.cpp`

Two mandatory unstubs:

### Cold -> RAM

Forbidden:

```cpp
if (!t.sourceData)
    memset(t.compressedData, 0, t.compressedBytes);
```

Required semantic replacement:

```cpp
PhysicalTensorRange r = alreadyRegisteredResolvedRangeFor(t);
// NO name relookup, NO second resolve here if range was already attached.

uint64_t completed = 0;
if (!VwaReadExactAsync(ioOps, Normalize(r),
                       t.compressedData,
                       t.compressedAllocated,
                       &completed)) {
    // release allocation/accounting
    // transition fail-closed
    return;
}
```

Use the real field/accessor names from the current `VirtualTensorRange.hpp`.
Do not invent a binary layout.

### RAM -> VRAM

Forbidden:

```cpp
t.gpuData = nullptr;
t.gpuBytes = uploadBytes;
t.state.store(ResidencyState::Hot);
```

Required semantic replacement:

```cpp
const void* src = config_.useQuantizedGpuPath
    ? t.compressedData
    : t.stagedData;

void* deviceObject = nullptr;
if (!VwaUploadExact(gpuOps, src, uploadBytes, &deviceObject)) {
    ReleaseHot(uploadBytes);
    t.state.store(srcState);
    t.inFlightOps.fetch_sub(1);
    return;
}

t.gpuData = deviceObject;
t.gpuBytes = uploadBytes;
t.state.store(ResidencyState::Hot);
```

The concrete Vulkan adapter must bind to the existing RawrXD GPU transfer primitive; do not add a second GPU allocator.

---

# Do not merge

Keep separate commits/evidence for:
- C1 provenance
- C2 measurement
- C3 policy freeze
- C4 storage unstub
- C5 GPU transfer unstub
- C6 expert slicing
- C7 overlap
- C8 budget proof
- C9 closure

No tokenizer/agent/UI/link-repair changes in this climb.
