# RawrXD VWA B3-B8 no-fiction drop

This bundle replaces the earlier broad C1-C9 helper idea with the narrower
sealed VWA boundary from the pasted state:

```text
RMV mounted tensor
    -> VWA quant-block range math
    -> exact physical range
    -> existing I/O transport
    -> Elastic lifecycle
    -> existing compute
```

## What this bundle adds

| File | Role |
|---|---|
| `VwaRangeAbi.hpp` | fixed POD ABI for MASM; not `VirtualTensorDesc` |
| `VwaRangeX64.asm` | pure block resolver + exact sync `ReadFile` fulfillment |
| `VwaRangePopulate.hpp` | populate ABI from audited RMV facts |
| `VirtualTensorRangePlanner.hpp` | no-allocation exact-adjacency coalescer |
| `VwaExpertSlice.hpp` | expert slice -> block range; no synthetic names |
| `VwaIocpRange.*` | transport-only exact overlapped read using existing handle |
| `VwaBudget.hpp` | witness validation only; no allocator |
| `ElasticResidencyManager.vwa_range.patch` | required tree-specific unstub law |
| `deep2_vwa_core_poc_001.cpp` | synthetic lower cert for resolver/fulfill/coalesce/slice |

## What this bundle does not add

```text
RequestBlocks
AcquireBlocks
VwaManager
VwaMount
VirtualWeightLoader
second residency FSM
second GGUF parser
fabricated VirtualTensorDesc binary layout
fake GPU DMA
```

## Gate mapping

| Gate | Source |
|---|---|
| B3 `VWA_IOCP_RANGE_001` | `VwaIocpRange.*` + existing shard handle |
| B4 `VWA_ELASTIC_RANGE_001` | apply patch law to `ExecuteNvmeToRam` |
| B5 `VWA_EXPERT_SLICE_001` | `VwaExpertSlice.hpp` + existing `ExpertByteOffset` |
| B6 `VWA_MOE_PREFETCH_001` | normalized expert demand -> existing prefetch |
| B7 `VWA_GPU_STAGE_001` | tree's existing Vulkan transfer must replace null-Hot |
| B8 `VWA_BOUNDED_K2_001` | `VwaBudget.hpp` + live peak counters |

B7 is intentionally not faked. A host `memcpy` is not GPU DMA and must not certify
`VWA_GPU_STAGE_001`.
