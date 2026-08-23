# VAL-051.7 — Gate 8: Bounded Window Mapping

## Document Identity
- **Gate:** 8
- **Version:** 1.0
- **Date:** 2026-08-22

---

## Window Structure

```
GGUF File
├─ Tensor A @ offset 0x1000, size 0x4000
├─ Tensor B @ offset 0x6000, size 0x2000
├─ Tensor C @ offset 0x9000, size 0x8000
└─ ...

Resident Window (maxResidentBytes = 0x8000)
├─ [Mapped Region 1] offset=0x1000, length=0x5000  ← A + partial B
└─ [Mapped Region 2] offset=0x9000, length=0x8000  ← C
```

---

## Configuration Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `maxResidentBytes` | 512 MB | Maximum total resident bytes |
| `pageAlignment` | 4096 | Platform page size |
| `mapGranularity` | 65536 | Minimum mapping unit |
| `oversizePolicy` | DedicatedWindow | Fail or dedicated window |

---

## Alignment Rules

1. **Mapped offset** is always page-aligned: `floor(tensorOffset / pageAlignment) * pageAlignment`
2. **Mapped bytes** is always page-rounded-up: `ceil(tensorBytes / pageAlignment) * pageAlignment`
3. **Granularity** may map more than the tensor requires (padding)
4. **Tensor data pointer** = `mappedBase + (tensorOffset - mappedOffset)`

---

## Oversize Tensor Policy

When a single tensor exceeds `maxResidentBytes`:

- **Fail:** Reject the tensor. Engine must handle failure.
- **DedicatedWindow:** Map in a dedicated window that exceeds the normal budget. This is tracked separately and does not participate in LRU eviction.

---

## Invariants

1. `currentResidentBytes <= maxResidentBytes` (except dedicated oversize)
2. Every mapped region is page-aligned
3. Every tensor pointer is within its mapped region bounds
4. No overlapping mapped regions for different tensors (unless explicitly coalesced)

---

## Implementation

See `ResidencyManager.hpp` / `ResidencyManager.cpp`:
- `AlignedSize()` — page-round-up
- `AlignedOffset()` — page-align down
- `MapTensor()` — allocate aligned memory (TODO: replace with mmap)
- `EvictToMakeRoom()` — LRU eviction respecting capacity
