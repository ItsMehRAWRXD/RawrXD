# VAL-051.7 — Residency Ownership Contract

## Document Identity
- **Gate:** 5
- **Version:** 1.0
- **Date:** 2026-08-22
- **Git HEAD:** fe8b0364fc0f2af4697d8407c0c8d2deb9ab1154

---

## 1. Ownership Chain

Every weight/tensor access follows this unambiguous ownership chain:

```
GGUF file (filesystem)
   ↓
GGUF Index (metadata, offsets, types)
   ↓
Tensor Metadata (name, dimensions, quantization type)
   ↓
Mapped Window (OS-level mmap / MapViewOfFile)
   ↓
Resident Tensor View (byte-aligned pointer + bounds)
   ↓
Residency Lease (acquired by forward operation)
   ↓
Forward Operation (GEMV, RMSNorm, etc.)
   ↓
Release / Eviction
```

---

## 2. Owner Definitions

| Entity | Owner | Responsibility |
|--------|-------|--------------|
| GGUF file | `GGUFLoader` | Open, close, validate checksum |
| GGUF Index | `GGUFLoader` | Parse header, tensor info, metadata |
| Tensor Metadata | `GGUFLoader` / `K2GlobalTensorIndex` | Validate offsets, sizes, types |
| Mapped Window | `ResidencyManager` | Create, move, unmap OS views |
| Resident Tensor View | `ResidencyManager` | Align, bound-check, expose pointer |
| Residency Lease | `Forward Operation` (caller) | Acquire before use, release after use |
| Forward Operation | `Deep2Engine::forwardLayer()` | Compute, never retain raw pointer |
| Release / Eviction | `ResidencyManager` | Unmap when lease count reaches zero |

---

## 3. Pointer Lifetime Rules

### 3.1 No raw mapped pointer survives its lease
A `float*`, `uint8_t*`, or any pointer obtained from a residency lease **becomes invalid** at `Release()` time. The forward operation must not store it, cache it, or return it.

### 3.2 No operation can trigger eviction of its own active tensor
While a lease is active (`IN_USE` state), the tensor is pinned. The eviction policy must skip `IN_USE` tensors.

### 3.3 No lease can be released twice
Double-release is a programming error. The manager must detect it and increment `releaseErrors`.

### 3.4 No tensor can be released by a non-owner
Only the entity that called `Acquire()` may call `Release()`. (Exception: scoped/RAII wrappers.)

---

## 4. Lease Lifecycle

```
UNMAPPED ──Acquire()──► RESIDENT ──Use()──► IN_USE ──Release()──► EVICTABLE
                                                              │
                                                              └──Evict()──► EVICTED ──Reacquire()──► RESIDENT
```

### State Definitions

| State | Meaning |
|-------|---------|
| `UNMAPPED` | Tensor not currently mapped into memory |
| `RESIDENT` | Tensor mapped, no active lease |
| `IN_USE` | Tensor mapped, at least one active lease |
| `EVICTABLE` | Tensor mapped, no leases, eligible for eviction |
| `EVICTED` | Tensor unmapped, generation incremented |

---

## 5. Generation Semantics

Every tensor has a **generation counter** that increments on every eviction/remap.

- Lease stores `(tensorId, generation)` at acquisition time.
- Validation checks `currentGeneration == leaseGeneration`.
- Mismatch → `staleLeaseCount++`, `residencyErrors++`, operation fails.

---

## 6. Alignment Behavior

- All mapped windows are aligned to the platform page boundary.
- Tensor offsets within the GGUF may not be page-aligned.
- The resident view pointer is adjusted to the tensor's actual start byte.
- The lease records both `mappedOffset` (page-aligned) and `tensorOffset` (actual).

---

## 7. Overlapping Window Behavior

- A single mapped window may contain multiple small tensors.
- Each tensor gets its own lease with independent generation.
- Eviction of one tensor in a shared window does not invalidate leases for co-resident tensors unless the entire window is unmapped.

---

## 8. Operation Spanning Remap

A forward operation **must not** span a remap. If a tensor needs to be remapped mid-operation:

1. Complete current operation.
2. Release all leases.
3. Allow eviction/remap.
4. Reacquire leases.
5. Resume next operation.

No operation may hold a lease across a remap boundary.

---

## 9. Error Behavior

| Error | Action | Counter |
|-------|--------|---------|
| Acquire on invalid tensor | Fail, return null lease | `tensorAcquireFailures++` |
| Use with stale lease | Fail, emit `RESIDENCY_FAIL` | `staleLeaseCount++`, `residencyErrors++` |
| Double release | Fail, emit `RESIDENCY_FAIL` | `releaseErrors++`, `tensorReleaseFailures++` |
| Evict with active lease | Skip, emit warning | (none — eviction prevented) |
| Map failure | Fail, emit `MAPPING_FAIL` | `mappingErrors++` |
| Unmap failure | Log, continue | `mappingErrors++` |

---

## 10. Teardown Behavior

On engine destruction:

1. Assert `activeLeaseCount == 0`.
2. Unmap all resident windows.
3. Assert `currentResidentBytes == 0`.
4. Assert `mapCount == unmapCount`.
5. Destroy `ResidencyManager`.

---

## Hard Invariants

1. **No raw mapped pointer survives its lease.**
2. **No operation can trigger eviction of its own active tensor.**
3. **No lease can be released twice.**
4. **No tensor can be released by a non-owner.**
5. **All mapping is centralized in `ResidencyManager`.**
6. **Forward code never calls `mmap`/`MapViewOfFile` directly.**
7. **Every acquisition has a matching release.**
8. **Active lease count is zero after `EndForward()`.**
9. **Resident bytes never exceed configured capacity + alignment overhead.**
10. **Stale lease detection fires deterministically, never silently dereferences.**

---

## Signatures

| Role | Name | Date |
|------|------|------|
| Author | VAL-051.7 Program | 2026-08-22 |
| Reviewer | (pending) | |
| Certifier | (pending) | |
