# VAL-051.7 — Gate 10: Deterministic Eviction

## Document Identity
- **Gate:** 10
- **Version:** 1.0
- **Date:** 2026-08-22

---

## State Machine

```
UNMAPPED ──RegisterTensor()──► (metadata only)

RESIDENT ──AcquireTensor()──► IN_USE ──ReleaseTensor()──► EVICTABLE ──Evict()──► EVICTED
    ▲                                                              │
    └────────────────────────Reacquire()───────────────────────────┘
```

---

## Eviction Policy: LRU (Oldest Eligible)

1. Only `EVICTABLE` tensors may be evicted.
2. `IN_USE` tensors are pinned (leaseCount > 0).
3. Eviction selects the tensor with the smallest `lastUseSequence`.
4. On eviction: generation increments, state becomes `EVICTED`.

---

## Invariants

1. **Zero evictions with active lease:** `IN_USE` tensors are never evicted.
2. **Balanced accounting:** `currentResidentBytes` decreases by `mappedBytes` on eviction.
3. **Generation increment:** Every eviction increments the tensor's generation.
4. **Stale lease detection:** Any lease with old generation fails validation.

---

## Negative Tests

| Test | Expected |
|------|----------|
| Evict active tensor | False, warning emitted |
| Release after eviction | False, `releaseErrors++` |
| Access after eviction | Stale lease detected |
| Multiple active leases | Eviction blocked until all released |

---

## Implementation

See `ResidencyManager::EvictToMakeRoom()` and `ResidencyManager::EvictTensor()`:
- Builds LRU candidate list from `EVICTABLE` tensors
- Sorts by `lastUseSequence`
- Evicts oldest until capacity constraint satisfied
