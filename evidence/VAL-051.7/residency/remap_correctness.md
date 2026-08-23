# VAL-051.7 — Gate 11: Remap Correctness Validation

## Document Identity
- **Gate:** 11
- **Version:** 1.0
- **Date:** 2026-08-22

---

## Forced Remap Sequence

Test with deliberately small residency capacity to force eviction/remap cycles:

```
Working set: A (1024), B (2048), C (512), D (4096)
Capacity: 3000 bytes (less than A+B+C+D = 7680)

Sequence: A → B → C → D → A → C → B → D
```

For every reacquisition:
```
source bytes == resident bytes  (memcmp)
```

---

## Validation Requirements

1. **Byte-identical reconstruction:** Every remapped tensor matches original GGUF bytes.
2. **Generation increment:** Generation increases on every eviction/remap.
3. **Lease invalidation:** Old leases fail validation after remap.
4. **Counter correctness:** `remapCount` and `remapBytes` match actual activity.

---

## Stress Test: 1000+ Cycles

```
Deterministic seed → random access sequence
Repeat: acquire, validate, release
Force eviction every N operations
Verify no stale access, no byte corruption
```

---

## Implementation

See `test_val_051_7_tensor_residency.cpp` (Gate 6) for basic remap tests.
Full 1000-cycle stress test to be added in Gate 18 stress matrix.
