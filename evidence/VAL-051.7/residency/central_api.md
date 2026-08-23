# VAL-051.7 — Gate 9: Canonical Acquire/Use/Release API

## Document Identity
- **Gate:** 9
- **Version:** 1.0
- **Date:** 2026-08-22

---

## Central API

All tensor access flows through `ResidencyManager`:

```cpp
// 1. Register tensor metadata (once at load time)
manager.RegisterTensor("blk.0.wq", fileOffset, tensorBytes, sourceData);

// 2. Acquire lease before use
void* data = nullptr;
size_t bytes = 0;
uint64_t generation = 0;
if (manager.AcquireTensor("blk.0.wq", data, bytes, generation)) {
    // 3. Use tensor
    LinearW(data, input, output, ...);
    
    // 4. Validate if crossing boundaries
    if (manager.ValidateLease("blk.0.wq", generation)) {
        // Safe to continue using
    }
    
    // 5. Release after use
    manager.ReleaseTensor("blk.0.wq");
}
```

---

## Prohibited Patterns

Forward code must NOT:
- Call `mmap`, `MapViewOfFile`, or equivalent directly
- Store raw tensor pointers beyond a single layer/forward
- Assume tensor data remains valid after `ReleaseTensor()`
- Access `WeightTensor::data` without acquiring a lease

---

## Layer Lifecycle Integration

```cpp
void Deep2Engine::forwardLayer(size_t layer, ...) {
    // Acquire attention weights
    manager.AcquireTensor("blk.N.wq", wqData, ...);
    manager.AcquireTensor("blk.N.wk", wkData, ...);
    manager.AcquireTensor("blk.N.wv", wvData, ...);
    manager.AcquireTensor("blk.N.wo", woData, ...);
    
    computeAttention(...);
    
    // Release attention weights
    manager.ReleaseTensor("blk.N.wq");
    manager.ReleaseTensor("blk.N.wk");
    manager.ReleaseTensor("blk.N.wv");
    manager.ReleaseTensor("blk.N.wo");
    
    // Acquire FFN weights
    manager.AcquireTensor("blk.N.wGate", gateData, ...);
    manager.AcquireTensor("blk.N.wUp", upData, ...);
    manager.AcquireTensor("blk.N.wDown", downData, ...);
    
    computeFFN(...);
    
    // Release FFN weights
    manager.ReleaseTensor("blk.N.wGate");
    manager.ReleaseTensor("blk.N.wUp");
    manager.ReleaseTensor("blk.N.wDown");
}
```

---

## Error Paths

Every acquire/use/release operation must handle errors:

| Error | Behavior |
|-------|----------|
| Acquire fails | Skip layer, emit `RESIDENCY_FAIL`, increment `tensorAcquireFailures` |
| Use with stale lease | Abort operation, emit `RESIDENCY_FAIL`, increment `staleLeaseCount` |
| Release fails | Log error, increment `releaseErrors` |
| Exception during use | Catch, release all leases in scope, rethrow |

---

## Audit Checklist

- [ ] No `mmap` in `Deep2Engine.cpp` except through `ResidencyManager`
- [ ] No `MapViewOfFile` in transformer code
- [ ] No raw `WeightTensor::data` access in `forwardLayer`
- [ ] Every `AcquireTensor` has matching `ReleaseTensor`
- [ ] `activeLeaseCount == 0` after `EndForward()`
