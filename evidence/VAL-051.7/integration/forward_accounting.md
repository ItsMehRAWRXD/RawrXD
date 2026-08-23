# VAL-051.7 — Gate 13: Forward Accounting

## Document Identity
- **Gate:** 13
- **Version:** 1.0
- **Date:** 2026-08-22

---

## Forward Lifecycle

```cpp
void Deep2Engine::generate(...) {
    ResidencyCounters::Reset();
    
    for (size_t t = 0; t < maxOutputLen; ++t) {
        ResidencyCounters::BeginForward();
        ResidencyCounters::OnForwardTransition();
        
        for (size_t layer = 0; layer < numLayers; ++layer) {
            ResidencyCounters::BeginLayer();
            ResidencyCounters::OnLayerTransition();
            
            forwardLayer(layer, ...);
            
            ResidencyCounters::EndLayer();
        }
        
        ResidencyCounters::EndForward();
    }
    
    ResidencyCounters::Print();
}
```

---

## Automatic Invariants

| Invariant | Check |
|-----------|-------|
| `forwardCount == expectedForwards` | Exact match |
| `layerCount == forwardCount * numLayers` | Exact match |
| `activeLeaseCount == 0` after forward | No leaked leases |
| `staleLeaseCount == 0` | No stale access |
| `residencyErrors == 0` | No residency failures |
| `releases <= acquisitions` | No double releases |
| `currentResidentBytes <= maxResidentBytes + overhead` | Capacity respected |

---

## Counter Requirements

| Counter | Requirement |
|---------|-------------|
| `forwardCount` | Exact |
| `layerCount` | `forwards × layers` |
| `acquireCount` | Deterministic per forward |
| `releaseCount` | Equals eligible releases |
| `remapCount` | Measured |
| `evictionCount` | Measured |
| `peakResidentBytes` | Bounded |

---

## Implementation

Already instrumented in `Deep2Engine.cpp`:
- `ResidencyCounters::BeginForward()` / `EndForward()` around layer loop
- `ResidencyCounters::BeginLayer()` / `EndLayer()` per layer
- `ResidencyCounters::Print()` after generation

Full accounting invariants to be enforced by certification harness (Gate 19).
