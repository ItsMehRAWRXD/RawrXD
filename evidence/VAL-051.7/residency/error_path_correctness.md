# VAL-051.7 — Extra B: Error-Path Correctness

## Document Identity
- **Extra:** B
- **Version:** 1.0
- **Date:** 2026-08-22

---

## Required Error Paths

For every acquire/use/release operation, these errors must produce balanced state:

| Error | Balanced State | No Leaked Lease | Correct Counters |
|-------|---------------|-----------------|------------------|
| Mapping failure | ✓ | ✓ | ✓ |
| Validation failure | ✓ | ✓ | ✓ |
| Tensor metadata failure | ✓ | ✓ | ✓ |
| Compute failure | ✓ | ✓ | ✓ |
| Early return | ✓ | ✓ | ✓ |
| B3 failure | ✓ | ✓ | ✓ |
| Exception/error | ✓ | ✓ | ✓ |
| Cancellation/abort | ✓ | ✓ | ✓ |
| Forward termination | ✓ | ✓ | ✓ |

## Implementation

Use RAII `ScopedResidencyLease` or `try/finally` pattern:

```cpp
ResidencyLease lease;
if (lease.Acquire(manager, "tensor", bytes)) {
    ScopedResidencyLease guard(lease);
    // Use lease...
    // Automatically released on scope exit
}
```
