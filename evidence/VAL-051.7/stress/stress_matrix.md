# VAL-051.7 — Gate 18: Stress Matrix

## Document Identity
- **Gate:** 18
- **Version:** 1.0
- **Date:** 2026-08-22

---

## Automated Test Matrix

| Tokens | Prompt Length | Residency Budget | Sessions | Repeat |
|--------|---------------|------------------|----------|--------|
| 1 | short | minimum | 1 | 3× |
| 3 | short | minimum | 1 | 3× |
| 5 | short | minimum | 1 | 3× |
| 15 | short | minimum | 1 | 3× |
| 32 | short | moderate | 1 | 3× |
| 64 | short | moderate | 1 | 3× |
| 128 | short | large | 1 | 3× |
| 15 | long | minimum | 1 | 3× |
| 15 | short | minimum | 5 | 3× |
| 15 | short | forced pressure | 1 | 3× |

## Repeatability Requirements

For each case:
- Run ≥3 times
- Compare structural counters (exact match)
- Compare token sequence (exact match)
- Compare position sequence (exact match)
- Compare errors (exact match: 0)
- Compare teardown state (clean)

## Leak Detection

After each run:
- [ ] `mapCount == unmapCount`
- [ ] `activeLeaseCount == 0`
- [ ] `currentResidentBytes == 0`
- [ ] No file handle leaks
- [ ] No allocation leaks (if instrumentation available)

## Forced Residency Pressure

```
maxResidentBytes = 64MB  (deliberately small)
model = Codestral-22B (requires ~35GB resident)
Expected: heavy eviction/remap activity
Verify: no crashes, no stale access, correct tokens
```
