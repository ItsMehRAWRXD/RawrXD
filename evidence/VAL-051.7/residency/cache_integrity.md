# VAL-051.7 — Extra E: Cache Integrity

## Document Identity
- **Extra:** E
- **Version:** 1.0
- **Date:** 2026-08-22

---

## KV Cache Ownership

- KV cache memory is owned by `KVCache` class, not `ResidencyManager`.
- KV cache is explicitly excluded from eviction (separate allocation).
- KV cache position is independent of weight residency.

## Invariants

1. KV cache sequence length matches expected forward count.
2. KV cache reset fully clears/reinitializes required state.
3. Repeated sessions cannot inherit stale KV state.
4. KV cache memory is not corrupted by weight residency activity.

## Tests

- [ ] KV position correct after 15 tokens
- [ ] KV reset clears all positions
- [ ] Second session starts with fresh KV cache
