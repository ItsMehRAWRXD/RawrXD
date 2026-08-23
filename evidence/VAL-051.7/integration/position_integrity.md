# VAL-051.7 — Gate 14: Autoregressive Position Invariants

## Document Identity
- **Gate:** 14
- **Version:** 1.0
- **Date:** 2026-08-22

---

## Position Requirements

For every generation step:

```
position = 0
position = 1
position = 2
...
position = N-1
```

### Invariants

1. **Position starts at expected value** (prompt length).
2. **Position increments exactly once per token.**
3. **Position never skips.**
4. **Position never repeats.**
5. **Position never regresses.**

---

## Residency Independence

Residency activity must NOT alter:
- KV-cache position
- RoPE position
- Token position
- Layer index
- Cache sequence length

---

## 15-Token Proof

| Metric | Expected |
|--------|----------|
| Forward events | 15 |
| Position events | 15 |
| Position sequence | monotonic increasing |
| Output tokens | 15 valid tokens |
| No residency-induced position mutation | confirmed |

---

## Implementation

Already tracked in `generate()` via `currentPos` variable.
Position trace to be captured in baseline snapshot (`positions` vector).
