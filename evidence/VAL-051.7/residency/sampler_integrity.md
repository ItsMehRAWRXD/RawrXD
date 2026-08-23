# VAL-051.7 — Extra F: Sampler Integrity

## Document Identity
- **Extra:** F
- **Version:** 1.0
- **Date:** 2026-08-22

---

## Requirements

1. **Seed fixed:** Same seed → same token sequence.
2. **RNG state defined:** Sampler maintains deterministic state.
3. **Same logits → same token:** Deterministic sampling.
4. **Same token sequence OFF/ON:** Residency must not affect sampling.
5. **EOS behavior identical:** Termination conditions unchanged.
6. **Invalid token ID rejected:** Out-of-vocab IDs discarded.
7. **Vocabulary bounds checked:** No buffer overruns.

## Tests

- [ ] Fixed seed produces identical tokens across runs
- [ ] OFF vs ON produce identical tokens with same seed
- [ ] EOS token terminates correctly
- [ ] Invalid token ID rejected
