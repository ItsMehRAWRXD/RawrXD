# VAL-051.7 — Extra D: Quantization Correctness Boundary

## Document Identity
- **Extra:** D
- **Version:** 1.0
- **Date:** 2026-08-22

---

## Requirements

Because residency moves raw tensor bytes, quantization correctness must be preserved:

1. **Q4/Q5/Q6/etc. source bytes unchanged:** `memcmp(source, resident, tensorBytes) == 0`
2. **Dequantization receives identical bytes OFF vs ON:** Same dequant kernel input
3. **Block boundaries survive remapping:** No partial quantization block exposed
4. **Tensor alignment after remap:** Pointer aligned to block-size requirements

## Critical Rule

A residency bug can masquerade as a numerical/dequantization bug.
Therefore:
- Always validate source bytes on remap (if `validateOnRemap` enabled)
- Compare OFF vs ON dequantization output
- Verify block alignment after every remap

## Tests

- [ ] Q4_K tensor: source == resident after remap
- [ ] Q5_K tensor: source == resident after remap
- [ ] Q6_K tensor: source == resident after remap
- [ ] Block alignment: `residentPtr % blockSize == 0`
