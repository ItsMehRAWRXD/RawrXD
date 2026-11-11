# G06 Q8_K oracle harness — implementation layout

```
F:\rawrxd\tools\
  k2_q6k_q8k_oracle.py          # independent Q6_K×Q8_K GEMV (shader-aligned)
  k2_g06_q8k_oracle_harness.py  # primary/secondary compare + receipts
  run_kimi_g06_q8k_oracle.ps1   # creates fresh evidence dir, runs harness

F:\rawrxd\evidence\KIMI_G06_Q8K_ORACLE_HARNESS_001_<stamp>\
  LAW.txt
  TYPE14_CONTRACT.json
  G06_HARNESS_RECEIPT.json
  oracle_q6k_q8k.txt
  oracle_fp32.txt
  OUT_DIR.txt
```

## Fail-closed rules

| Role | Metric | Band |
|------|--------|------|
| Primary | GPU vs Q6_K×Q8_K oracle | max_abs ≲ 1e-6 |
| Secondary | GPU vs FP32 scalar | telemetry only (~0.0109 expected) |

- `certified=false` · `PROMOTE=0` · `TIP_CLIMB=HOLD` · `CERTIFIED=0`
- Official 25-gate ledger: **not modified**
- Anchors pristine: `KIMI_LAYER39_FIRST_FAIL_001`, `KIMI_LAYER39_SINGLE_002`

## type==14 contract validation rules

From `src/deep2/shaders/deep2_qgemv.comp`:

1. `blocksPerRow = (cols + 255) / 256`; `rowBytes = blocksPerRow * 210` (contiguous).
2. Q6_K block = 210 bytes: `ql[128] | qh[64] | scales[16] | d:f16[2]` — **no inter/intra padding**.
3. Activation: per-256 Q8_K; `invScale = -127 / signedMaxAbs`; nearest-int via `MAGIC=12582912`; clamp `[-127,127]`.
4. Dot: `q8D * q8 * d * scale * (q-32)` with scale index `half*8 + group*2 + l//16`.
5. ArenaFFNAct (post_swiglu capture) → ArenaDown (gpu_down capture).
6. Capture columns must be multiple of 256 (Kimi expert I=2048 ✓).

## Boundary review (shader walk)

- **Unexpected padding:** no
- **Unexpected block-boundary shift:** no
