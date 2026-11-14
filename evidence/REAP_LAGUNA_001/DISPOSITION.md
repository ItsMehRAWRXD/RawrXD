# REAP_LAGUNA_001 — Disposition

## Verdict

`REAP_LAGUNA=PASS` on measured tip EXE `CEBA0DE4…` (live `rawr.exe`).

## What PASS means (this pack only)

Using existing REAP strata / board definitions — **not** a new enterprise cert ladder:

| Check | Result |
|-------|--------|
| HEADS geometry (`GGUF_DYNAMIC_GEOMETRY_001`) | PASS |
| `HEADS_LAYER` (per-layer from `wq.rows`) | PASS |
| `ATTN_GATE` BIND + APPLY | PASS |
| `LAYER_NAN` | 0 |
| `GENERATED_TOKENS` | 8 (>0) |
| Product tetrad (OPEN/ENTER/COMMIT) | all 1; `PRODUCT_PASS=1` |
| Strata Laguna GGUF runnable on tip | yes |

**Explicitly not claimed:** `COMPETITIVE_PASS`, TPS climb, `PROMOTE`, enterprise CERT / 0/128 lift.

## Root causes already closed (held)

1. **HEADS array geometry** — R99 / `BR_REAP_LAGUNA_HEADS_GEOMETRY_CLOSED_R99`
2. **BF16 MoE `bytesPerExpert` 2×** → historical `LAYER_NAN` L42 — R100 / peer `CDA4804C` (`MoEWeightsLoader` QuantTypeTable)
3. **attn_gate apply** — `LagunaAttnGateApply.hpp` softplus on tip (FAIR_H2H smoke6 already showed APPLY; tip remasure confirms)

## Tip remasure (this seal)

- EXE SHA256: `CEBA0DE4734A3897B96A825C5CE16685161DB8A3C570C22F6B06B3DE4368A3C5`
- Artifacts: `runs/laguna_tip.*`, `runs/result_summary.txt`
- STDOUT: eight `hi` tokens; `DECODE_TPS_REAL≈0.070`
- `CROSS_SHA_CREDIT=0` vs peer R100 (independent measure)

## Residuals → not REAP_LAGUNA reopen

- `PROVENANCE_MISMATCH` (discovery LOCATION) — RELATED
- `DEEP2_REAP_LAGUNA_TPS_OR_COMPETITIVE_H2H` — OPEN residual only
- Fair H2H N≥3 median — HOLD / `COMPETITIVE_PASS=0`

## Authority flags

```text
PROMOTE=0 CERTIFIED=0 GATE_STOP=1 TIP_CLIMB=HOLD
ENTERPRISE=0/128 INVENT_PASS=0 CROSS_SHA_CREDIT=0
Q6K_VULKAN_SPV_REPAIR=PASS HELD
NEXT_OWNER=ORNITH_PACKED_GEMV_L3_ULP|Move51+|MULTIFAMILY_EXPAND
NO_LIFT=8TPS_CLIMB|PROMOTE
```
