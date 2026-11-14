# G02-06 RELATED — AA4F addrOk remasure (C9FB0B48)

ASOF_LOCAL=2026-11-13T22:43:00-05:00
PROMOTE=0 TIP_CLIMB=HOLD INVENT_PASS=0 CERT_RESULT=NOT_RUN CROSS_SHA_CREDIT=0

## Gate touch

- Near: G02 (infer/stream survivability), G03 (crash/SEH hygiene)
- RELATED ≠ PASS on CERT_001 checklist

## Runtime evidence

| Cand | EXE_SHA256 | TOK | SEH | EXIT | AV_CLOSED |
|------|------------|-----|-----|------|-----------|
| tip_land_avfix_aa4frem (HotPatcher addrOk + Deep2 CURRENT) | C9FB0B4846680E4B4B00A365E697DFC00492CF31B73328D706A99CB16DA668AE | 0 | OPEN=0 STREAM=0 | NULL | 0 |
| tip_land_avfix_aa4frem_isoA (addrOk + Deep2 bak_pre_m1m2) | 21234DAFD2C19F6A5115715737FE20A8F53FE8CE813F9B602F5AF8A39FABBAE1 | 0 | STREAM=1 CODE=0xC0000005 | 0 | 0 |

Witnesses:

- `GUI_TOP25_VALUATION_001/gpu/ide_mf_aa4frem_gemma3_C9FB0B4846680E4B_20261113_224109.meta.txt`
- `GUI_TOP25_VALUATION_001/gpu/ide_mf_aa4frem_isoA_gemma3_21234DAFD2C19F6A_20261113_224240.meta.txt`
- Seal: `GUI_TOP25_VALUATION_001/gpu/AA4F8530_ADDROK_REMEASURE_001.txt`
- Board: `board_receipts/BR_AA4F8530_ADDROK_REMEASURE_001.txt`

## Notes

- Tip `6754616E` RO / TIP_ABSORB=0.
- Primary: PRODUCT_OPEN tensors=340 then mid-VRAM hard truncate (~blk.23); HotPatcher addrOk land alone does not close AA4F-class AV.
- isoA isolates Deep2Engine CURRENT as the mid-VRAM hard-AV delta vs bak; stream path still SEH-AV.
- Control pin `7FD1F270` retained (prior TOK=8 SEH=0); not credited to tip.
