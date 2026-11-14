# G02-06 RELATED — AA4F addrOk Deep2 bisect STREAM_SEH (F0117A8D)

ASOF_LOCAL=2026-11-13T22:56:00-05:00
PROMOTE=0 TIP_CLIMB=HOLD INVENT_PASS=0 CERT_RESULT=NOT_RUN CROSS_SHA_CREDIT=0

## Gate touch

- Near: G02 (infer/stream survivability), G03 (crash/SEH hygiene)
- RELATED ≠ PASS on CERT_001 checklist

## Bisect result

| Role | EXE_SHA256 | TOK | SEH | AV_CLOSED | ROOT |
|------|------------|-----|-----|-----------|------|
| Prior primary CURRENT+addrOk | C9FB0B4846680E4B4B00A365E697DFC00492CF31B73328D706A99CB16DA668AE | 0 | mid-VRAM hard (no EmitSeh) | 0 | Deep2 CURRENT mid-VRAM |
| isoA bak+addrOk | 21234DAFD2C19F6A5115715737FE20A8F53FE8CE813F9B602F5AF8A39FABBAE1 | 0 | STREAM 0xC0000005 | 0 | exposes stream path |
| isoB embd+addrOk (this receipt pin) | F0117A8DB143A1B8C98F76FFB3E12D3A48B2D897213636033C2D97EA702F77FB | 0 | STREAM 0xC0000005 | 0 | EMBD_RES=1; still fclose leaf |
| Control 7FD1 OPEN_SKIP | 7FD1F27095388585D03DFB68C70E033B126D6406E8DE23C4F21F10D1EF8323C6 | 8 | 0 | n/a (CROSS_SHA=0) | tip-bind wire authority |

## STREAM_SEH attribution

- `ROOT_OBJ=libucrt:fclose.obj` (leaf; READ VA=FFFFFFFFFFFFFFFF)
- Map: isoA/isoB RIP in `_fclose_internal` / `_fclose_nolock_internal`
- Wrapper: `product_deep2_infer_seh.cpp.obj` / `product_deep2_infer.cpp.obj`
- `GpuForward` not in CURRENT↔bak delta (same obj075 in both rsps)
- Not closed by: embd-resident Deep2, HotPatcher old↔addrOk, IE qdim077↔avfix079, bunnyhop=0

## Mid-VRAM attribution

- `ROOT_OBJ=Deep2Engine.cpp.obj` CURRENT (`sha16=721011F6`) vs bak (`sha16=5B9021D7`)
- CURRENT string delta includes `RAWRXD_KV_FP16_ROUNDTRIP` / `kvCacheFp16RoundTripWanted`

## Notes

- Tip `6754616E` RO / TIP_ABSORB=0
- AV_CLOSED=0 — do not invent PASS
- Seal: `GUI_TOP25_VALUATION_001/gpu/AA4F8530_ADDROK_BISECT_STREAM_SEH_001.txt`
