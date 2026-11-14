# G02-06 RELATED — AA4F Deep2 bisect R69 (B8E5F6E5)

ASOF_LOCAL=2026-11-13T23:15:00-05:00
PROMOTE=0 TIP_CLIMB=HOLD INVENT_PASS=0 CERT_RESULT=NOT_RUN CROSS_SHA_CREDIT=0
WORKER=c0810162 follow-on P0
TIP_RO=6754616EA30A566423727F82513AC66D8241FDB73343F9CD7A440FF9D4E43431 UNTOUCHED=1

## Gate touch

- Near: G02 (infer/stream survivability), G03 (crash/SEH hygiene)
- RELATED ≠ PASS on CERT_001 checklist

## Cand

| Field | Value |
|-------|-------|
| EXE | `clean_link/RawrXD-Win32IDE_tip_land_aa4f_r69.exe` |
| EXE_SHA256 | B8E5F6E57F73759361FAF283CE227BCEF5AF37488785E83F005D4C9D094DCB49 |
| SHA16 | B8E5F6E57F737593 |
| Remeasure | `gpu/ide_mf_aa4f_r69_gemma3_B8E5F6E57F737593_20261113_231333` |

## Runtime (gemma3-1b-Q2_K, FORCE=0)

| Metric | Value |
|--------|-------|
| PRODUCT_OPEN_PASS | 1 |
| GENERATE_STREAM_ENTER | 1 |
| MID_VRAM_HARD | 0 |
| INFER_STREAM_SEH | 0 |
| PRODUCT_DEEP2_OPEN_SEH | 0 |
| GENERATED_TOKENS | 0 |
| PROCESS_EXIT | NULL |
| AV_CLOSED | 0 |
| SEH | 0 |

Control 7FD1 TOK=8 SEH=0 remains CROSS_SHA=0 authority (not blended).

## ROOT_FIX

1. **Mid-VRAM / fclose VA=-1 owner (CURRENT vs bak):** tip-land `ProductRuntime` bakes `sizeof(Deep2Engine)==0x2868` with `ext@+0x2868`. CURRENT Eng tail quality fields (+0x10) overlapped `ext`/`modelAlias` → mid-open poison and `fclose` of string bytes as `FILE*` (`libucrt:fclose.obj` READ VA=-1).
2. **Fix:** move quality counters + `FILE*` ownership into `D2GenQualityProbe` / process-local `D2GenQualitySlotFor` (no Eng-tail members). Poison `fclose` guard retained. `alreadyClosed` destructor fast-exit + HotPatcher UEF opt-in already on branch.
3. **GpuForward:** not in delta (unchanged).

## Disposition

- Mid-VRAM hard truncate: cleared on this cand (OPEN+STREAM_ENTER).
- STREAM_SEH fclose leaf: cleared (SEH=0).
- Residual: TOK=0, EXIT=NULL during decode after FINAL_NORM (no EmitSeh) — AV_CLOSED=0, do not invent PASS.
- NEXT: decode-path EXIT=NULL owner for TOK>0; PROMOTE=0 TIP_CLIMB=HOLD

Seal: `GUI_TOP25_VALUATION_001/gpu/AA4F_R69_DEEP2_BISECT_001.txt`
Board: `board_receipts/BR_AA4F_DEEP2_BISECT_R69.txt` (append)
END
