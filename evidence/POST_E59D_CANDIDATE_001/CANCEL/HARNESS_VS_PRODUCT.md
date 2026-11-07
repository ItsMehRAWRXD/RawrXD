# HARNESS vs PRODUCT — ORIGINAL Cancel crash classification

ASOF_UTC=2026-11-03T12:36:00Z
GITHUB_COMMIT=70fe7cdaf7
CERT_EXE_SHA=3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F
PROMOTE=0
REBUILD=HELD
REBUILD_AUTHORIZED=0

## Classification (controlling)

```
CRASH_CLASSIFICATION=MIXED
HARNESS_SOLE=REFUTED
HARNESS_MULTI_NOTIFY_REQUIRED=0
PRODUCT_LEAN=1
PRODUCT_DEFECT=NOT_PROVEN
CRASH_ROOT_CAUSE=NOT_PROVEN
HANG_EQUIV_CRASH=NOT_EQUATED
```

**MIXED** = product path is crashable under single BM_CLICK Cancel submit (same fault signature), but rebuild-authorizing product callback remains unproven (no usable native stack), and Cancel still differs from minimal Request-A-only survivors (Clear + dual SetEdit + arm poll).

Not **HARNESS**: multi-notify amplifier alone is **not** required — single BM_CLICK Cancel still dies.
Not pure **PRODUCT** for rebuild: exact callback / stack still NOT_PROVEN.
Not **UNRESOLVED**: decisive same-SHA experiment closed the sole-harness hypothesis.

## Evidence matrix (same SHA 3B720981)

| Run | Click | Clear | SetEdit | Result |
|-----|-------|-------|---------|--------|
| Original Cancel (sealed) | Triple BM_CLICK+WM_COMMAND+Post | yes | dual | **CRASH** `0xC000041D` ~3s; comctl32 RVA **0xBD02**; dump `070906.dmp` |
| Cancel retest 2026-11-03T12:34Z | **Single BM_CLICK only** | yes | dual | **CRASH** exit `-1073740771` (~0.5s); last_crash address **0x7ffc7be7bd02** (same); dump `073409.dmp` |
| hang HANG_SINGLE / HANG_TRIPLE / BLOCK_TRIPLE | single or triple | no | timed/dual | **NO_CRASH** 20–30s; REQUEST_A_SUBMITTED=1 |
| Prior REPRO2 hang | triple attempt | ? | ? | hang INCONCLUSIVE; **NOT_EQUATED** to crash |

## Fault signature (single-BM Cancel = original)

```
EXIT=-1073740771 (0xC000041D)
UNDERLYING=0xC0000005 @ 0x7ffc7be7bd02
MODULE=comctl32.dll RVA 0xBD02
DUMP_SINGLE_BM=CANCEL\logs\rawrxd-20261103-073409.dmp
SHA256_DUMP=4565F36B9AF63C41D20862908577D7B14C5E4E1C96AC93530BDA1B7E48D2C51E
LAST_CRASH=CANCEL\logs\last_crash_single_bm_073409.txt
CLICK_MODE=SINGLE_BM_CLICK
GITHUB_COMMIT=70fe7cdaf7
```

## Harness disposition

- Active Cancel harness ClickChild → **single BM_CLICK** (amplifier removed).
- Triple harness preserved: `harness_cancel_a_stop_b_TRIPLE.ps1`
- Original FAIL receipt preserved: `RECEIPT_ORIGINAL_TRIPLE_FAIL.md` (if present) + sealed dump `070906.dmp`
- Harness fix did **NOT** enable Cancel PASS → do **not** seal Cancel PASS; do **not** rebuild from amplifier theory.

## Rebuild gate

```
REBUILD=HELD
REBUILD_AUTHORIZED=0
PRODUCT_DEFECT=NOT_PROVEN
```

Authorize rebuild only after usable stack / proven product callback (or independent Clear/SetEdit elimination still crash on single user-like click). ChatWindow source modify/rebuild = **blocked**.

## Hang seal

`SETEDIT_CLICK_HANG.md` SEALED=1 · HANG_EQUIV_CRASH=NOT_EQUATED · controlled NO_HANG_NO_CRASH.

## STACK (CANCEL_NATIVE_STACK_RESIDUAL_001)

```
NATIVE_STACK=PARTIAL
SAME_PATH=YES
PRODUCT_FRAMES_ON_FAULTING_THREAD_STACK=YES
CONCRETE_CALLBACK=NOT_PROVEN
PRODUCT_DEFECT=NOT_PROVEN
CDB_WINDBG=NOT_INSTALLED
```

Both `073409.dmp` and `070906.dmp`: exception CONTEXT RIP=`comctl32+0xBD02`, write AV via RCX, shared near-RSP comctl32/user32 chain, shared product RVAs (`+0x12FB9C`, `+0x583420`, …) on faulting thread stack scan. Authority: `CANCEL\CANCEL_NATIVE_STACK_RESIDUAL_001.md`. Scan ≠ cdb unwind; rebuild still HELD.

## Next

1. cdb true unwind / PDB symbolize product RVAs (complete native stack).
2. Optional: Cancel without Clear + WM_SETTEXT-only to shrink MIXED residual.
3. BATCH1_CANCEL_RECOVERY remains OPEN; PROMOTE=0.

## Stack→callsite residual (append; sole-harness seal unchanged)

ASOF_UTC=2026-11-03T13:25:00Z · authority: `CLASSIFY_HARNESS_VS_PRODUCT_STACK_CALLSITE.md`

```
RESIDUAL_CLASS=MIXED_RESIDUAL
FAULT_ORIGIN_CLASS=C
HARNESS_RESIDUAL_A=SUSPECTED_NOT_PROVEN
PRODUCT_CLASS_B=NOT_PROVEN
HARNESS_SOLE=REFUTED
PRODUCT_DEFECT=NOT_PROVEN
REBUILD=HELD
PROMOTE=0
```

Correlation: exception RIP `comctl32+0xBD02` nests under resolved WinMain → `0x12FB80` → GetMessageA/DispatchMessageA; shared dump frames `+0x12FB9C`/`+0x33F9` are pump/WinMain (above dispatch), not a named product WndProc. Do not reopen `HARNESS_SOLE=REFUTED`.
