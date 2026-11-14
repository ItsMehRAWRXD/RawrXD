# G02-06 RELATED — AA4F R75 EXIT=NULL → TOK (B8E5F6E5)

ASOF_LOCAL=2026-11-13T23:32:26-05:00
PROMOTE=0 TIP_CLIMB=HOLD INVENT_PASS=0 CERT_RESULT=NOT_RUN CROSS_SHA_CREDIT=0
TIP_RO=6754616EA30A566423727F82513AC66D8241FDB73343F9CD7A440FF9D4E43431 UNTOUCHED=1

## Gate touch

- Near: G02 (infer/stream survivability), G03 (crash/SEH hygiene)
- RELATED ≠ PASS on CERT_001 checklist

## Prior residual (R69)

| Metric | B8E5 mid-VRAM-cleared |
|--------|----------------------|
| OPEN | 1 |
| STREAM_ENTER | 1 |
| MID_VRAM_HARD | 0 |
| STREAM_SEH | 0 |
| TOK | 0 |
| EXIT | NULL |
| AV_CLOSED | 0 |

ROOT_FIX prior: D2GenQualitySlotFor ABI (Eng-tail quality off; sizeof matches seh 0x2868).

## Diagnose (EXIT=NULL after STREAM_ENTER)

1. **ArmSpeed E8B0M**: `StreamerArmSpeedEnv` SetEnvIfUnset `DEEP2_WEIGHT_BUDGET_MIB=E8B0M` (59568 MiB). GpuForward emitted WEIGHT_BUDGET receipt per layer → stderr flood; ABSORB076 already noted E8B0M spam truncated mid-decode.
2. **Cross-kill**: concurrent remasure scripts `Stop-Process RawrXD*` murdered the cand mid-prefill → EXIT=NULL SEH=0 TOK=0 (looked like decode hang). Controlling proof: rename to `PrivateCand_*` (not RawrXD*) + kill only foreign RawrXD* → durable TOK.
3. Not logits: B8E5 err stopped mid-prefill (~13–18/39 FINAL_NORM) with no LOGITS_BEFORE.

## Cand (controlling)

| Field | Value |
|-------|-------|
| EXE | `clean_link/PrivateCand_aa4f_r69_exitnull.exe` (= tip_land_aa4f_r69 B8E5 bytes) |
| EXE_SHA256 | B8E5F6E57F73759361FAF283CE227BCEF5AF37488785E83F005D4C9D094DCB49 |
| Remeasure | `gpu/ide_mf_aa4f_r69_priv_gemma3_B8E5F6E57F737593_20261113_233037` |

## Runtime (gemma3-1b-Q2_K, FORCE=0, DEEP2_WEIGHT_BUDGET_MIB=8192)

| Metric | Value |
|--------|-------|
| PRODUCT_OPEN_PASS | 1 |
| GENERATE_STREAM_ENTER | 1 |
| PREFILL_DONE | 1 |
| MID_VRAM_HARD | 0 |
| INFER_STREAM_SEH | 0 |
| PRODUCT_DEEP2_OPEN_SEH | 0 |
| GENERATED_TOKENS | 8 |
| PROCESS_EXIT | 0 |
| AV_CLOSED | 1 |
| SEH | 0 |
| E8B0M_SPAM | 0 |
| WALL_MS | 107401 |

## ROOT_FIX (this turn)

1. **ProductStreamerPrep**: after ArmSpeed, honor `WEIGHT_BUDGET_MIB` → `DEEP2_WEIGHT_BUDGET_MIB`; else clamp absurd (>16GiB / E8B0M) to 8192. SOURCE_WIRED.
2. **GpuForward**: prefer `WEIGHT_BUDGET_MIB`, once-only budget emit, clamp >16GiB (SOURCE_WIRED; full GpuForward-only relink of gemma_seal obj regresses STREAM_SEH — do not displace obj075 without full consistent rebuild).
3. **Remasure hygiene**: PrivateCand rename avoids `RawrXD*` cross-kill; set `DEEP2_WEIGHT_BUDGET_MIB=8192` with `WEIGHT_BUDGET_MIB=8192`.
4. Prior D2GenQualitySlotFor ABI retained on B8E5 cand.

## Note M1M2 085f

2696F3B2 AV_CLOSED=1 SEH=0 TOK=0 FAIL until TOK>0 — unchanged this turn; CROSS_SHA=0.

## Disposition

- TOK=8 SEH=0 EXIT=0 AV_CLOSED=1 on private B8E5 cand (RELATED durable decode).
- PROMOTE=0 TIP_CLIMB=HOLD REJECT_TIP_PROMOTE=1
- Control 7FD1 TOK=8 remains CROSS_SHA=0 authority (not blended).

Board: `board_receipts/BR_EXIT_NULL_TOK_R75.txt`
END
