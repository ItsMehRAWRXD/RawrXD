# WATCHDOG_ASM_BIND_001 RECEIPT

## Verdict

| Field | Value |
|------|------|
| RESTORED | **Y** |
| BIND_STATUS | SOURCE_WIRED + OBJECT_SMOKE |
| LINK_SMOKE | **NOT_RUN** (no Win32IDE relink) |
| RUNTIME_HMAC | **NOT_RUN** |
| PROMOTE | **0** |
| TIP_CLIMB | HOLD |
| CERTIFIED | 0 |
| MagBuf CRC | CLEARED_JOIN (unchanged; B04) |

## What changed

1. Restored `src/asm/RawrXD_Watchdog.asm` from `Full Source\src\asm\RawrXD_Watchdog.asm` (was END-only 5B; now 25271B .text HMAC-SHA256).
2. CMake Phase WD: always assemble-from-source; skip genesis/stub prebuilts (~816B) — Auth-parallel.
3. Object smoke: ml64 EXIT=0 → `RawrXD_Watchdog_from_source.obj` (13248B).
4. dumpbin: 5 PUBLIC `asm_watchdog_*` + `wd_compute_hmac_sha256`; UNDEF `asm_camellia256_get_hmac_key`.
5. No Win32IDE relink → sealed EXE SHA unchanged (≠ new tetrad).

## Artifacts

| Artifact | SHA256 / size |
|----------|---------------|
| Watchdog.asm (product) | A75DF2ADC748748CBD675F2FEE09DF75E805E62E32CBB0C3002A70A0DA76A704 / 25271 |
| Watchdog.obj (evidence smoke) | 8FC7DBB7E1EDAD638C4A422B95A394686A2385B73C9DEBF33116A8E2482A8EEE / 13248 |
| Stale buildtree stub obj | E0D6746A4626DDB1EAEFFD2DBC93D4A47A734612064CC0BFD30804447E1B6404 / 816 |
| Sealed Win32IDE EXE (unchanged) | 89BFD6142CEE7A6AA537DF0297014E240C7CC55B142C230521527914469F8630 |

## Exports (External)

```
asm_watchdog_init
asm_watchdog_verify
asm_watchdog_get_baseline
asm_watchdog_get_status
asm_watchdog_shutdown
wd_compute_hmac_sha256
; UNDEF import: asm_camellia256_get_hmac_key
```

## Link gate (next, not this turn)

C MagBuf owners still define `asm_watchdog_init` / verify / get_status. Dual-link of restored MASM body requires gating those C exports (LNK2005). MagBuf CRC join stays CLEARED; HMAC RUNTIME remains NOT_RUN until product link + Camellia key init E2E.

## Evidence paths

- `evidence/WATCHDOG_ASM_BIND_001/LAW.txt`
- `evidence/WATCHDOG_ASM_BIND_001/RECEIPT.md`
- `evidence/WATCHDOG_ASM_BIND_001/_asm_from_source.bat`
- `evidence/WATCHDOG_ASM_BIND_001/_dumpbin_exports.bat`
- `evidence/WATCHDOG_ASM_BIND_001/ml64_from_source.out`
- `evidence/WATCHDOG_ASM_BIND_001/dumpbin_symbols.txt`
