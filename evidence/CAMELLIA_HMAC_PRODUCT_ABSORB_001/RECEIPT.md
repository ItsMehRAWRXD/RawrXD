# RECEIPT — CAMELLIA_HMAC_PRODUCT_ABSORB_001

```
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
WORKSPACE=G:\~dev\rawrxd
ASOF_UTC=2026-10-28T09:00:00Z
```

## Verdict

| Gate | Result |
|------|--------|
| Camellia256 product reassemble | **PASS** (ml64 + ninja; set_key→cam_hmac_key absorb) |
| Watchdog product reassemble | **PASS** (RSP-align absorb) |
| Win32IDE relink `-j2` | **PASS** (`CMAKE_BUILD_EXIT=0`) |
| ABSORB (HMAC into EXE) | **PASS** (earned; new EXE SHA) |
| RELINK_REQUIRED | **0** (closed vs WATCHDOG_HMAC_PRODUCT_001) |
| INIT_SELF_TEST_BLOCK | **-8 OPEN** (held; ≠ invent) |
| TPS `--max-tokens 64` | **SHA_BOUND_D121659F_ONLY** (not re-proven) |
| PROMOTE | **0** |

## Sealed EXE

| Field | Value |
|-------|-------|
| Path | `G:\~dev\rawrxd\build_win32ide_link001\bin\RawrXD-Win32IDE.exe` |
| Size | 331634176 |
| SHA256 | `866E9D1B3B6E617B7C6001EA3BFC754002C0CE61F8880FF6294C95B86E6A601F` |
| Prior (no hmac absorb) | `D121659F03EE1CF2D818035C182BCAC05B8AD32642F85D58457FB77044E95D50` |

## Product objs (post-ninja)

| Obj | SHA256 | Size |
|-----|--------|------|
| `RawrXD_Camellia256.obj` | `49CE60B7FE06C4D15C313F55638B241ABE394F2DC395515553797456AE4DDC24` | 32137 |
| `RawrXD_Watchdog.obj` | `8A0244FDA2BDA1F8458B86B3C43C5E671F1585CE5DDCC7B900E13EF2604804E6` | 13256 |

## Build

```
_asm_rebuild.bat
_relink_win32ide.bat
  cmake --build build_win32ide_link001 --target RawrXD-Win32IDE --config Release -j 2
_seal_hashes.bat
```

Cite: `logs/relink_j2.log`, `logs/pre_exe_sha.txt`, `logs/post_exe_sha.txt`, `logs/exe_sha_final.txt`

## TPS note

`TOKEN64_PRODUCT_RUN_002` / `TPS_PRODUCT_SEAL=1` remains SHA-bound to `D121659F…` only.  
New EXE `866E9D1B…` did **not** re-run `--max-tokens 64` this mission → no TPS claim transfer.

## Held open

- `self_test=-8` (RFC 3713 KAT / schedule gap)
- `PROMOTE=0` · `TIP_CLIMB=HOLD` · `CERTIFIED=0`

## Paths

- `evidence/CAMELLIA_HMAC_PRODUCT_ABSORB_001/LAW.txt`
- `evidence/CAMELLIA_HMAC_PRODUCT_ABSORB_001/RECEIPT.md`
- `evidence/CAMELLIA_HMAC_PRODUCT_ABSORB_001/logs/`
- `evidence/CAMELLIA_HMAC_PRODUCT_ABSORB_001/_asm_rebuild.bat`
- `evidence/CAMELLIA_HMAC_PRODUCT_ABSORB_001/_relink_win32ide.bat`
- `src/asm/RawrXD_Camellia256.asm`
- `src/asm/RawrXD_Watchdog.asm`
