# LIVE_TETRAD_POST_RELINK_001 RECEIPT

## Sealed EXE (relink; Camellia/001 historical only)

| Field | Value |
|------|------|
| Path | `G:\~dev\rawrxd\build_win32ide_link001\bin\RawrXD-Win32IDE.exe` |
| Size | 331632128 |
| SHA256 | `D121659F03EE1CF2D818035C182BCAC05B8AD32642F85D58457FB77044E95D50` |
| Match expected | Yes |
| Post-run sealed | Yes (untouched) |
| Historical Camellia | `89BFD614…` untouched — does not cover this EXE |
| Historical 001 | `4A5D6B31…` untouched |

## Invocation (no rebuild)

```
LOCAL_ONLY=1
RAWRXD_HEADLESS=1
RawrXD-Win32IDE.exe --headless --local --no-server \
  --model G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf \
  --prompt "Say hi in one word." --max-tokens 16 --backend local --verbose
```

cwd: `G:\~dev\rawrxd\build_win32ide_link001\bin`  
Harness: `run_tetrad.bat` via `cmd.exe /c`.

## Capture

| Field | Value |
|------|------|
| Start local | 2026-10-28 04:49:41.94 |
| End local | 2026-10-28 04:49:48.29 |
| Start UTC (approx) | 2026-10-28T08:49:41Z |
| End UTC (approx) | 2026-10-28T08:49:48Z |
| Model | TinyLlama 1.1B Chat Q4_K_M |
| Backend | LocalGGUF / Deep2Engine HOST_DECODE (CPU) |
| REQUESTED_MAX_TOKENS | 16 |
| EFFECTIVE_MAX_TOKENS | 16 |
| GENERATED_TOKENS | 16 |
| TOKENS_COMMITTED | 16 |
| TOKEN_COMMIT_PASS | 1 |
| PRODUCT_OPEN_PASS | 1 |
| SESSION_ENTER_PASS | 1 |
| PRODUCT_PASS | 1 |
| PRODUCT_RUN | observed (`STREAM_FINISHED=1` `FIRST_TOKEN=1`) |
| EXIT_REASON | COMPLETE |
| Exit code | UNOBSERVED (Win32 GUI); stderr `TD=11 CLEAN_EXIT` |
| DECODE_TPS_REAL | 4.304887 (display-only) |
| SYNTHETIC_TOKEN_PATH | 0 |
| Raw log | `raw.log` (also stdout/stderr) |

## Disposition (LIVE_TETRAD on THIS SHA)

| Gate | Result | Reason |
|------|--------|--------|
| PRODUCT_OPEN | **PASS** | `PRODUCT_OPEN_PASS=1` |
| PRODUCT_RUN | **PASS** | STREAM_FINISHED=1 FIRST_TOKEN=1 PRODUCT_PASS=1 |
| TOKENS_GENERATED | **PASS** | GENERATED_TOKENS=16 TOKEN_COMMIT_PASS=1 |
| LIVE_TETRAD | **PASS** | OPEN∧SESSION∧GENERATED_TOKENS>0∧TOKEN_COMMIT on `D121659F…` |
| PROMOTE | **0** | Always; CERTIFIED=0 TIP_CLIMB=HOLD |

## Notes

- Prior partial on EXPECTED `32C28BF7…` superseded; this seal is D121659F only.
- Sibling `TOKEN64_PRODUCT_RUN_002` TPS_PRODUCT_SEAL=1 on same SHA (GENERATED_TOKENS=64).
- Does **not** rewrite `LIVE_TETRAD_POST_CAMELLIA_001` / `LIVE_TETRAD_SEALED_EXE_001`.
