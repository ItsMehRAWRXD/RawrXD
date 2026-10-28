# LIVE_TETRAD_SEALED_EXE_001 RECEIPT

## Sealed EXE

| Field | Value |
|------|------|
| Path | `G:\~dev\rawrxd\build_win32ide_link001\bin\RawrXD-Win32IDE.exe` |
| Size | 331623936 |
| SHA256 | `4A5D6B31DD83CE117A1F8769D55474186C4629EA4074F033125EEE1D20F0E3CE` |
| Match expected | Yes |
| Post-run sealed | Yes (untouched) |
| Provenance | `evidence/UNLINKED_SYMBOLS_E2E_001/LINK_WIN32IDE_002.txt` |

## Invocation (no rebuild)

```
LOCAL_ONLY=1
RAWRXD_HEADLESS=1
RAWRXD_PRODUCT_MODEL=<tinyllama gguf>
RawrXD-Win32IDE.exe --headless --local --no-server \
  --model G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf \
  --prompt "Say hi in one word." --max-tokens 16 --backend local --verbose
```

cwd: `G:\~dev\rawrxd\build_win32ide_link001\bin`

## Capture

| Field | Value |
|------|------|
| PID | 21320 |
| Start UTC | 2026-10-28T07:36:11.3883838Z |
| End UTC | 2026-10-28T07:36:17.9319766Z |
| Model | TinyLlama 1.1B Chat Q4_K_M (`arch=llama`, 201 tensors) |
| Backend | LocalGGUF / Deep2Engine HOST_DECODE (CPU) |
| GENERATED_TOKENS | 8 |
| TOKENS_COMMITTED | 8 |
| TOKEN_COMMIT_PASS | 1 |
| PRODUCT_OPEN_PASS | 1 |
| SESSION_ENTER_PASS | 1 |
| PRODUCT_PASS | 1 |
| EXIT_REASON | COMPLETE |
| Exit code | UNOBSERVED (Win32 GUI subsystem via Start-Process); stderr `TD=11 CLEAN_EXIT` |
| Raw log | `raw.log` (also `raw_stdout.log`, `raw_stderr.log`) |

## Disposition

| Gate | Result | Reason |
|------|--------|--------|
| PRODUCT_OPEN | **PASS** | `PRODUCT_OPEN_PASS=1` SESSION_ENTER/EXIT ok; tensors=201; HEADLESS_READY=1 SOURCE=PRODUCT_OPEN_PASS |
| PRODUCT_RUN | **PASS** | stderr `PRODUCT_RUN` STREAM_FINISHED=1 FIRST_TOKEN=1 EXIT_REASON=COMPLETE PRODUCT_PASS=1 PATH=generateStream |
| TOKENS_GENERATED | **PASS** | `GENERATED_TOKENS=8` `TOKENS_COMMITTED=8` SYNTHETIC_TOKEN_PATH=0 |
| LIVE_TETRAD | **PASS** | OPEN∧SESSION∧GENERATED_TOKENS>0∧TOKEN_COMMIT all observed on sealed EXE |
| PROMOTE | **0** | Always; TPS_PRODUCT_SEAL=0 BLOCKED_AT=64_TOKEN_PRODUCT_RUN; MULTI_FAMILY next; CERTIFIED=0 TIP_CLIMB=HOLD |

## Notes

- Entry used sealed EXE `--headless` product path; no separate `product_deep2` harness; no rebuild.
- `DECODE_TPS_REAL=1.937` is display-only; not invented as PERFORMANCE_PASS.
- `R25_PRODUCTOPEN=SKIP GATE_OFF` (MASM gate off); LocalOnly `ProductOpenSession` path still PASS.
