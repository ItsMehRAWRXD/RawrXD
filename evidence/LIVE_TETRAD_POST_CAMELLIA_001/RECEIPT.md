# LIVE_TETRAD_POST_CAMELLIA_001 RECEIPT

## Sealed EXE (post-Camellia)

| Field | Value |
|------|------|
| Path | `G:\~dev\rawrxd\build_win32ide_link001\bin\RawrXD-Win32IDE.exe` |
| Size | 331629056 |
| SHA256 | `89BFD6142CEE7A6AA537DF0297014E240C7CC55B142C230521527914469F8630` |
| Match expected | Yes |
| Post-run sealed | Yes (untouched) |
| Provenance | `evidence/CAMELLIA_AUTH_ASM_BIND_001` |
| Historical seal | `LIVE_TETRAD_SEALED_EXE_001` SHA `4A5D6B31…` untouched |

## Invocation (no rebuild)

```
LOCAL_ONLY=1
RAWRXD_HEADLESS=1
RawrXD-Win32IDE.exe --headless --local --no-server \
  --model G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf \
  --prompt "Say hi in one word." --max-tokens 16 --backend local --verbose
```

cwd: `G:\~dev\rawrxd\build_win32ide_link001\bin`  
Harness: `run_tetrad.bat` via `cmd.exe /c` (PowerShell strips `$vars`).

## Capture

| Field | Value |
|------|------|
| Start local | 2026-10-28 04:05:06.09 |
| End local | 2026-10-28 04:05:12.46 |
| Start UTC (approx) | 2026-10-28T08:05:06Z |
| End UTC (approx) | 2026-10-28T08:05:12Z |
| Model | TinyLlama 1.1B Chat Q4_K_M (`arch=llama`, 201 tensors) |
| Backend | LocalGGUF / Deep2Engine HOST_DECODE (CPU) |
| GENERATED_TOKENS | 8 |
| TOKENS_COMMITTED | 8 |
| TOKEN_COMMIT_PASS | 1 |
| PRODUCT_OPEN_PASS | 1 |
| SESSION_ENTER_PASS | 1 |
| PRODUCT_PASS | 1 |
| PRODUCT_RUN | observed (`STREAM_FINISHED=1` `FIRST_TOKEN=1`) |
| EXIT_REASON | COMPLETE |
| Exit code | UNOBSERVED (Win32 GUI subsystem; bat `EXITLEVEL=` empty); stderr `TD=11 CLEAN_EXIT` |
| Raw log | `raw.log` (also `raw_stdout.log`, `raw_stderr.log`) |

## Disposition (B16 / LIVE_TETRAD on THIS SHA)

| Gate | Result | Reason |
|------|--------|--------|
| PRODUCT_OPEN | **PASS** | `PRODUCT_OPEN_PASS=1` SESSION_ENTER/EXIT ok; tensors=201; HEADLESS_READY=1 SOURCE=PRODUCT_OPEN_PASS |
| PRODUCT_RUN | **PASS** | stderr `PRODUCT_RUN` STREAM_FINISHED=1 FIRST_TOKEN=1 EXIT_REASON=COMPLETE PRODUCT_PASS=1 |
| TOKENS_GENERATED | **PASS** | `GENERATED_TOKENS=8` `TOKENS_COMMITTED=8` SYNTHETIC_TOKEN_PATH=0 TOKEN_COMMIT_PASS=1 |
| LIVE_TETRAD | **PASS** | OPEN∧SESSION∧GENERATED_TOKENS>0∧TOKEN_COMMIT all observed on SHA `89BFD614…` |
| PROMOTE | **0** | Always; TPS_PRODUCT_SEAL=0 BLOCKED_AT=64_TOKEN_PRODUCT_RUN; MULTI_FAMILY next; CERTIFIED=0 TIP_CLIMB=HOLD |

## Notes

- Entry used post-Camellia EXE `--headless` product path; no separate `product_deep2` harness; no rebuild/relink.
- `DECODE_TPS_REAL=1.700602` is display-only; not invented as PERFORMANCE_PASS.
- `R25_PRODUCTOPEN=SKIP GATE_OFF` (MASM gate off); LocalOnly `ProductOpenSession` path still PASS.
- Does **not** rewrite `LIVE_TETRAD_SEALED_EXE_001`.
