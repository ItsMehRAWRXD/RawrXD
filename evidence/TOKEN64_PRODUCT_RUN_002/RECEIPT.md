# TOKEN64_PRODUCT_RUN_002 RECEIPT

## Sealed EXE

| Field | Value |
|------|------|
| Path | `G:\~dev\rawrxd\build_win32ide_link001\bin\RawrXD-Win32IDE.exe` |
| Size | 331632128 |
| SHA256 | `D121659F03EE1CF2D818035C182BCAC05B8AD32642F85D58457FB77044E95D50` |
| Pre-run match | Yes |
| Post-run sealed | Yes (untouched) |
| Prior 001 SHA | `89BFD614…` (BLOCKED_CLAMP; unchanged) |

## Root cause (cleared)

1. **Hard clamp 8** — `product_deep2_infer_seh.hpp` `InferBody` used `StreamPack{…, 8, …}` ("HOST_DECODE matrix floor"). Headless `--max-tokens` never reached ProductRun → `CALLER_OVERRIDE` / `EFFECTIVE_MAX_TOKENS=8` / `GENERATED_TOKENS=8`.
2. **CLI argv swallow** — `main_win32.cpp` `parseCmdLine` quoted-arg `while+getline` re-read past the closing `"` on `--prompt "…"`, consuming `--max-tokens 64` into the prompt string. After (1) alone, first 002 attempt saw default `2048` / `GENERATED_TOKENS=1997` (archived `*_attempt1_cli_swallow.log`).

## Fix

- `ProductDeep2Infer(..., uint32_t maxTokens=0)`; `InferBody` honors caller (0 → StreamBody default 64).
- Headless LocalGGUF passes `m_config.maxTokens` into `ProductDeep2Infer`.
- `parseCmdLine`: single close-quote read (no swallow of trailing flags).

## Invocation

```
LOCAL_ONLY=1
RAWRXD_HEADLESS=1
RawrXD-Win32IDE.exe --headless --local --no-server \
  --model G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf \
  --prompt "Write a short paragraph about why clear writing matters. Keep going until you have enough text." \
  --max-tokens 64 --backend local --verbose
```

cwd: `G:\~dev\rawrxd\build_win32ide_link001\bin`  
Harness: `run.bat` via `cmd.exe /c`

## Capture

| Field | Value |
|------|------|
| Start local | 2026-10-28 04:43:17.55 |
| End local | 2026-10-28 04:43:29.51 |
| CLI_MAX_TOKENS | 64 |
| REQUESTED_MAX_TOKENS | 64 |
| EFFECTIVE_MAX_TOKENS | 64 |
| MAX_TOKENS_SOURCE | CALLER_OVERRIDE |
| opts.maxTokens | 64 |
| GENERATED_TOKENS | 64 |
| TOKENS_COMMITTED | 64 |
| TOKEN_COMMIT_PASS | 1 |
| PRODUCT_OPEN_PASS | 1 |
| SESSION_ENTER_PASS | 1 |
| PRODUCT_PASS | 1 |
| STREAM_FINISHED | 1 |
| FIRST_TOKEN | 1 |
| EXIT_REASON | COMPLETE |
| DECODE_TPS_REAL | 6.395629 (display-only ≠ PERFORMANCE_PASS) |
| headless_server.log | `CLI_MAX_TOKENS=64` `RUN_INFER_ROUTE … maxTokens=64` |

## Disposition

| Gate | Result |
|------|--------|
| SHA_MATCH | PASS (`D121659F…`) |
| PRODUCT_OPEN / SESSION / RUN | PASS |
| TOKEN_COMMIT | PASS (64) |
| GENERATED_TOKENS>=64 | PASS (64) |
| TOKEN64 / TPS_PRODUCT_SEAL | **1** (earned) |
| PROMOTE | **0** |
| TIP_CLIMB | HOLD |
| CERTIFIED | 0 |
| 001 | remains **BLOCKED_CLAMP** |
