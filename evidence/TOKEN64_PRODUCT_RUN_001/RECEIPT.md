# TOKEN64_PRODUCT_RUN_001 RECEIPT

## Sealed EXE

| Field | Value |
|------|------|
| Path | `G:\~dev\rawrxd\build_win32ide_link001\bin\RawrXD-Win32IDE.exe` |
| Size | 331629056 |
| SHA256 | `89BFD6142CEE7A6AA537DF0297014E240C7CC55B142C230521527914469F8630` |
| Pre-run match | Yes |
| Post-run sealed | Yes (untouched) |
| Rebuild | No |

## Invocation (no rebuild)

```
LOCAL_ONLY=1
RAWRXD_HEADLESS=1
RawrXD-Win32IDE.exe --headless --local --no-server \
  --model G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf \
  --prompt "Write a short paragraph about why clear writing matters. Keep going until you have enough text." \
  --max-tokens 64 --backend local --verbose
```

cwd: `G:\~dev\rawrxd\build_win32ide_link001\bin`  
Harness: `run.bat` via `cmd.exe /c` (PowerShell strips `$vars`).

## Capture

| Field | Value |
|------|------|
| Start local | 2026-10-28 04:21:55.76 |
| End local | 2026-10-28 04:22:07.03 |
| Model | TinyLlama 1.1B Chat Q4_K_M (`arch=llama`, 201 tensors) |
| Backend | LocalGGUF / Deep2Engine HOST_DECODE (CPU) |
| CLI_MAX_TOKENS | 64 |
| REQUESTED_MAX_TOKENS | 8 |
| EFFECTIVE_MAX_TOKENS | 8 |
| MAX_TOKENS_SOURCE | CALLER_OVERRIDE |
| opts.maxTokens | 8 |
| GENERATED_TOKENS | 8 |
| TOKENS_COMMITTED | 8 |
| TOKEN_COMMIT_PASS | 1 |
| PRODUCT_OPEN_PASS | 1 |
| SESSION_ENTER_PASS | 1 |
| PRODUCT_PASS | 1 |
| PRODUCT_RUN | observed (`STREAM_FINISHED=1` `FIRST_TOKEN=1`) |
| EXIT_REASON | COMPLETE |
| Exit code | UNOBSERVED (Win32 GUI subsystem); stderr `TD=11 CLEAN_EXIT` |
| DECODE_TPS_REAL | 0.830025 (display-only) |
| Raw logs | `raw.log`, `raw_stdout.log`, `raw_stderr.log` |

## Disposition (64-token product seal)

| Gate | Result | Reason |
|------|--------|--------|
| SHA_MATCH | PASS | Pre+post `89BFD614?` |
| PRODUCT_OPEN | PASS | `PRODUCT_OPEN_PASS=1` |
| SESSION | PASS | `SESSION_ENTER_PASS=1` |
| PRODUCT_RUN | PASS | `PRODUCT_RUN` / `STREAM_FINISHED=1` |
| TOKEN_COMMIT | PASS | `TOKEN_COMMIT_PASS=1` TOKENS_COMMITTED=8 |
| GENERATED_TOKENS>=64 | FAIL | actual GENERATED_TOKENS=8; product clamp EFFECTIVE_MAX_TOKENS=8 despite CLI 64 |
| TOKEN64 / TPS_PRODUCT_SEAL | **BLOCKED_CLAMP** | CLI 64 never reached generator; CALLER_OVERRIDE fixed at 8 |
| PROMOTE | **0** | Always; even 64-token PASS would not flip PROMOTE |
| TIP_CLIMB | HOLD | Unchanged |
| CERTIFIED | 0 | Unchanged |

## Notes

- Same EXE SHA as `LIVE_TETRAD_POST_CAMELLIA_001` / `MULTI_FAMILY_PRODUCT_001`.
- Runtime note also emits `BLOCKED_AT=64_TOKEN_PRODUCT_RUN`.
- `DECODE_TPS_REAL=0.830025` is display-only; not PERFORMANCE_PASS; `TPS_PRODUCT_SEAL=0`.
- Disposition is **BLOCKED_CLAMP** (not NOT_RUN; product path ran) with actual GENERATED_TOKENS=8.
