# TOKEN64_PRODUCT_RUN_003 RECEIPT

## Sealed EXE (HMAC absorb; D121659F TPS does not transfer)

| Field | Value |
|------|------|
| Path | `G:\~dev\rawrxd\build_win32ide_link001\bin\RawrXD-Win32IDE.exe` |
| Size | 331634176 |
| SHA256 | `866E9D1B3B6E617B7C6001EA3BFC754002C0CE61F8880FF6294C95B86E6A601F` |
| Cite | `CAMELLIA_HMAC_PRODUCT_ABSORB_001` |
| Prior TPS seal | `TOKEN64_PRODUCT_RUN_002` on `D121659F…` — **does not transfer** |

## Invocation

```
LOCAL_ONLY=1 RAWRXD_HEADLESS=1
RawrXD-Win32IDE.exe --headless --local --no-server \
  --model G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf \
  --prompt "Write a short paragraph about why clear writing matters. Keep going until you have enough text." \
  --max-tokens 64 --backend local --verbose
```

## Capture

| Field | Value |
|------|------|
| Start/End local | 2026-10-28 05:05:32.04 / 05:05:44.70 |
| CLI / REQUESTED / EFFECTIVE | 64 / 64 / 64 |
| MAX_TOKENS_SOURCE | CALLER_OVERRIDE |
| opts.maxTokens | 64 |
| GENERATED_TOKENS | 64 |
| TOKENS_COMMITTED | 64 |
| TOKEN_COMMIT_PASS | 1 |
| PRODUCT_OPEN / SESSION / PASS | 1 / 1 / 1 |
| STREAM_FINISHED / FIRST_TOKEN | 1 / 1 |
| EXIT_REASON | COMPLETE |
| DECODE_TPS_REAL | 5.751662 (display-only ≠ PERFORMANCE_PASS) |
| SYNTHETIC_TOKEN_PATH | 0 |

## Disposition

| Gate | Result |
|------|--------|
| GENERATED_TOKENS>=64 | **PASS** (64) |
| TOKEN64 / TPS_PRODUCT_SEAL | **1** (earned on `866E9D1B…`) |
| PROMOTE | **0** |
| TIP_CLIMB | HOLD |
| CERTIFIED | 0 |
| self_test=-8 | OPEN |
| 002 | remains SHA-bound to `D121659F…` only |
