# MULTI_FAMILY_PRODUCT_002 RECEIPT

## Sealed EXE (HMAC absorb SHA; priors historical)

| Field | Value |
|------|------|
| Path | `G:\~dev\rawrxd\build_win32ide_link001\bin\RawrXD-Win32IDE.exe` |
| Size | 331634176 |
| SHA256 | `866E9D1B3B6E617B7C6001EA3BFC754002C0CE61F8880FF6294C95B86E6A601F` |
| Cite | `CAMELLIA_HMAC_PRODUCT_ABSORB_001` |
| Historical | `D121659F…` · `89BFD614…` (`MULTI_FAMILY_PRODUCT_001`) untouched as prior authority |

## Invocation

```
LOCAL_ONLY=1 RAWRXD_HEADLESS=1
RawrXD-Win32IDE.exe --headless --local --no-server \
  --model G:\~dev\rawrxd\models\gemma3-1b-Q2_K.gguf \
  --prompt "Say hi in one word." --max-tokens 16 --backend local --verbose
```

## Capture

| Field | Value |
|------|------|
| Start/End local | 2026-10-28 05:03:23.00 / 05:03:43.87 |
| Model | gemma3-1b-Q2_K (`ARCH=gemma3`) |
| FAMILY_NE_TINYLLAMA | 1 |
| EFFECTIVE_MAX_TOKENS | 16 |
| GENERATED_TOKENS | 16 |
| TOKENS_COMMITTED | 16 |
| TOKEN_COMMIT_PASS | 1 |
| PRODUCT_OPEN_PASS | 1 |
| SESSION_ENTER_PASS | 1 |
| PRODUCT_PASS | 1 |
| STREAM_FINISHED / FIRST_TOKEN | 1 / 1 |
| EXIT_REASON | COMPLETE |
| DECODE_TPS_REAL | 1.456211 (display-only) |
| SYNTHETIC_TOKEN_PATH | 0 |
| INFERENCE_SPLIT | HOLD |

## Disposition

| Gate | Result |
|------|--------|
| MULTI_FAMILY | **PASS** (gemma3 ≠ TinyLlama on `866E9D1B…`) |
| PROMOTE | **0** |
| self_test=-8 | OPEN |
