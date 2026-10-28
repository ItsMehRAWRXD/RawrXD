# LIVE_TETRAD_POST_HMAC_ABSORB_001 RECEIPT

## Sealed EXE (HMAC absorb; priors historical)

| Field | Value |
|------|------|
| Path | `G:\~dev\rawrxd\build_win32ide_link001\bin\RawrXD-Win32IDE.exe` |
| Size | 331634176 |
| SHA256 | `866E9D1B3B6E617B7C6001EA3BFC754002C0CE61F8880FF6294C95B86E6A601F` |
| Match expected | Yes |
| Cite | `CAMELLIA_HMAC_PRODUCT_ABSORB_001` |
| Historical | `D121659F…` (`LIVE_TETRAD_POST_RELINK_001`) · `89BFD614…` · `4A5D6B31…` untouched |

## Invocation

```
LOCAL_ONLY=1
RAWRXD_HEADLESS=1
RawrXD-Win32IDE.exe --headless --local --no-server \
  --model G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf \
  --prompt "Say hi in one word." --max-tokens 16 --backend local --verbose
```

cwd: `G:\~dev\rawrxd\build_win32ide_link001\bin` · Harness: `run_tetrad.bat`

## Capture

| Field | Value |
|------|------|
| Start local | 2026-10-28 05:01:35.31 |
| End local | 2026-10-28 05:01:40.16 |
| Start/End UTC (approx) | 2026-10-28T09:01:35Z / 09:01:40Z |
| Model | TinyLlama 1.1B Chat Q4_K_M |
| REQUESTED/EFFECTIVE_MAX_TOKENS | 16 / 16 |
| GENERATED_TOKENS | 16 |
| TOKENS_COMMITTED | 16 |
| TOKEN_COMMIT_PASS | 1 |
| PRODUCT_OPEN_PASS | 1 |
| SESSION_ENTER_PASS | 1 |
| PRODUCT_PASS | 1 |
| STREAM_FINISHED / FIRST_TOKEN | 1 / 1 |
| EXIT_REASON | COMPLETE |
| Exit | UNOBSERVED GUI; `TD=11 CLEAN_EXIT` |
| DECODE_TPS_REAL | 4.963730 (display-only) |
| SYNTHETIC_TOKEN_PATH | 0 |

## Disposition

| Gate | Result |
|------|--------|
| PRODUCT_OPEN | **PASS** |
| PRODUCT_RUN | **PASS** |
| TOKENS_GENERATED | **PASS** (16) |
| LIVE_TETRAD | **PASS** on `866E9D1B…` |
| PROMOTE | **0** |
| TIP_CLIMB | HOLD |
| CERTIFIED | 0 |
| self_test=-8 | OPEN (independent) |
