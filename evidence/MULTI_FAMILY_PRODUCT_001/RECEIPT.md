# MULTI_FAMILY_PRODUCT_001 RECEIPT

## Sealed EXE (same post-Camellia)

| Field | Value |
|------|------|
| Path | `G:\~dev\rawrxd\build_win32ide_link001\bin\RawrXD-Win32IDE.exe` |
| Size | 331629056 |
| SHA256 | `89BFD6142CEE7A6AA537DF0297014E240C7CC55B142C230521527914469F8630` |
| Match expected | Yes (pre + post run) |
| Post-run sealed | Yes (untouched) |
| Provenance | `evidence/CAMELLIA_AUTH_ASM_BIND_001` |
| TinyLlama tetrad | `LIVE_TETRAD_POST_CAMELLIA_001` untouched |
| Historical seal | `LIVE_TETRAD_SEALED_EXE_001` SHA `4A5D6B31…` untouched |

## Second family (independent of TinyLlama R25)

| Field | Value |
|------|------|
| Model | `G:\~dev\rawrxd\models\gemma3-1b-Q2_K.gguf` |
| ARCH | `gemma3` |
| FAMILY_NE_TINYLLAMA | 1 |
| tensors | 340 |
| BLOCKED_NO_MODEL | 0 |

## Invocation (no rebuild)

```
LOCAL_ONLY=1
RAWRXD_HEADLESS=1
RawrXD-Win32IDE.exe --headless --local --no-server \
  --model G:\~dev\rawrxd\models\gemma3-1b-Q2_K.gguf \
  --prompt "Say hi in one word." --max-tokens 16 --backend local --verbose
```

cwd: `G:\~dev\rawrxd\build_win32ide_link001\bin`  
Harness: `run_multifamily.bat` via `cmd.exe /c` (PowerShell strips `$vars`).

## Capture

| Field | Value |
|------|------|
| Start local | 2026-10-28 04:11:15.80 |
| End local | 2026-10-28 04:11:36.65 |
| Start UTC (approx) | 2026-10-28T08:11:15Z |
| End UTC (approx) | 2026-10-28T08:11:36Z |
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
| SYNTHETIC_TOKEN_PATH | 0 |
| PATH | generateStream |
| Raw log | `raw.log` (also `raw_stdout.log`, `raw_stderr.log`) |

## Disposition

| Gate | Result | Reason |
|------|--------|--------|
| PRODUCT_OPEN | **PASS** | `PRODUCT_OPEN_PASS=1` SESSION_ENTER/EXIT ok; tensors=340; ARCH=gemma3; HEADLESS_READY=1 |
| PRODUCT_RUN | **PASS** | stderr `PRODUCT_RUN` STREAM_FINISHED=1 FIRST_TOKEN=1 EXIT_REASON=COMPLETE PRODUCT_PASS=1 |
| TOKENS_GENERATED | **PASS** | `GENERATED_TOKENS=8` `TOKENS_COMMITTED=8` SYNTHETIC_TOKEN_PATH=0 TOKEN_COMMIT_PASS=1 |
| MULTI_FAMILY | **PASS** | Independent non-TinyLlama GGUF (`arch=gemma3`) on same EXE SHA `89BFD614…` with OPEN∧SESSION∧TOKENS>0∧TOKEN_COMMIT |
| PROMOTE | **0** | Always; TPS_PRODUCT_SEAL=0 BLOCKED_AT=64_TOKEN_PRODUCT_RUN; CERTIFIED=0 TIP_CLIMB=HOLD; PromoteReady conjunction incomplete |

## Notes

- Entry used post-Camellia EXE `--headless` product path; no separate `product_deep2` harness; no rebuild/relink.
- `DECODE_TPS_REAL=0.767341` is display-only; not invented as PERFORMANCE_PASS.
- Does **not** rewrite `LIVE_TETRAD_POST_CAMELLIA_001` or `LIVE_TETRAD_SEALED_EXE_001`.
- Does **not** reopen HexMag Copilot, Markov→Deep2, or Camellia bind.
- Inference SPLIT HOLD preserved (`RAWR_HAS_RAWR_INFERENCE` unchanged).
- Binary stderr still echoes static `NEXT_INDEPENDENT_GATE=MULTI_FAMILY` string; seal authority is this folder + `P1_PRODUCT_GATE.txt`.
