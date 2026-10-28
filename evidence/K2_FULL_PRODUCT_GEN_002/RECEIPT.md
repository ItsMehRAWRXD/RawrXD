# K2_FULL_PRODUCT_GEN_002 RECEIPT

## Definition (in-repo)

`K2_FULL_PRODUCT_GENERATION` = TOP15 breakthrough **#04** / CLOSEST **#3**:
Win32IDE/HeadlessIDE product path (`ProductOpenSession` → `ProductRun` /
`Deep2Engine::generateStream`) on **Kimi-K2-Instruct-0905** multi-shard GGUF,
on the CURRENT tip EXE — not TinyLlama tetrad, not gemma3 multi-family,
not `deep2_benchmark` MoE probes, not `VWA_K2_FULL_E2E_001` criteria closure.

Prior: `K2_FULL_PRODUCT_GEN_001` = **BLOCKED_OOM** on historical SHA `89BFD614…`
(NOT_RUN vs CURRENT tip until this seal).

Cites: `TOP15_BREAKTHROUGH_ORDER.txt`, `POST_SCHEDULER_PROMOTE_REQ_001`
MATRIX S18 / LAW, `WIN32IDE_FULL_SOURCE_AUDIT_001` MATRIX A26.

## Sealed EXE

| Field | Value |
|------|------|
| Path | `G:\~dev\rawrxd\build_win32ide_link001\bin\RawrXD-Win32IDE.exe` |
| Size | 331634176 |
| SHA256 | `866E9D1B3B6E617B7C6001EA3BFC754002C0CE61F8880FF6294C95B86E6A601F` |
| Pre-run match | Yes |
| Post-run sealed | Yes (untouched) |
| Rebuild | No |

## Model (strongest local K2; only on-disk quant)

| Field | Value |
|------|------|
| Path | `F:\OllamaModels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M\Kimi-K2-Instruct-0905-Q4_K_M-00001-of-00013.gguf` |
| Quant | Q4_K_M |
| Smaller quant available | **No** — sibling dirs (`Q2_K`, `Q3_K_*`, `IQ4_*`, `UD-IQ*`, …) exist but contain **0** `.gguf`; only `Q4_K_M` has 13 shards |
| Under `rawrxd/models/` | **No** Kimi/K2 GGUF present |
| Shards | 13/13 indexed |
| Tensors | 1096 |
| ARCH | deepseek2 |
| Layers / experts | 61 / 384 (expertsPerToken=8) |
| MLA | yes (qLora=1536 kvLora=512) |

## Invocation (no rebuild; cmd bat)

```
LOCAL_ONLY=1
RAWRXD_HEADLESS=1
RAWRXD_DEEP2_ALLOW_ELASTIC=1
RawrXD-Win32IDE.exe --headless --local --no-server \
  --model F:\OllamaModels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M\Kimi-K2-Instruct-0905-Q4_K_M-00001-of-00013.gguf \
  --prompt "Say hi in one word." --max-tokens 64 --backend local --verbose
```

cwd: `G:\~dev\rawrxd\build_win32ide_link001\bin`  
Harness: `run_k2_product.bat` via `cmd.exe /c`

## Capture

| Field | Value |
|------|------|
| Start local | 2026-10-28 05:36:01.05 |
| End local | 2026-10-28 05:36:05.83 |
| Index open | Yes (13 shards, tokenizer vocab=163840) |
| AUTO_BACKEND weights estimate | 44152 MB |
| Host RAM / commit | 37099 MB / 29922 MB |
| AUTO_BACKEND | **Reject** `Insufficient host memory` |
| FAILED_STAGE | `BACKEND_SELECT` |
| FAILED_OWNER | `NO_FEASIBLE_BACKEND` |
| GENERATED_TOKENS | **0** |
| TOKENS_COMMITTED | 0 |
| PRODUCT_OPEN_PASS (final) | 0 |
| SESSION_ENTER_PASS (final) | 0 |
| TOKEN_COMMIT_PASS | 0 |
| PRODUCT_PASS | 0 |
| EXIT_REASON | Insufficient host memory |
| CLEAN_EXIT | 1 (`TD=11`) |
| Logs | `logs/raw_stdout.log`, `logs/raw_stderr.log`, `raw.log` |

Note: early index arm emitted `PRODUCT_OPEN_PASS=1` with
`DEEP2_RESIDENCY_ENTERED=0`; PRODUCT_RUN then rejected backend and stamped
final gates to 0. Index-open ≠ generation PASS.

## Disposition

| Gate | Result | Reason |
|------|--------|--------|
| SHA_MATCH | PASS | Pre+post `866E9D1B…` |
| K2_MODEL_PRESENT | PASS (path) | F:\ OllamaModels 13-shard Q4_K_M |
| SMALLER_QUANT | N/A | No alternate on-disk GGUF |
| K2_INDEX | OBSERVED | 1096 tensors / 13 shards |
| PRODUCT_GENERATION | **BLOCKED** | AUTO_BACKEND OOM: weights 44152MB > host RAM 37099MB |
| GENERATED_TOKENS>0 | FAIL | actual 0 |
| K2_FULL_PRODUCT_GENERATION | **BLOCKED_OOM** | ≠ PASS; ≠ NOT_RUN (path exercised to BACKEND_SELECT on CURRENT) |
| PROMOTE | **0** | Always |
| TIP_CLIMB | HOLD | Unchanged; scheduler not reopened |
| CERTIFIED | 0 | Unchanged |

## Sibling cross-cite (untouched)

| Seal | Disposition | Note |
|------|-------------|------|
| `K2_FULL_PRODUCT_GEN_001` | **BLOCKED_OOM** | Historical SHA `89BFD614…` |
| `TOKEN64_PRODUCT_RUN_003` | cite audit MATRIX | CURRENT tip; TinyLlama ≠ K2 |
| `MULTI_FAMILY_PRODUCT_002` | cite audit MATRIX | gemma3; ≠ K2 |

## Notes

- `models/` has no K2 weights; only on-disk K2 quant is F:\ Q4_K_M.
- RX 7800 XT reported `problem=31 healthy=0` this run; reject reason was host RAM, not GPU.
- Do not invent PASS. `PROMOTE=0`. `TIP_CLIMB=HOLD`.
