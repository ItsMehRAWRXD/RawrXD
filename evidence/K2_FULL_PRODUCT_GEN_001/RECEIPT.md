# K2_FULL_PRODUCT_GEN_001 RECEIPT

## Definition (in-repo)

`K2_FULL_PRODUCT_GENERATION` = TOP15 breakthrough **#04** / CLOSEST **#3**:
Win32IDE/HeadlessIDE product path (`ProductOpenSession` → `ProductRun` /
`Deep2Engine::generateStream`) on **Kimi-K2-Instruct-0905** multi-shard GGUF,
on the sealed post-Camellia EXE — not TinyLlama tetrad, not gemma3 multi-family,
not `deep2_benchmark` MoE probes, not `VWA_K2_FULL_E2E_001` criteria closure.

Cites: `TOP15_BREAKTHROUGH_ORDER.txt`, `POST_SCHEDULER_PROMOTE_REQ_001`
MATRIX S18 / LAW, `THREE_AUTHORITY_SPLIT.txt`.

## Sealed EXE

| Field | Value |
|------|------|
| Path | `G:\~dev\rawrxd\build_win32ide_link001\bin\RawrXD-Win32IDE.exe` |
| Size | 331629056 |
| SHA256 | `89BFD6142CEE7A6AA537DF0297014E240C7CC55B142C230521527914469F8630` |
| Pre-run match | Yes |
| Post-run sealed | Yes (untouched) |
| Rebuild | No |

## Model (strongest local K2)

| Field | Value |
|------|------|
| Path | `F:\OllamaModels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M\Kimi-K2-Instruct-0905-Q4_K_M-00001-of-00013.gguf` |
| Under `rawrxd/models/` | **No** Kimi/K2 GGUF present |
| Shards | 13/13 indexed |
| Tensors | 1096 |
| ARCH | deepseek2 |
| Layers / experts | 61 / 384 (expertsPerToken=8) |
| MLA | yes (qLora=1536 kvLora=512) |

## Invocation (no rebuild)

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
| Start local | 2026-10-28 04:29:42.10 |
| End local | 2026-10-28 04:29:53.09 |
| Index open | Yes (13 shards, tokenizer vocab=163840) |
| AUTO_BACKEND weights estimate | 44152 MB |
| Host RAM / commit | 41447 MB / 33170 MB |
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
| SHA_MATCH | PASS | Pre+post `89BFD614…` |
| K2_MODEL_PRESENT | PASS (path) | F:\ OllamaModels 13-shard Q4_K_M |
| K2_INDEX | OBSERVED | 1096 tensors / 13 shards |
| PRODUCT_GENERATION | **BLOCKED** | AUTO_BACKEND OOM: weights 44152MB > host RAM 41447MB |
| GENERATED_TOKENS>0 | FAIL | actual 0 |
| K2_FULL_PRODUCT_GENERATION | **BLOCKED_OOM** | ≠ PASS; ≠ NOT_RUN (path exercised to BACKEND_SELECT) |
| PROMOTE | **0** | Always |
| TIP_CLIMB | HOLD | Unchanged |
| CERTIFIED | 0 | Unchanged |

## Sibling cross-cite (untouched)

| Seal | Disposition | Note |
|------|-------------|------|
| `TOKEN64_PRODUCT_RUN_001` | **BLOCKED_CLAMP** | TinyLlama; CLI 64 → EFFECTIVE 8; GENERATED_TOKENS=8; same EXE SHA |
| `LIVE_TETRAD_POST_CAMELLIA_001` | untouched | TinyLlama tetrad; 8 tokens |
| `MULTI_FAMILY_PRODUCT_001` | untouched | gemma3; 8 tokens |

## Notes

- `models/` has no K2 weights; strongest available K2 is the F:\ 13-shard Q4_K_M set.
- RX 7800 XT reported `problem=31 healthy=0` this run; reject reason was host RAM, not GPU.
- Historical `DEEP2_KIMI_K2_001` MoE probes used `deep2_benchmark.exe` (different EXE) — not this product seal.
- Do not invent PASS. `PROMOTE=0`.
