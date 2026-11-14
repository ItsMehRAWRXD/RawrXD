# K2_L5_P1_TIP_LOAD_001 RECEIPT

Lane **L5 P1** tip remasure for `RAWRXD_ALL_BACKENDS_COMPLETE_001` workstreams
**W09** (Kimi K2 multi-shard) and **W13** (large 70/80/120B).

```text
PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0
INVENT_PASS=0 NOT_RUN!=PASS CROSS_SHA_CREDIT=0
```

## Sealed EXE

| Field | Value |
|------|------|
| Path | `G:\~dev\rawrxd\bin\RawrXD-Win32IDE.exe` |
| Size | 332257792 |
| SHA256 | `6754616EA30A566423727F82513AC66D8241FDB73343F9CD7A440FF9D4E43431` |
| Pre/post match | Yes |

## K2 model (on-disk)

| Field | Value |
|------|------|
| Path | `F:\OllamaModels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M\Kimi-K2-Instruct-0905-Q4_K_M-00001-of-00013.gguf` |
| Quant | Q4_K_M only (13/13 shards present) |
| Index | MULTISHARD_SHARDS_INDEXED=13/13 · TENSORS=1096 |
| ARCH | deepseek2 · L=61 · experts=384 · expertsPerToken=8 · MLA yes |

## Invocation

```
LOCAL_ONLY=1 RAWRXD_HEADLESS=1 RAWRXD_DEEP2_ALLOW_ELASTIC=1
RawrXD-Win32IDE.exe --headless --local --no-server \
  --model <K2 shard00001> --prompt "Say hi in one word." \
  --max-tokens 8 --backend local --verbose
```

cwd: `G:\~dev\rawrxd\bin` · harness: `run_k2_l5.bat`

## Host

| Field | Value |
|------|------|
| RAM total / free (pre) | ~63093 MB / ~11475 MB |
| Wall | 2026-11-14 11:43:32 → 11:47:11 local |

## Disposition (fail-closed)

| Gate | Value |
|------|------|
| Multi-shard index | **OK** 13/13 |
| Engine init | reached (MULTIGPU DualStick armed) |
| PRODUCT_OPEN_PASS | **0** |
| SESSION_ENTER_PASS | 1 |
| PRODUCT_OPEN reason | **NOT_STREAMABLE** (`OPEN_WORKING_SET_ACQUIRABLE=0`) |
| GENERATED_TOKENS | **0** |
| TOKEN_COMMIT_PASS | 0 |
| HEADLESS_READY | 0 |
| CLEAN_EXIT | 1 (`TD=11`) |
| **PROMOTE** | **0** |

`INDEX_OPEN != PRODUCT_OPEN_PASS != GENERATED_TOKENS>0`.  
Not credited as gen PASS. Not CROSS_SHA vs historical `K2_FULL_PRODUCT_GEN_*`.

## W13 — 70/80/120B

| Field | Value |
|------|------|
| Status | **NOT_RUN** |
| Reason | **PATH_ABSENT** — no `*70B*`/`*80B*`/`*120B*`/`*72B*` GGUF dir under searched roots |
| Searched | `F:\ollamamodels`, `F:\OllamaModels`, `G:\~dev\rawrxd\models`, HF hub cache |

## Artifacts

`LAW.txt` `SUMMARY.txt` `RECEIPT.md` `RETURN_LINE.txt` `HASHES_PRE.txt`
`HASHES_POST.txt` `post_sha.txt` `run_meta_partial.txt` `run_k2_l5.bat`
`logs/raw_stdout.log` `logs/raw_stderr.log`
