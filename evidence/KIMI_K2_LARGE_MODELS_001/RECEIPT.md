# KIMI_K2_LARGE_MODELS_001 RECEIPT

```text
SEAL=KIMI_K2_LARGE_MODELS_001
WS=WS6 / RAWRXD_ALL_BACKENDS_COMPLETE_001
PROMOTE=0 CERTIFIED=0 CROSS_SHA_CREDIT=0
```

## Tip primary (EXE_SHA=6754616E…)

| Track | Disposition | Evidence |
|-------|-------------|----------|
| K2 multi-shard index | **13/13** | `runs/K2_MULTISHARD_R3` MULTISHARD_SHARDS_INDEXED |
| K2 generation | **BLOCKED_OOM** | PRODUCT_OPEN=FAIL NOT_STREAMABLE; OPEN_WORKING_SET_ACQUIRABLE=0; TOK=0; BACKEND_SELECT not reached on tip |
| 70B deepseek-r1 | **FAIL_SEH** | PRODUCT_DEEP2_OPEN_SEH CODE=0xC0000005 after INIT_OK; TOK=0 |
| 80B qwen3-next | **BLOCKED_OOM** (R1) / FAIL_SEH (R3) | R1: Failed to allocate 301989888B `blk.18.ffn_up_exps.weight`; TOK=0 |
| 120B gpt-oss | **BLOCKED_OOM** (R1) / FAIL_SEH (R3) | R1: Failed to allocate 23592960B `blk.13.attn_q.weight`; TOK=0 |

## RELATED (no CROSS_SHA credit)

| Cite | Disposition |
|------|-------------|
| `K2_TIP005_RELATED` EXE=D9589D9A… | BLOCKED_OOM FAILED_STAGE=BACKEND_SELECT weights=44152MB hostRAM=41797MB decision=Reject Insufficient host memory |
| `K2_D41B_OR_SCOPE_EXCEPTION_001` | prior BACKEND_SELECT BLOCKED_OOM (untouched) |
| `K2_338E_OR_SCOPE_EXCEPTION_001` | prior BACKEND_SELECT BLOCKED_OOM (untouched) |

## Law application

```text
BLOCKED_OOM != PASS
FAIL_SEH != PASS
MULTISHARD_INDEX != GENERATION_PASS
TIP005_BACKEND_SELECT != tip_6754616E_credit
NOT_RUN != PASS (cleared by exercise)
```

## Models exercised

- K2: `F:\OllamaModels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M\…-00001-of-00013.gguf` (13 shards)
- 70B: `F:\OllamaModels\_rawrxd_ws6_links\deepseek-r1-70b.gguf` ← ollama blob hardlink
- 80B: `F:\OllamaModels\_rawrxd_ws6_links\qwen3-next-80b.gguf`
- 120B: `F:\OllamaModels\_rawrxd_ws6_links\gpt-oss-120b.gguf`
