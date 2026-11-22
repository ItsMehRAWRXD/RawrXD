# Architecture reconciliation — 2026-11-22

## GGUF header parse (authoritative)
File: `F:\OllamaModels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M\Kimi-K2-Instruct-0905-Q4_K_M-00001-of-00013.gguf`
```
magic=GGUF version=3 tensor_count=98 kv_count=63
general.architecture = deepseek2
general.name         = Kimi-K2-Instruct-0905
general.size_label   = 384x14B
deepseek2.block_count         = 61
deepseek2.expert_count        = 384
deepseek2.expert_used_count   = 8
deepseek2.expert_shared_count = 1
deepseek2.expert_gating_func  = 2
```

## Two distinct models
| Model | Architecture | Blocks | Experts | Runtime |
| --- | --- | --- | --- | --- |
| **Kimi K2** | `deepseek2` | 61 | 384 (top-8) | **Executable** |
| **Inkling** | `inkling2_loop` / `inkling2v` | 24 | 128 | **NOT executable** (llama-server/Ollama 0.40.17 reject it) |

## Consequences
- R01/R02 "inkling2_loop / 48 visits / 3 passes over blocks 6–18" apply to **Inkling**, not Kimi K2.
- For Kimi K2 (deepseek2): `visit_multiplier = 1` for all tensors.
- For Inkling: `visit_multiplier = loopCount` for blocks in [loopStart, loopEnd].
- REAP must not rewrite/prune Inkling until a compatible runtime generates successfully (`INKLING_EXECUTION=FAIL`, `REPLAY_CORRUPTION=NOT_ESTABLISHED`).

## R02 (corrected) parameters
- Kimi K2: 61 blocks, 384 experts, top-8, `visit_multiplier=1`, prunable = `ffn_*_exps` tensors.
- Inkling: 24 blocks, 128 experts, `visit_multiplier=loopCount` on the loop range.
- `source_sha256` must be recorded per model.