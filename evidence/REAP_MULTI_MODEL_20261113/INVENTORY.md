# REAP Multi-Model Inventory — 2026-11-13

PROMOTE=0 · CROSS_SHA_CREDIT=0 · NOT_RUN≠PASS · ORIGINAL_GGUF_INTACT=1

## Tooling (rebind; do not cross-credit)

| Binary | Path | SHA-256 |
|--------|------|---------|
| rawr-reap (pre-rebuild) | F:\rawrxd\build_reap\bin-msvc\rawr-reap.exe | EF3BB98DCE8C3AC373F9AE561E4C4751F9A37736A5E19CD6256B3A9A425F845E |
| rawr.exe (live) | G:\~dev\rawrxd\build_ninja\bin\rawr.exe | BDC5E4A261086D24902B28E65A8AA213F30FED9FAC04D3C811D55FCDAB0F517B |

Note: user hint ECB45BC9… does **not** match live rawr.exe (BDC5E4A2…). CROSS_SHA_CREDIT=0.

## Local GGUF / Ollama roots

| Root | Present |
|------|---------|
| F:\OllamaModels | YES (canonical; F:\ollamamodels same tree) |
| G:\~ | MISSING |
| F:\rawrxd / G:\~dev\rawrxd | product trees (evidence + builds) |

## Priority inventory (Batch 01)

| Model | Pri | Class | Arch (caps) | Shards | Bytes | GiB | L / experts / top-k | Layout | Present |
|-------|-----|-------|-------------|--------|-------|-----|---------------------|--------|---------|
| MiniMax-M2.7-Q4_K_M | P0 | MoE | minimax-m2 | 3 | 138342384448 | 128.84 | 62 / 256 / 8 | deepseek_triplet | YES |
| Kimi-K2-Instruct-0905-Q4_K_M | P0 | MoE | deepseek2 | 13 | 621245224864 | 578.58 | (hist retain-8/149) | MLA/MoE | YES |
| Qwen3.6-35B-A3B-Q4_K_M | P1 | MoE | qwen35moe | 1 | 21166757728 | 19.71 | MoE (logical_experts=10240) | expert tensors | YES |
| DeepSeek-R1-Q4_K_M | P1 | MoE | deepseek2 | 11 | 404430188064 | 376.65 | MoE (logical_experts=14848) | expert tensors | YES |
| Qwen3-Next 80B (ollama) | P1 | UNKNOWN | (blob) | 1+meta | 50351320736 | 46.89 | ollama library/qwen3-next/80b | blob | YES blob |
| GPT-OSS 120B (ollama) | P1 | UNKNOWN | (blob) | 1+meta | 65369799840 | 60.88 | ollama library/gpt-oss/120b | blob | YES blob |
| Laguna S 2.1 (ollama) | P2 | UNKNOWN | laguna (hist) | 1+meta | 96031829760 | 89.44 | L=48 hist; attn geom FAIL hist | blob | YES blob |
| Qwen3.8-27B-AD-Q4_K_M | CTRL | DENSE | qwen35 | 1 | 17120781792 | 15.94 | dense (expert_tensors=0) | dense | YES |
| Qwen3.8-27B-Q4_K_M | CTRL | — | — | 0 | 0 | 0 | dir empty (.cache only) | — | NO local GGUF |
| Qwen2.5-Coder-14B-Q8_0 | CTRL | DENSE | qwen2 | 1 | 15701597632 | 14.62 | dense | dense | YES |
| GLM-4.7-Flash-Q4_K_M | P2 | MoE | deepseek2 | 1 | 18132721120 | 16.89 | MoE (logical_experts=2944) | expert tensors | YES |
| Qwen3.8-Flash-Next-AD-IQ1_M | P1 | MoE* | qwen4exp | 2 | 84930920928 | 79.10 | expert_tensors=144 | qwen4exp | YES |

\* Dense ≠ MoE expert prune. Control dense models: classify only; no expert REAP.

## Byte accounting (inspect)

| Model | tensors | expert_tensors | expert_bytes | non_expert (derived) |
|-------|---------|----------------|--------------|----------------------|
| MiniMax-M2.7 | 809 | 186 | 135725580288 | 2616804160 |
| Kimi-K2-0905 | 1096 | 180 | 612907352064 | ~8.3e9 |
| DeepSeek-R1 | 1025 | 174 | 393983557632 | ~10.4e9 |
| Qwen3.6-35B-A3B | 733 | 120 | 19503513600 | ~1.66e9 |
| Qwen3.8-27B-AD | 866 | 0 | 0 | 17120781792 |
| Qwen2.5-Coder | 579 | 0 | 0 | 15701597632 |

## SHA-256

See MANIFEST_SHA256.json (background hash of all priority shards; may be IN_PROGRESS).

## Caps notes

- rawr-reap capabilities: MiniMax = architecture_runtime_not_supported:minimax-m2 (REAP transform gate). Runtime path is Deep2 standard multi-shard bind, not K2 MLA.
- Qwen3.8-27B non-AD local GGUF missing; use AD as dense control.
