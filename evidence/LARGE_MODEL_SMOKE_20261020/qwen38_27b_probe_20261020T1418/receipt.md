# Qwen3.8 27B native smoke receipt — 2026-10-20

Status: **BLOCKED (graph wiring)**

This was a controlled, read-only native Vulkan smoke using the current-source
`deep2_bench_tps.exe` on the R9700. The model was the exact local Ollama GGUF
blob resolved from `qwen3.8:27b`:

- Path: `F:\OllamaModels\blobs\sha256-f5f1dd8920d417aac2718b0bda3403da274301efdd6760b4f0f4b864ff2ad57d`
- Size: 16,810,714,464 bytes
- GGUF identity: `qwen35`, `Qwen3.8 27B 0814`, 65 blocks, embedding 5120,
  24 attention heads, 4 KV heads, 0 MoE experts
- Executable SHA-256: `951421087FADACCCC43C1DDDEC7B503F8EF52C092EFC9D79F7BA1BAFC1BDAF88`
- Git base at launch: `5cc3040b67ea25e0244b13e3363b0553c9a5a848`
- Prompt: `1 4019 1058 1032`; requested decode: 2 tokens; device: R9700 (index 0)

The GGUF ingested and bound 673 graph operations in 65.5 seconds. Execution
failed before the first logits row:

```
PREFILL_FAIL pos=0 err=residualadd: addend 'attn_proj' missing
exit code 1
```

No throughput, parity, or GPU-only result is claimed. The model's Qwen3.5
hybrid blocks contain `attn_qkv`, `attn_gate`, and SSM tensors; the active
universal graph does not yet emit a valid `attn_proj` producer for this mixer.
This is a genuine architecture-graph blocker, separate from the successful
Nemotron 30B Q4_K_M receipt. The original preflight, run log, and exit code are
retained beside this receipt.
