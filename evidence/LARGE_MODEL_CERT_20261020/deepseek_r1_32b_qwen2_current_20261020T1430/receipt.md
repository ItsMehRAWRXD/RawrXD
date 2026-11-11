# DeepSeek-R1 Distill Qwen 32B native smoke receipt — 2026-10-20

Status: **PASS (bounded native GPU smoke)**

- Model: local Ollama blob for `deepseek-r1:32b`, `DeepSeek R1 Distill Qwen 32B`
- Path: `F:\OllamaModels\blobs\sha256-6150cb382311b69f09cc0f9a1b69fc029cbd742b66bb8ec531aa5ecf5c613e93`
- Size: 19,851,335,552 bytes
- GGUF architecture: `qwen2`; 64 blocks; embedding 5120; 40 attention heads;
  8 KV heads; no MoE experts
- Executable SHA-256: `951421087FADACCCC43C1DDDEC7B503F8EF52C092EFC9D79F7BA1BAFC1BDAF88`
- Git base at launch: `ade64a9682c00e95987261a561d0dbeaf7762adf`
- Prompt: `1 4019 1058 1032`; generated positions: 2; device: R9700 (index 0)

The current universal GGUF graph ingested and bound 899 operations, then ran
all four prompt positions and two decode positions successfully:

- finite logits: yes; GPU complete: yes
- CPU calls: 0; fallback: none
- decode wall: 5,724.7 ms; decode TPS: 0.175
- prefill wall: 36,392.9 ms; prefill TPS: 0.110
- GPU calls: 2,245; submissions/waits: 2,694 / 2,694
- device peak: 18,504.9 MB; host-RAM peak: 23,987.1 MB
- output stream: `7596 287`

This certifies a bounded native execution path and zero CPU fallback for this
32B Qwen2-family model. It is not an independent llama.cpp full-logit parity
receipt, sustained throughput certification, multi-GPU evidence, or a claim on
the 150 TPS target.
