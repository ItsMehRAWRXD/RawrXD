# Nemotron 30B row-8/Q6 per-op timing receipt — 2026-10-20

## Purpose

Profile the sustained native Nemotron-H decode path before selecting the next optimization target. This is an 8-token diagnostic run using the already validated row-8 Q6 command-reuse route.

## Workload and controls

- Model: `F:/rawrxd/models/nemotron-3.5-lightning-30b-Q4_K_M.gguf`
- Architecture: `nemotron_h_moe`; 53 layers; hidden 2688; 32 attention heads; vocabulary 131072; context 1048576
- GPU: AMD Radeon AI PRO R9700
- Decode workload: 64-token prompt, 8 generated tokens, code prompt
- Route: `DEEP2_QUANT_ROW_TILE=8`, `DEEP2_QUANT_Q6_SHARED_TILE=1`, `DEEP2_QUANT_REUSE_COMMANDS=1`
- Timing: `DEEP2_OP_TIMING=1`
- Process exit: `0`

## Result

- Serial prefill: 3805.9 ms
- Serial decode: 284.2 ms for 8 tokens (~28.15 TPS in this diagnostic run)
- GPU calls: 5364
- CPU calls: 0
- Serial logits: finite; benchmark verdict `PASS`
- Speculative arm: not applicable because recurrent SSM state cannot be rolled back safely

The per-token trace records `op=10` (`SsmScan`) at 21.505–22.435 ms for positions 64–70, while `op=9` (`LmHead`) is 3.359–4.218 ms and `batch_flush_ms` is 8.836–9.932 ms. The SSM scan is therefore the dominant measured decode operation; fence/flush work is material but is not the first optimization target.

## Evidence

Raw output and receipt: `evidence/NEMOTRON30B_ROW8_TIMING_20261020/`.

This receipt identifies a bottleneck and does not claim a 40 TPS or 150 TPS pass. The sustained 128-token baseline remains 25.34 TPS across two independent runs (`evidence/NEMOTRON30B_ROW8_SUSTAINED_RECEIPT_20261020.md`).
