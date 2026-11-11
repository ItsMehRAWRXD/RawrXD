# Nemotron 30B sustained row-8 baseline — 2026-10-20

Configuration: `DEEP2_QUANT_ROW_TILE=8`, `DEEP2_QUANT_Q6_SHARED_TILE=1`, `DEEP2_QUANT_REUSE_COMMANDS=1`; R9700; `nemotron-3.5-lightning-30b-Q4_K_M.gguf`; 64-token prompt; 128 generated tokens.

Both independent runs exited `0`, used the native GPU path, reported `cpu_calls=0`, and produced finite serial logits. Nemotron-H contains recurrent SSM blocks, so the speculative verifier is intentionally disabled: rollback of recurrent state would be unsound and the benchmark reports N/A for speculative stream agreement.

| Run | Prefill | Decode | Serial TPS |
| --- | ---: | ---: | ---: |
| R1 | 3875.2 ms | 5077.8 ms | 25.21 |
| R2 | 3863.4 ms | 5024.4 ms | 25.48 |
| Mean | 3869.3 ms | 5051.1 ms | 25.34 |

Receipts: `evidence/NEMOTRON30B_ROW8_128TOK_20261020/SPEC_BENCH_RECEIPT.txt` and `evidence/NEMOTRON30B_ROW8_128TOK_R2_20261020/SPEC_BENCH_RECEIPT.txt`.

This closes the short-run variance question and establishes a sustained 30B GPU baseline. It does not close the 40 TPS target: the measured mean is 63.4% of 40 TPS. S12 remains FAIL at 150 TPS. The next optimization should instrument SSM scan, expert routing, quantized projections, and fence waits separately before changing synchronization behavior.
