# S07 row-8 Q6 route and Nemotron 30B smoke receipt — 2026-10-20

## Build and artifact validation

- Release `deep2_spec_bench` rebuild: exit `0`.
- Shader compiler `scripts/compile_quant_row4_shaders.ps1`: exit `0`; it now compiles row-4 and row-8 regular/Q6 shared-tile SPIR-V artifacts.
- Executable SHA-256: `098AC5B2D2F4BA06D413AB9E1FE96C09B63E74C2D659AB278985A1AF88913061`.
- `quant_dot_row8_q6tile.spv` SHA-256: `7FF688E8101244722166801B1176725D4BBA9AA3FA11578D793972278F46EFB9`.

## Row-8 Q6 controlled comparison

Configuration: `DEEP2_QUANT_ROW_TILE=8`, `DEEP2_QUANT_Q6_SHARED_TILE=1`, `DEEP2_QUANT_REUSE_COMMANDS=1`, TinyLlama Q4_K_M, R9700, 128 generated tokens, gamma 4, repeat drafter.

The corrected row-8 shader uses eight 32-lane cohorts and loads all 54 aligned Q6 words per cohort. The command-reuse recorder now uses `QuantDotRowsPerWorkgroup()` too; this prevents redundant empty dispatch groups when replaying a row-8 command.

Receipt: `evidence/S07_Q6_ROW8_128_BOTH_R4_20261020/SPEC_BENCH_RECEIPT.txt` (exit `0`).

- Code: serial `31.55 TPS`, speculative `30.36 TPS`; 3/12 drafts accepted; streams identical; finite logits; CPU calls `0`.
- Prose: serial `29.47 TPS`, speculative `27.83 TPS`; 0/8 drafts accepted; streams identical; finite logits; CPU calls `0`.
- Verdict: benchmark correctness PASS (`6/6`), but S07 acceleration remains OPEN because speculative execution is slower and target work is not reduced.
- The wide dependency batch candidate was rejected: code serial `28.89 TPS`, speculative `28.22 TPS` (`evidence/S07_Q6_ROW8_128_CODE_WIDE_R1_20261020`).
- Spin polling did not establish a repeatable gain (`evidence/S07_Q6_ROW8_128_CODE_SPIN_R2_20261020`).

The earlier apparent 43–47 TPS row-8 readings were invalidated by incomplete Q6 shared-tile loads and are not used as certification evidence.

## Native Nemotron 30B smoke

Receipt: `evidence/NEMOTRON30B_ROW8_8TOK_20261020/SPEC_BENCH_RECEIPT.txt` (exit `0`).

- Model: `nemotron-3.5-lightning-30b-Q4_K_M.gguf`, architecture `nemotron_h_moe`, 53 layers, hidden 2688, 32 heads, vocab 131072, context 1048576.
- Workload: native GPU serial path, 8 generated tokens; recurrent SSM blocks correctly disable speculative rollback.
- Prefill `4054.1 ms`; decode `275.7 ms` for 8 tokens (~`29.02 TPS`); `gpu_calls=5364`, `cpu_calls=0`.
- Serial logits remained finite; no fallback was reported. Speculative fields are N/A by design for this recurrent graph.

## Certification state

- Row-8 Q6 route: correctness PASS, performance candidate only; no 40 TPS claim.
- TinyLlama sustained 40 TPS: OPEN.
- Nemotron 30B sustained 40 TPS: OPEN; this is an 8-token smoke, not a sustained certification.
- S07: OPEN until speculative target-forward savings and repeatable end-to-end speedup are demonstrated.
- S12: FAIL against the 150 TPS requirement.
