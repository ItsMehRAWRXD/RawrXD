# RawrXD production maturity scoreboard (fail-closed)

**ASOF:** 2026-11-13 · **PROMOTE=0** · **CERTIFIED=0** · **RELEASE=HELD** · **TIP_CLIMB=HOLD**

Latest MiniMax Batch01 EXE: `4B19643C1DA9B61288DC804A3928C9FCAA70A128454A509ED7C8134B1DF8ECF7` (`batch01_raw_hello2.*`; prenorm SEALED; FDO=Q_LINEAR_0)

Prior NeoX L2 EXE: `BC1583B773D6DC28109D7F64AD43844E2F97E1FC2446E8E3F828BC73736DE3D5` (`minimax_neox_l2gate.*`)

Prior retain-256 theta EXE: `EA4E20229633F9671F1B43620A3B6F27D21667F57A784B06830986E3E2B94113` (`minimax_r256_theta_moe.*`)

| Score | Status | Measured basis |
|-------|--------|----------------|
| CLI_PCT | **51** · CLI_COMPLETE=**0** | 11-cat floor mean (`VALUATION_CLI.txt`); zip/help+status+dense TPS raised. ≠ certified. |
| GUI_PCT | **32** · GUI_COMPLETE=**0** | EXE_RELINK tip `6754616E…` 332MB; EXE_ABSORB_GPU_DEFAULT=0; HWND=NOT_RUN; no invent climb. |
| COMPOSITE_PCT | **32** | `min(51,32)` fail-closed — rollup `VALUATION_SCOREBOARD.txt` |
| CLI_MATURITY | **Not certified** | Dense r17 GEN=8 HOST_DECODE=0; MATCH=0; chat GEN OPEN; agent status EXIT=0. |
| GUI_MATURITY | **Not certified** | Unsuffixed tip MISSING; stub 5647F05E REJECT; FOUR_PANEL NOT_RUN; EXE_ABSORB_GPU_DEFAULT=0. |
| TOP25_PARITY | **MEASURED_PARTIAL** | Ops audited (`TOP25_RECOGNITION_OPS_001` + `TOP25_OPS_001`). No sealed peer IDE/perf parity. ≠ certified. |
| TOP25_RECOGNITION | **NOT_READY** | DRAFT_SHA_BOUND (v14.7.3/v1.0.0 zips); NOT_PUBLISHED; clean-VM ABSENT; PROMOTE=0. |
| COMMERCIAL_VALUATION | **ESTIMATE** `$75M–$125M` | CERTIFIED=0. Stale Aug-2026 ≠ cert. |

## Competitive throughput (citations only — not a ranking)

| Witness | Measured | Not a claim of |
|---------|----------|----------------|
| `cli_llama32_smoke_post.err.txt` | Prefill 3.21 tok/s; Decode 3.19 tok/s; E2E 0.46 TPS | Top-25 / MoE / GPU champion |
| `REAP_ALL_16GB_001` QUALITY_CURVE / COMPARISON_MATRIX | MiniMax decode ≈0.32–0.37 tok/s on cited arms | Semantic PASS or peer win |
| `REAP_ALL_16GB_001/INDEP_SMOKE_SEAL.txt` | MiniMax REAP16 CLEAN_EXIT + 48 tokens; SEMANTIC_COHERENCE=FAIL | Production REAP ship |
| `DEEP2_671_STREAM_TPS_35_50_001/STATUS.txt` | TARGET_35_50_TPS=UNMINTED; DECODE_TPS=NOT_RUN | 35–50 TPS achieved |
| `COMPETITIVE_BENCH_001/smoke_runs/*.meta` | Help/smoke meta; EXIT empty | Ollama/vLLM head-to-head |

`PRODUCT_FLOOR_TPS=5.000` in stderr is a floor constant, not a measured result.

## P0 gates

| Gate | Result | Witness |
|------|--------|---------|
| Dense unload | **PASS** | `cli_llama32_smoke_post.*` |
| MiniMax sigmoid gating | **RUNTIME_REACHED** | `RE_MINIMAX_SIGMOID_GATE_001` |
| MiniMax EH_to_HE | **NOT root cause** | `RE_MINIMAX_LAYOUT_CHAT_001.txt` |
| MiniMax Forced chat vs RAW | **NOT sole cause** | same RE file |
| MiniMax flat QK-norm | **SOURCE_WIRED** | `RE_MINIMAX_QKNORM_FLAT_001` |
| MiniMax RoPE Neox | **PAIR_MATCH + L2_OK** | ggml rotate_pairs MATCH; in-RoPE `B03_ROPE_L2_OK` rat=1 — `RE_MINIMAX_NEOX_WO_Q6K_001` |
| MiniMax Q_PRE/POST L2 | **FALSE_LEAD** | B04 dumps were pre-QK-norm labeled PRE — `RE_MINIMAX_QPRE_IS_PRENORM_001` |
| MiniMax wo cols=6144 | **MATCH** | bind+LinearW headScratch; not trunc→3072 — `RE_MINIMAX_ROPE_WO_LMHEAD_001` |
| MiniMax lm_head Q6_K geom | **MATCH** | rows=200064 cols=3072; gemv_q6_k_scalar registered — same + NEOX_WO_Q6K RE |
| MiniMax ropeTheta=5e6 | **MEASURED MATCH** | `B03_ROPE_THETA=5000000` — `RE_MINIMAX_MOE_ROPE_Q4K_001.txt` |
| MiniMax MoE 3D expert axis | **MATCH** | last-dim experts; bytes=9179136 — same RE |
| MiniMax Forced prompt specials | **PASS** | `RE_MINIMAX_PROMPT_TOKENS_001.txt` (N=39; `]~b]`+role) |
| MiniMax forward residual | **MATCH** | attn→+res→ffn_norm→moe→+res |
| MiniMax STREAM_CORRECTNESS | **NOT_PASS** | backtick runs (`2765:11.62`) |
| MiniMax retain-256 quality | **RUNTIME_REACHED / NOT_PASS** | `minimax_r256_quality.*` + `minimax_r256_theta_moe.*` |
| MiniMax attn softmax scale | **MATCH** | `1/sqrt(128)` Deep2==llama — `RE_MINIMAX_SOFTMAX_SWIGLU_LMHEAD_001` |
| MiniMax MoE SwiGLU order | **MATCH** | silu(gate)*up separate gate/up/down — same RE |
| MiniMax Q_LINEAR_0 Q4_K×Q8_K | **SEALED** | offline GEMV maxdiff=2.24e-08; FP32 1.25e-3=false lead — `RE_MINIMAX_QLINEAR0_SEAL_001` |
| MiniMax lm_head vs llama FNV | **REFERENCE_BLOCKED** | llama-direct CPU TIMEOUT (walltime/load); DLL OK |
| Kimi COHERENT_USEFUL | **OPEN** | `QUALITY_149.txt` |
| GUI four-panel | **FAIL_CLOSED** | `FOUR_PANEL_COMPLETION_001` |

## RE notes (this turn)

- **Q_LINEAR_0 SEALED:** offline Q4_K×Q8_K GEMV maxdiff=2.24e-08 (`compare_q_linear_q8k.rerun`) — `RE_MINIMAX_QLINEAR0_SEAL_001`. FP32-dequant 1.25e-3 = **false lead** (wrong authority). **PATCH=N**.
- **AL13 gate_inp:** verify-axis false FAIL closed; export OK; OVERALL PASS after `_al13_verify.py` row_E0 fix.
- Softmax/SwiGLU formula MATCH; lm_head FNV still REFERENCE_BLOCKED — prior RE.
- **PRENORM SEALED:** ATTN_NORM_0 maxdiff=2.98e-08 — Batch01.
- **Semantic progress ≠ PASS:** RAW Hello → `.\n\nThe first`; retain-256 still backticks.
- Prior closed: NeoX L2, Q4_K block, KV, embed, QK-norm, wo/lm_head, Softmax/SwiGLU.

## Next executable gate

`FFN_DOWN_5_CANDIDATE` / dump layers 3..8 (`B3_FIRST_BAD phase=FFN_DOWN pos=5`). Cross-link AL09 tok4 L17 / AL10_AL14. llama Forced STAGE_DIGEST still REFERENCE_BLOCKED.

`PROMOTE=0` · `TIP_CLIMB=HOLD` · `NOT_RUN!=PASS`
