# RawrXD production maturity scoreboard (fail-closed)

**ASOF:** 2026-11-13 · **PROMOTE=0** · **CERTIFIED=0** · **RELEASE=HELD** · **TIP_CLIMB=HOLD**

Latest MiniMax Batch01 EXE: `4B19643C1DA9B61288DC804A3928C9FCAA70A128454A509ED7C8134B1DF8ECF7` (`batch01_raw_hello2.*`; prenorm SEALED; FDO=Q_LINEAR_0)

Prior NeoX L2 EXE: `BC1583B773D6DC28109D7F64AD43844E2F97E1FC2446E8E3F828BC73736DE3D5` (`minimax_neox_l2gate.*`)

Prior retain-256 theta EXE: `EA4E20229633F9671F1B43620A3B6F27D21667F57A784B06830986E3E2B94113` (`minimax_r256_theta_moe.*`)

| Score | Status | Measured basis |
|-------|--------|----------------|
| CLI_MATURITY | **Not certified** | Dense unload PASS (`391D1F45…`). MiniMax semantic NOT_PASS. |
| GUI_MATURITY | **Not certified** | Four-panel FAIL_CLOSED. |
| TOP25_PARITY | **Unmeasured** | — |
| COMMERCIAL_VALUATION | **Unverified** | Stale Aug-2026 ≠ cert. |

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
| Kimi COHERENT_USEFUL | **OPEN** | `QUALITY_149.txt` |
| GUI four-panel | **FAIL_CLOSED** | `FOUR_PANEL_COMPLETION_001` |

## RE notes (this turn)

- **PRENORM SEALED:** `B03_PRENORM_MATERIALIZE` for shard+non-MLA; ATTN_NORM_0 maxdiff=2.98e-08 vs ggml — `RE_MINIMAX_BATCH01_PRENORM_QLINEAR_001`.
- **FIRST_DIVERGENT_OP=Q_LINEAR_0:** Q4_K GEMV maxdiff≈1.25e-3 (K/V same class). Q_NORM/K_NORM OK given Deep Q/K. No RoPE/attn/MoE patches yet.
- **Semantic progress ≠ PASS:** RAW Hello → `.\n\nThe first` (was `olisian¶¶¶`).
- Prior closed: NeoX L2, Q4_K block, KV ownership, embed MATCH, QK-norm flat, wo/lm_head geom.

## Next executable gate

Seal `Q_LINEAR_0` vs linked-ggml / llama STAGE_DIGEST (same RAW Hello). Then continue Q_ROPE→ATTN chain. No speculative MoE/attn edits.

`PROMOTE=0` · `TIP_CLIMB=HOLD` · `NOT_RUN!=PASS`
