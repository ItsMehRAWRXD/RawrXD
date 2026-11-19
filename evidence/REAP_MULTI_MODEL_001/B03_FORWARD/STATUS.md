# B03 MiniMax — quality gate (OPEN) · MoE plumbing CLOSED

`PROMOTE=0` · `CERTIFIED=0` · `REFERENCE_PARITY=NOT_ESTABLISHED` · `CROSS_SHA_CREDIT=0`

Controlling smoke: `minimax_b03x.*` · EXE `EXE_SHA256.txt` =
`ED81A5B5D5B154881792116B79CFAF4052F035EE76EC1E3D346F8DBB8199B54F`

## Measured (b03x)

| Gate | Result |
|------|--------|
| ChatTemplate | Forced **minimax** (`]~b]user` / `]~b]ai`) |
| `expert_gating_func` | **2 = sigmoid** (`B03_MOE_CFG` / `B03_MOE_GATE`) |
| `exp_probs_b` | Bound + injected (`B03_MOE_BIAS_INJECT E=256`) |
| Cross-shard expert assemble | **OK** — `blk.21.ffn_up_exps` on shard1, gate/down on shard0 |
| `experts_selected` / `executed` | **26288 / 26288** · `parity=1` |
| `acquire_ok` / `acquire_fail` | **26288 / 0** |
| L0 QKV maxAbs (prior) | finite O(10) after QK-norm + partial RoPE |
| Decoded 4-tok | `false廷.false` — **QUALITY OPEN** |
| Physical REAP | retain-29 · `writer_invoked=false` |

## Reverse-engineered defects closed this batch

1. **Cross-shard MoE split** — MiniMax places `ffn_up_exps` for boundary layers
   (L21, L44) on the *next* shard from gate/down. Single-loader `LoadExpert`
   always failed → `AcquireCrossShard` assembles gate/up/down across loaders.
2. **Sigmoid + `exp_probs_b`** — GGUF `expert_gating_func=2`; bias tensor now
   dumped/validated and injected before Route.
3. **REAP + bias resurrection** — masking logits to `-inf` then adding
   `exp_probs_b` re-selected pruned experts (IDs ≥29). Choice scores are now
   re-masked after bias.

## Still OPEN (quality)

- Generated text remains incoherent under retain-29 REAP bank.
- Next RE targets: (a) encode dump of MiniMax specials vs GPT-2 BPE merges,
  (b) smoke with larger/no REAP bank for semantic baseline,
  (c) reference parity vs llama.cpp MiniMax path on L0 activations.

```
MOE_PARITY=1
ACQUIRE_FAIL=0
MINIMAX_QUALITY=OPEN
REFERENCE_PARITY=NOT_ESTABLISHED
PROMOTE=0
CERTIFIED=0
```
