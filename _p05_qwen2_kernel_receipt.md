# P0.5 RECEIPT — DEEP2_QWEN2_CPU_CORRECTNESS_001 (Q4K kernel llama-parity) — 2026-09-28

## Root cause (two independent defects, both fixed)

1. **Nibble grouping in the Q4_K GEMV hot path.** The int-dot path
   (`quantize_row_q8_K` + `vec_dot_q4_K_q8_K`-style decode) used **16-lo + 16-hi
   sub-block grouping** with scale group `is = j/32` applied to both 16-value
   halves. llama.cpp `dequantize_row_q4_K` (ggml-quants.c, verbatim) is:
   - per 64-value chunk: scale pair `(is+0, is+1)` via `get_scale_min_k4`
   - 32 LOW nibbles `q[l] & 0xF` with `d1 = d*sc[is+0]`, `m1 = dmin*mn[is+0]`
   - 32 HIGH nibbles `q[l] >> 4` with `d2/m2` from `is+1`
   The engine's own *fallback* path (`unpack_q4_k_scales`, 32/32) was already
   llama-correct; the hot path was not.

2. **The regression gate certified the wrong reference.**
   `tests/q4k_vecdot_parity_gate.cpp`'s "canonical" dequant used the same wrong
   16/16 grouping, so `PARITY=PASS` (2.4e-6) was self-consistency, not llama
   parity. Gate reference rewritten to llama-verbatim semantics.

## Evidence chain (32B Qwen2.5-Coder-Instruct Q4_K_M, real GGUF bytes)

| Step | Result |
|---|---|
| Pre-fix top-10 (pos-0, 5-token prompt) | `47380 'xcc' :9.467, 82 's' :9.385, 53432 'xdd'` |
| llama.cpp adjudication (same model, temp 0) | `"The capital of France is Paris."` — greedy token `' Paris'` = **12095** |
| Post-fix oracle (fresh InferenceEngine.lib 18:00:21, oracle exe 18:00:44) | `SAMPLER_RESULT token=12095` |
| Post-fix top-1 margin | `12095:17.631` vs `1304:14.718` — decisive |
| Provenance | SRC edit 17:51:14 → obj 18:00:20 → lib 18:00:21 → exe 18:00:44 → run after |

Tokenizer separately verified: `TOK_PROBE=PASS`
(The=785, capital=6722, of=315, France=9625, is=374 — real Qwen2 BPE ids.)

## Binary-provenance lesson (recorded)

The first "rebuild" produced **identical logits to 9 decimals** because
`qwen2_oracle_gate.exe` links `ENGINE_LIB =
rawrxd/build_clean_n1/Release/InferenceEngine.lib` — a different build tree
from the one the earlier ad-hoc build touched. The exe mtime (17:22:10) was
older than the source edit (17:51:14). Fix: rebuild `RawrXD-InferenceEngine`
in `build_clean_n1` (obj 18:00:20), then the oracle target, then rerun.

## Also discovered during adjudication

- `blk.4.ffn_down.weight` is **Q6_K (type 14)**, not Q4_K — earlier receipts
  conflated it with the Q4K path. Q4K tensors at blk.4: attn_q/k/v-output/
  ffn_gate/ffn_up (type 12).
- GGUF axis order: `ne[0]` = contiguous per-row length (contraction axis for
  GEMV rows), `ne[1]` = row count.
- `Start-Process -ArgumentList` splits unquoted args with spaces: the oracle
  received `The` as the whole prompt (`PROMPT_TOKENS=1`); embedded quotes fix
  it (`PROMPT_TOKENS=5`).

## Gate status

```
GATE=DEEP2_QWEN2_CPU_CORRECTNESS_001
ORACLE_HARNESS=PASS
EMBED_PARITY_32B=PASS
Q6K_GEMV_PARITY=PASS (prior receipt; unchanged)
Q4K_GEMV_PARITY=PASS (gate reference now llama-verbatim)
32B_POSITION0_PREDICTION = 12095 ' Paris' == LLAMA_GREEDY_TOKEN
COHERENT_OUTPUT=PASS (first time)
VERDICT=PASS
```

Commit: 0309b5152 (model-correctness branch)