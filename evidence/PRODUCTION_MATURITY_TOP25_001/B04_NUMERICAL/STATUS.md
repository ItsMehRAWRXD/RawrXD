# B04 MiniMax numerical / tokenizer parity

`PROMOTE=0` · `CERTIFIED=0` · `CROSS_SHA_CREDIT=0`

## Controlling EXE

`EXE_SHA256.txt` = `95DA21A3B7FB3CF78AD702B5008CD907AD7516494ED338097CB2803DB3A2B980`
(post `add_bos=false` + `token_type` atomic encode)

Historical baseline (layout A/B only; do not credit PASS):
`B00554BFF1ED4EBCD249EF5E9F2137421B999739758A0C47C4C1F4C5D04F1246`

## B04-01 / B04-04 Tokenizer parity (RAW)

| Side | Prompt | IDs |
|------|--------|-----|
| llama-tokenize | `Hello` | `[19739]` |
| Deep2 `RAWRXD_RAW_PROMPT=1` after fix | `Hello` | `[19739]` (`prompt_tokens=1`) |
| Deep2 **before** fix | `Hello` | `[200034, 19739]` (`prompt_tokens=2`) |

`FIRST_DIVERGENT_OP` (tokenizer/policy): **ADD_BOS_DEFAULT**
- llama.cpp `llama-vocab.cpp`: `add_bos = false` until KV overrides
- Deep2 `GGUFTokenizerBundle::addBos` was `true` when KV absent
- MiniMax GGUF omits `tokenizer.ggml.add_bos_token`
- Fix landed: default `addBos=false` (+ CanonicalTokenizer)

Also landed: load `tokenizer.ggml.token_type`; CONTROL(3)/USER_DEFINED(4)
atoms (`]~b]`, `]~!b[`, `[e~[`, `<think>`, …) stay atomic in `BPETokenizer::Encode`.
Witness: `specials=54 token_types=200064 gpt2=1`.

## B04-04 Chat prompt IDs (reference)

Rendered MiniMax (Deep2 `formatMiniMax` bytes, no BOM):

`llama-tokenize` → 39 ids starting
`[200034, 200019, 28463, 10, …, 19739, 200020, 10, 200019, 1361, 10, 200050, 10]`

Deep2 templated encode dump vs this list = NEXT (chat smoke).

## B04-02 Layer digests (Deep2 only — ref blocked)

RAW Hello, retain-256, `RAWRXD_STAGE_DIGEST=1` (`deep2_raw_nobos.*`):

| Stage | n | max_abs | note |
|-------|---|---------|------|
| PROMPT_EMBED pos0 | 3072 | 8.66e-2 | Hello embed |
| Q_PRE_ROPE_0 | 6144 | 9.04 | |
| V_0 | 1024 | 12.95 | type mix Q4_K/Q6_K path |
| ATTN_PRE_O_0 | 6144 | 12.95 | |
| ATTN_OUT_0 | 3072 | **761** | **>50× jump vs PRE_O — suspect wo/Q6_K or layout** |
| ARGMAX pos1 | — | id=88094 `uncurkan` | semantic FAIL |

## B04-05 Reference numerical

`REFERENCE_TENSOR_PARITY=REFERENCE_BLOCKED`

`C:\llama.cpp\...\llama-cli.exe` failed allocating ~107 GiB `CPU_REPACK` for full MiniMax.
Tokenizer-only stick remains available via `llama-tokenize.exe`.
Attempting `llama-direct` completion with `-ngl` (see `ref_hello_direct.*`).

## Semantic (RAW R256, post add_bos fix)

`output="uncurkan\n\n\n… "` · still **SEMANTIC_QUALITY=FAIL**

R256 negative result stands: full experts ≠ coherence.

## Next gate

`MINIMAX_ATTN_Q6K_V_OR_EXPERT_DOWN_OR_LMHEAD`
1. Unblock llama.cpp mmap/partial-offload OR host-side Q6_K `wo` / `output.weight` unit parity on real tensors
2. Chat encode ID dump vs 39-id reference
3. Fix first **tensor** divergence after ID-matched inputs (ATTN_OUT jump is leading suspect)

```
MINIMAX_GATE=NUMERICAL_AND_SEMANTIC
TOKENIZER_RAW_IDS=PASS
ADD_BOS_POLICY=FIXED
TOKEN_TYPE_ATOMIC=FIXED
REFERENCE_TENSOR_PARITY=REFERENCE_BLOCKED
FIRST_DIVERGENT_OP=ADD_BOS_DEFAULT (closed); NEXT_TENSOR=ATTN_OUT_OR_Q6K_WO
SEMANTIC_QUALITY=FAIL
PROMOTE=0
CERTIFIED=0
CROSS_SHA_CREDIT=0
```

## Reference load attempts (2026-11-13)

| Attempt | Result |
|---------|--------|
| llama-cli CPU default | FAIL ~107GiB CPU_REPACK alloc |
| llama-direct -ngl 20 | FAIL VRAM OOM |
| llama-direct -cmoe -ngl 4 --no-repack | ~43GiB working set; no gen text before kill |
| llama-direct -ngl 0 --no-repack | incomplete / killed |

REFERENCE_TENSOR_PARITY=REFERENCE_BLOCKED (tokenizer stick only).
