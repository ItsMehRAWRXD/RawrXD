# Deep2 User-Input Demand-Load Hotpatch 001

This source drop replaces speculative/background model streaming with an execution-owned demand-load path for DeepSeek2 / DeepSeek-R1 style MoE GGUF models.

## Non-negotiable I/O rule

A model-weight read is legal only while the single scheduler owner has an open operation ticket containing the current token, layer, operation, and I/O reason. `d2u_tensor_read()` rejects every read that does not match that ticket.

There are no worker threads, async queues, predictive prefetch calls, I/O rings, mmap residency tricks, sequential-scan hints, or background submits in this source drop.

`BACKGROUND_SUBMITS` and `PREDICTIVE_LOADS` are authority counters and must remain zero.

## User-input-driven expert loading

DeepSeek-R1 routes each MoE layer from the hidden state produced by the actual user/prompt path. Only after router math returns the real Top-K may the expert operation load weights.

For packed expert tensors with GGUF dimensions `[input, output, expert]`, expert `e` is a contiguous quantized slice:

```
row_bytes     = (input / quant_block_values) * quant_block_bytes
expert_bytes  = row_bytes * output
expert_offset = e * expert_bytes
```

The first real route to `(layer,e)` loads exactly three slices: gate, up, and down. They are retained in the foreground expert hotset cache. Later prompt/decode hits reuse the quantized bytes without I/O. Cache pressure causes synchronous LRU eviction on the scheduler owner thread.

No unselected expert is touched.

## Included runtime path

```
user token id
  -> exact token-embedding row load
  -> for layer 0..60
       -> RMSNorm
       -> MLA absorb path
          q_a -> q_norm -> q_b
          kv_a -> kv_norm + RoPE key
          latent KV cache (KV-LoRA + PE only)
          q_nope * K_B -> latent attention space
          attention over latent cache
          latent result * V_B
          output projection + residual
       -> FFN norm
       -> dense FFN for leading dense blocks, OR
          deterministic router math
          -> actual Top-K
          -> exact routed expert demand loads / hotset hits
          -> SwiGLU gate/up/down
          -> weighted combine
          -> shared expert execution
          -> residual
       -> sequential layer completion authority
  -> KV commit
  -> output norm + output head
  -> decode authority
  -> token commit
  -> runtime-local promotion gate
```

## MLA

`d2u_mla.c` implements the absorbed MLA execution shape used by DeepSeek2 models: Q-LoRA, KV-LoRA, decoupled no-PE/RoPE query dimensions, normalized latent KV cache, K-B absorption into latent rank, V-B expansion, YaRN-style frequency scaling, and attention output projection.

The cache grows only to the positions actually submitted. It does **not** allocate the declared 163,840-token context up front.

## Router

`d2u_router.c` removes training-time random load-balancing noise. It computes the real router matrix product, then uses:

- sigmoid scoring when the correction-bias tensor is present;
- correction bias for selection only;
- group-limited selection when the GGUF group metadata is present;
- original un-biased scores for routed weights;
- selected-weight normalization and GGUF expert scale.

A correction-bias model without group metadata fails closed instead of guessing.

## Quant kernels

Portable scalar dequant/dot support is included for:

- F32, F16, BF16
- Q4_0, Q4_1, Q5_0, Q5_1, Q8_0
- Q2_K, Q3_K, Q4_K, Q5_K, Q6_K, Q8_K

The Q4_K block layout is the actual 144-byte GGUF layout: two FP16 super scales, 12 packed scale/min bytes, and 128 quant bytes. This intentionally does not use the existing RawrXD wrapper that declares 32+128 bytes while asserting 144 bytes.

`Q4_K_M` is a GGUF quantization policy, not one physical tensor type; a Q4_K_M model can contain several K-quant tensor types, so the runtime dispatches per tensor type.

## GGUF parsing

`d2u_gguf.c` parses GGUF v2/v3 metadata and tensor descriptors from every supplied shard without external libraries. Large tokenizer arrays are skipped in place rather than copied into RAM.

Missing `qk_nope_head_dim`, `v_head_dim`, and attention-head count can be derived from real tensor geometry:

- `blk.N.attn_k_b.weight`: `[qk_nope, kv_lora, heads]`
- `blk.N.attn_v_b.weight`: `[kv_lora, v_head, heads]`

No guessed head dimensions are baked into the runtime.

## Authority semantics

### Scheduler authority

`d2u_scheduler_claim()` accepts exactly the owner cookie created for the session. Every inference I/O operation requires a matching active ticket from that owner.

### Decode authority

`d2u_mint_decode_authority()` succeeds only after:

- strict sequential completion of every transformer block;
- KV commit success;
- finite output/logit computation;
- scheduler authority remains live;
- no operation is left open;
- no background or predictive I/O counter is nonzero.

### Promotion

`d2u_try_promote()` is a **runtime-local execution gate**, not a claim about the repository's certification branch. It requires:

```
MODEL_VALID
&& PRODUCT_OPEN_PASS
&& SESSION_ENTER_PASS
&& GENERATED_TOKENS > 0
&& TOKEN_COMMIT_PASS
&& SCHEDULER_AUTHORITY
&& DECODE_AUTHORITY
&& BACKGROUND_SUBMITS == 0
&& PREDICTIVE_LOADS == 0
&& !FAILED
```

A source build or smoke test alone cannot produce this live runtime-local promotion; a successful token path can.

## Build

Windows/MSVC:

```
build_portable.bat
```

Linux/clang/gcc:

```
./build_portable.sh
```

Both use warnings-as-errors and run `d2u_smoke`.

## Inspect your DeepSeek-R1 shards first

PowerShell:

```
$dir='F:\OllamaModels\DeepSeek-R1-Q4_K_M-COMPLETE'
$shards=Get-ChildItem "$dir\*.gguf" | Sort-Object Name | ForEach-Object FullName
& .\d2u_inspect.exe $shards
```

The inspect gate should report the actual architecture, dimensions, quant tensor types, expert geometry, and whether the two head dimensions came from metadata or tensor geometry.

## Drive loading with user token IDs

The source drop intentionally does not add another tokenizer implementation. Pass token IDs from the existing Deep2 tokenizer path:

```
& .\d2u_run_tokens.exe $shards -- 1 1234 5678 42
```

Each token's real hidden state chooses its own scattered experts. The CLI reports cumulative I/O, hotset size, expert-cache hits/misses, decode authority, and runtime-local promotion. The default routed-expert hotset budget is 16 GiB; set `D2U_EXPERT_CACHE_GIB` before running the CLI to override it.

## Important performance boundary

This is a correctness-first portable hotpatch. The quant kernels are scalar C and MLA is straightforward CPU code. It is intended to establish the **right I/O/authority graph** against the real 671B files before replacing the portable kernels with your MASM/Vulkan kernels. No 70+ TPS claim is made by this drop.

The critical architectural change is that approximately-active-per-token compute does not imply simultaneous residency of the full model: each layer touches only its current always-on weights, current shared expert, and router-selected expert slices. Scattered experts are addressed directly by tensor/shard/offset rather than discovered by streaming through the model.
