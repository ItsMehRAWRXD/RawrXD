# The Qwen3.5 prefill fallback: the complete root cause

## The symptom

```
first_fallback_reason=legacy quant type dequantised on CPU, no GPU kernel: blk.00.attn_gate.weight
cpu_operations=168
vulkan_tensor_ops=718
dispatch_ms=27380.907
prefill_tps=0.04
```

168 CPU operations for 65 layers is about 2.6 per layer, which is the
per-layer cost of a hybrid block whose projections are not on the device.

## The cause, in one line

**`attn_gate.weight` is Q5_K, and Q5_K is the one quantization format with no
GPU kernel in either tree.**

The failing model's `blk.0`, read from the model's own tensor directory:

| tensor | dtype_id | type | shape |
|---|---|---|---|
| **attn_gate.weight** | **13** | **Q5_K** | 5120 x 6144 |
| attn_qkv.weight | 12 | Q4_K | 5120 x 10240 |
| ffn_up.weight / ffn_gate.weight | 13 | Q5_K | 5120 x 17408 |
| ffn_down.weight | 13 | Q5_K | 17408 x 5120 |
| ssm_out.weight | 13 | Q5_K | 6144 x 5120 |
| attn_norm.weight / post_attention_norm.weight | 0 | F32 | 5120 |
| ssm_alpha.weight / ssm_beta.weight | 8 | Q8_0 | 5120 x 48 |
| ssm_conv1d.weight | 0 | F32 | 4 x 10240 |

A hybrid block has one Q4_K projection and **four** Q5_K projections, so
most of its weights are in the one format the device cannot read.

## The path, step by step

`Executor::OpLinear` has three branches for a quantized weight.

1. **The packed GPU branch** (`runtime_graph_executor.cpp:1216`). It is entered
   for Q4_K, Q6_K, Q2_K, Q3_K, Q5_K and NVFP4 when `n_in % 256 == 0`.
   For `attn_gate` that holds: 5120 % 256 == 0, and the byte check is
   `2880 * 6144 == 17,694,720`, which is exactly the weight's size. So the
   branch is entered and the dispatch is attempted.

2. **`QuantDot::DotBlocked`** (`quant_dot_dispatch.cpp:451`). Its kind
   check is `if (kind < 0 || kind > 7)`. `QuantKindOf` returns **8** for
   `GGML_TYPE_Q5_K` (`runtime_graph_executor.cpp:210`, with the comment
   *"Qwen hybrid projections: native Q5_K GPU kernel"*). **Kind 8 is rejected
   with "unsupported kind"**, the dispatch returns false, and the executor
   falls through.

3. **The CPU legacy branch** (`runtime_graph_executor.cpp:1490`), which
   lists Q5_K, dequantises the row with ggml's own `to_float` and dots on
   the host. It sets the message in the trace. **This path is numerically
   correct. It is slow, not wrong.**

So the message names `attn_gate` because the gate projection is the first
Q5_K weight the block reaches.

## Why the kernel cannot simply be told to accept kind 8

Two more places assume kinds 0 to 7:

- `RowBytesForKind` (`quant_dot_dispatch.cpp`) has no case for kind 8, so it
  would return Q4_0's stride, 18 bytes per 32 values, for a Q5_K row that
  is 176 bytes per 256 values. The weight would be read with the wrong
  stride.
- `RowDotInterleavedQ8` (the CPU replay in the executor) handles kinds 0
  and 1 with the k-quant integer-MAC path and kinds 2, 3 and 4 as 32-value
  legacy blocks. **Kinds 5, 6, 7 and 8 fall into the 32-value branch and
  would be decoded with the wrong layout.** For Q2_K and Q3_K this is
  currently unreachable, because the kind check rejects them first. Accepting
  kind 8 without a Q5_K decode would turn a slow answer into a wrong one.

## What has to happen

**Q5_K needs a block decode in the packed GEMV.** Its block is 256 values
in 176 bytes: five 32-value quants, two 16-bit scales and two 16-bit
minimums, with the minimums applied to half the blocks.

The layout is already known to the tree. `QuantBlockTraits` in the
`G:\VSC0de\Deep2Engine` tree carries Q5_K's block length and size, so the
decode is mechanical rather than a piece of reverse engineering.

The work is three coordinated changes, and **all three have to land
together**:

1. A Q5_K branch in the packed GEMV shader, alongside the Q8_0, Q2_K, Q4_K
   and Q6_K branches it already has.
2. `RowBytesForKind` gains `case 8: return ((n_in + 255u) / 256u) * 176u;`
3. `DotBlocked` accepts `kind <= 8`, and `RowDotInterleavedQ8` gains a
   Q5_K branch so the CPU replay and the device agree.

The proof that it works is the pattern this tree already uses: run the
kernel on the device and compare it against a host reference computed in
double precision, with the reference written from the block layout rather
than from the kernel. The four lowerings already proven on the R9700
(grouped RMSNorm at 4.08e-07, the PLE causal convolution at 2.02e-08, the
MoE router at 1.81e-06 and the QSA indexer scoring at 2.82e-08) were
proven that way.

## What is not the cause

- **The GDN kernel is not missing.** `deep2_qwen4exp_gdn.comp` is a correct
  gated delta-net, and `Executor::OpGdn` already dispatches it
  (`gpu.DispatchGdn`, `runtime_graph_executor.cpp:4999`). The CPU work in
  front of that dispatch is the causal convolution and the dequantisation of
  the recurrent parameters, both of which the host does for every layer of
  every token.
- **The device selection is not the cause.** The log says
  `Selected device: AMD Radeon AI PRO R9700`, which is device 0, the native
  one. The Direct3D12 entries are the Windows compatibility wrappers and
  are not selected.
- **Forcing device-local memory would make it worse.** The fallback is a
  kernel gap, not a placement problem, and device-local VRAM on a discrete
  card is not host-visible, so the host could not read the weight it has to
  dequantise.

## On the throughput number

`dispatch_ms=27380.907` and `prefill_tps=0.04` are a **prefill at the
model's declared 262,144-token context**, over 65 layers. It is
attention-bound and it is not the decode rate. The decode rate is the
number the throughput target is about, and it is not measured by this trace.

At that context the residency is 24 GiB per sequence, of which the
recurrent state is 108 MiB. The cache decides whether the model fits; the
state does not.
