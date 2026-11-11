# Qwen3.5 (qwen35) prefill failure: rmsnorm weight too small

## The observed failure

```
PREFILL_FAILED: rmsnorm: weight too small block=0
  tensor=blk.0.post_attention_norm.weight decoded=5120 activation=6144
```

Reproduced with `deep2_exec_trace.exe --model
F:\OllamaModels\Qwen3.5-40B-Claude-4.6-Opus-Deckard-Heretic-Uncensored-Thinking.Q4_K_M.gguf`.

The check that produced it is `Executor::OpRmsNorm`
(`src/deep2/runtime_graph_executor.cpp`):

```cpp
if (!DequantPrefix(w, wf, x.size()) || wf.size() < x.size()) {
    last_error_ = "rmsnorm: weight too small block=" ... " tensor=" + w.name +
                  " decoded=" + ... " activation=" + ...;
    return false;
}
```

**The check is correct and must not be relaxed.** It refused a real desync:
the norm weight has 5120 elements and the activation it was handed has 6144.

## The model's actual geometry

From the shard manifest (`dims` are `[ne0, ne1]`, so `ne0` is the input):

| tensor | shape | in | out |
|---|---|---|---|
| `blk.0.attn_norm.weight` | 5120 | | |
| `blk.0.post_attention_norm.weight` | 5120 | | |
| `blk.0.attn_qkv.weight` | 5120 x 10240 | 5120 | 10240 |
| `blk.0.attn_gate.weight` | 5120 x 6144 | 5120 | 6144 |
| `blk.0.ffn_gate.weight` | 5120 x 17408 | 5120 | 17408 |
| `blk.0.ffn_down.weight` | 17408 x 5120 | 17408 | 5120 |
| `blk.0.ssm_out.weight` | 6144 x 5120 | 6144 | 5120 |

**The hidden width is 5120.** The gated attention branch produces **6144**
(`attn_qkv` gives value 5120 and gate 5120, the value is gated, and
`attn_gate` projects 5120 to 6144). The GDN branch also runs in 6144
(`ssm_out` projects 6144 back to 5120).

**`blk.0.ffn_norm.weight` does not exist.** The FFN norm of this
architecture is named `post_attention_norm.weight`, and it is 5120 wide,
which is correct: it normalises the 5120-wide stream.

## What the graph does

`src/deep2/modelgenie/universal_gguf.cpp` emits the gated mixer as one
fused op:

```cpp
o.op = Op::Attention;
o.a = "attn_norm";
o.b = name(Role::AttnQKV);
o.c = name(Role::AttnGate);
o.out = "attn_proj";
o.detail = "gated_qkv";
```

and the executor's `gated_qkv` path does this
(`runtime_graph_executor.cpp`):

```cpp
OpLinear(in.b, x, qkv, e);                        // 5120 -> 10240
const size_t half = qkv.size() / 2;                // 5120
for (size_t i = 0; i < half; ++i)
    gated[i] = qkv[i] * (qkv[half + i] / (1.0f + std::exp(-qkv[half + i])));
OpLinear(in.c, gated, y, e);                       // 5120 -> 6144
ts[t].hidden = y;                                  // 6144
ts[t].attn_proj = y;                               // 6144
```

**The gated mixer's output is 6144 wide and it is written straight into
`attn_proj` and into the hidden state.** The graph then does:

```cpp
o.op = Op::ResidualAdd; o.a = "resid_in"; o.b = "attn_proj"; o.out = "resid1";
```

`resid_in` is the block input, which is 5120 wide. And the FFN norm consumes
`resid1`:

```cpp
o.op = Op::RmsNorm; o.a = "resid1"; o.b = name(Role::FfnNorm); o.out = "ffn_norm";
```

**So a 6144-wide tensor reaches a 5120-wide norm, and the check refuses.**

## The missing step

**The 6144-wide branch output is never projected back to the 5120-wide hidden
before it becomes the block's contribution to the residual.** The tensor that
does that projection is `ssm_out.weight`, 6144 x 5120.

The gated mixer therefore has to do one of two things, and it currently does
neither:

1. keep the hidden state at the residual width and treat the 6144-wide value
   as a branch contribution that is projected back before the residual add,
   which is what `ssm_out` is for; or
2. apply the 6144-to-5120 output projection to the gated mixer's output
   before it is written to `attn_proj` and to the hidden state.

Either way the residual add and the FFN norm then see 5120, which is what
their weights are.

**This is not a parser problem and not an offset problem.** The manifest is
read correctly, the tensor is found correctly, and the role is bound
correctly. The desync is in the graph's operator ordering, in the width the
gated mixer leaves behind.

## A second, latent defect in the same area

`universal_gguf.cpp` maps two different tensors to one role:

```cpp
if (n.find(".ffn_norm.weight") != std::string::npos ||
    n.find(".post_attention_norm.weight") != std::string::npos) return Role::FfnNorm;
```

In this model only `post_attention_norm.weight` exists, so nothing collides
here. But a variant that carries both would have one of them silently win
the role, because the per-block role map holds one name per role. Two
distinct tensors, two distinct widths, one slot.

## The 7800 XT

The device enumeration in the failing run:

```
Found device 0: AMD Radeon AI PRO R9700
Found device 1: Microsoft Direct3D12 (AMD Radeon AI PRO R9700)
Found device 2: AMD Radeon(TM) Graphics
Found device 3: Microsoft Direct3D12 (AMD Radeon(TM) Graphics)
Found device 4: Microsoft Basic Render Driver
```

The RX 7800 XT is absent, and the reason is visible in the device manager
state:

```
FriendlyName : AMD Radeon RX 7800 XT
Status       : Error
Problem      : CM_PROB_FAILED_ADD
InstanceId   : PCI\VEN_1002&DEV_747E&SUBSYS_53241849&REV_C8\6&2E27FDA8&0&0000000B
```

`CM_PROB_FAILED_ADD` is how Code 43 presents to the Plug and Play manager:
Windows enumerates the card and then fails to start it, so it never reaches
the Vulkan loader. The R9700 and the integrated GPU are `CM_PROB_NONE`. The
engine's behaviour is correct: it enumerates what Vulkan offers and uses the
R9700.

**A cold power cycle and a clean driver reinstall are the right response,
and they are outside what software can do from here.** Nothing in the engine
should be changed to work around it, and the single-device path has to stay
the thing that is certified.
