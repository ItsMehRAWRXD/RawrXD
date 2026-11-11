# Per-layer topology audit

The Qwen3.5 prefill failure was traced to the engine lowering a gated
hybrid block as an ordinary attention block. The fix has to be per layer,
because a hybrid model's layers are not all the same, and the question is
which kind each layer is.

This is that question, asked of the file and answered from the file.

## What it does

`deep2_topology_audit` reads the header and the tensor directory of a model
and, for every layer, records:

- the kind of mixer it has
- the normals it carries and their widths
- the projections it carries and their shapes
- the recurrent state it needs, derived from the file
- every shape problem the widths imply

It then reports the sequence of layers and **every transition between them**.
A transition is where the lowering has to change, and therefore where a
lowering is most likely to be wrong.

The weight payload is never read, so it is cheap on a model of any size, and
it touches no device.

## The mixer is decided from the set of parts, never from one tensor

A layer is a gated delta because it has the gate **and** the recurrent
coefficients **together**. Deciding it from the fused projection alone calls
phi-3 a gated delta, and phi-3 is an ordinary dense transformer with a
fused qkv. That mistake was made here while the tool was being written, and
it is the same mistake the engine made.

## The corpus, 30 models

| model | arch | layers | mixers |
|---|---|---|---|
| Qwen3.8-27B-AD | qwen35 | 65 | 17 full attention, 48 gated delta (fused input) |
| Qwen3.6-27B-Fable-Fusion | qwen35 | 65 | 17 full attention, 48 gated delta (fused input) |
| Qwen3.5-40B | qwen35 | 96 | 24 full attention, 72 gated delta (fused input) |
| Qwen3.8-Flash-Next | qwen4exp | 5 | 1 full attention, 4 gated delta (fused input) |
| NVIDIA-Nemotron-3-Nano-4B | nemotron_h | 42 | 4 full attention, 21 gated delta (own input), 17 no mixer |
| nemotron-3.5-lightning-30b | nemotron_h_moe | 30 | 7 full attention, 23 gated delta (own input), 23 no mixer |
| DeepSeek-R1 / GLM-4.7 / Kimi-K2 | deepseek2 | 9-61 | latent attention, and blocks with no mixer |
| llama3.2-3b, Codestral, BigDaddyG | llama | 28-80 | full attention |
| qwen2.5-coder, DeepSeek-R1-0528 | qwen2, qwen3 | 36-48 | full attention |
| Phi-3-mini, Phi-3-medium | phi3 | 32-40 | fused qkv attention |
| gemma-4-31B, gemma-4-E4B | gemma4 | 42-60 | full attention |
| MiniMax-M2.7 | minimax-m2 | 22 | full attention |

**Every model's width chain closes on every layer. There are no shape
problems in the corpus.**

That is the important result, and it is the opposite of where the search
started. The models are not the problem. The engine's lowering is.

## The layers are interleaved, and that matters

The blocks of a hybrid model are not one run of one kind followed by one run
of the other.

Qwen3.8-27B-AD, 65 layers:

```
transition at layer 3:  gated delta -> full attention
transition at layer 4:  full attention -> gated delta
transition at layer 7:  gated delta -> full attention
transition at layer 8:  full attention -> gated delta
...
```

**The pattern is three gated layers and one attention layer, repeating, with
the attention layer every fourth.** There are 32 transitions in 65 layers,
not one. A lowering that assumed a single transition, or that assumed the
split was at 17/18, would be wrong for two thirds of the model.

Nemotron-3-Nano-4B alternates the other way, one gated layer and one layer
with no mixer of its own, repeating.

## The recurrent state, derived from the file

The value width is what the block's output projection takes in. The head
count is what the decay bias is wide. The value head width is the value
width divided by the head count. The key head width is what the A and D
matrices are square in. The state is the head count by the key head width by
the value head width.

| model | heads | key head width | value head width | elements per sequence |
|---|---|---|---|---|
| Qwen3.5-40B, Qwen3.6-27B, Qwen3.8-27B | 48 | 48 | 128 | 294,912 |
| Nemotron-3-Nano-4B | 96 | 96 | 80 | 737,280 |

For the 27B model the state is 294,912 elements per sequence, which is
589,824 bytes in f16 per sequence per layer that carries one.

## What the two gated hybrids are

They are not the same operation and they do not have the same width.

**Qwen3.5 and Qwen3.6 and Qwen3.8 and Qwen4Exp**: the recurrent input
projection is fused into the attention projection and there is a gate. The
value width is 6144 and the residual stream is 5120, and `ssm_out` is the
projection that brings the value back. There is no `ssm_in`.

**Nemotron-H**: the recurrent input projection is its own, `ssm_in`, and
there is no gate. The value width is 7680 and the residual stream is 3136.

**DeepSeek's MLA is a third thing again**: the query and the key and value
are compressed, and the value is expanded from a narrow latent. It is not a
gated hybrid and it is not a softmax attention.

**This is the distinction the engine's detection has to make, and the
distinction the qwen35 detector already makes**: it requires the fused
projection AND the gate AND the recurrent coefficients together, so it fires
on the family that needs it and not on the one that does not.

## What this does not establish

- It is not an execution result. The layers are classified, not run.
- The Nemotron activation explosion is still not attributed. The values
  between -3416 and 2012 are suspicious, and this audit says which layer
  and which operator they belong to, which is the first step, but it does
  not say which one is wrong.
- The corpus is 30 models. It is not every model that exists.
