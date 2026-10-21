# Qwen4Exp grouped RMSNorm: device execution evidence

The hyperconnection mix normalises the hidden state per stream before the down
projection, and nothing in the tree could do that. The generic ops shader has
`OP_RMSNORM`, which normalises over the whole row, not over a stream of it.
A whole-row norm over a four-stream hidden state is a different number, so it
is not a substitute.

This lowers the per-stream norm and proves it on the device.

## The operation

The hidden state is cut into `hc_count` streams, and each stream is normalised
on its own: the sum of squares is over that stream's slice, and the scale is
`(1 + w)` rather than `w`, because that is what the reference's
`grouped_gemma_rmsnorm` does. The two details are the whole difference
between a grouped norm and a row norm.

The reference for the operation is the already-executed hyperconnection
combine path, which performs the same normalisation inline. The two cannot
disagree about it, because the combine path is the one that was executed
against a host reference first.

## The result

```
tokens=7 head_dim=16 hc_count=4 width=64
max_abs_diff = 4.080363e-07
tolerance    = 2.000000e-05
all finite   = yes

RESULT: PASS (the device reproduced the reference)
```

Device: AMD Radeon AI PRO R9700, Vulkan 1.4.357, with the validation layer
on for the whole run.

## What this does and does not establish

- It establishes that the per-stream normalisation is available on the device
  and is numerically correct. The mix path needs it and now has it.
- It does not complete the mix path. The per-stream silu mean and the
  sigmoid-gated mean are still missing, and the down and up projections are
  still quantised-weight GEMMs, which are a separate problem.
- It is not bound into the runtime graph. The model is still fail-closed and
  still `NOT_CERTIFIED`.

## The gate

`Qwen4Exp_GroupedRmsNorm_Device` runs the artifact and compares it against the
reference. A machine with no GPU is BLOCKED, never PASS.
