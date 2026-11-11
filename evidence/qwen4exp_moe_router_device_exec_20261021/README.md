# Qwen4Exp MoE router: device execution evidence

The router turns a hidden state into one logit per expert. It is the first
part of the sparse MoE operator and it does not depend on the format the
experts are stored in, which makes it the part that can be proven first.

The artifact had been compiled and statically checked and had never been run.

## The operation

The router weight is `[hidden_width, experts]`, so the weight column for an
expert is strided rather than contiguous, and the expert's logit is the dot
product of the hidden state with that column. The top-k selection is not part
of this kernel: the kernel produces the logits, and the selection is a
separate step.

## The result

```
hidden_width=64 experts=512 top_k=10
max_abs_diff = 1.813027e-06
tolerance    = 2.000000e-05
all finite   = yes

RESULT: PASS (the device reproduced the reference)
```

Device: AMD Radeon AI PRO R9700, Vulkan 1.4.357, with the validation layer
on for the whole run.

## What this does and does not establish

- It establishes that the router logits are available on the device and are
  numerically correct at the canonical 512 experts.
- It does not complete the sparse MoE operator. The top-k over these logits,
  the grouped expert dispatch and the MXFP4 and IQ2 formats the experts are
  stored in are all still missing.
- It is not bound into the runtime graph. The model is still fail-closed and
  still `NOT_CERTIFIED`.

## The gate

`Qwen4Exp_MoeRouter_Device` runs the artifact and compares it against the
reference. A machine with no GPU is BLOCKED, never PASS.
