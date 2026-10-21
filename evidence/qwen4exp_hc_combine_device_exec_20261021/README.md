# Qwen4Exp hyperconnection combine: device execution evidence

The hyperconnection combine lowering was a static artifact. It had been compiled
with `glslc` and checked with `spirv-val`, and those checks passed, and it had
never been run on a device. A correctness kernel that has never executed is an
untested artifact: it might not even build in the driver's hands, and a static
validator cannot say whether the numbers are right.

This is the execution evidence for it.

## What ran

- Artifact: `src/deep2/shaders/deep2_qwen4exp_hc_combine.spv`
- Device: AMD Radeon AI PRO R9700, Vulkan 1.4.357
- The validation layer was on for the whole run, and it reported nothing.

## The result

```
tokens=5 head_dim=16 hc_count=4 width=64
combined   max_abs_diff = 1.043e-07
normalized max_abs_diff = 4.041e-07
tolerance                = 2.000e-05
all values finite        = yes

RESULT: PASS (the device reproduced the reference)
```

The reference is computed on the host in double precision, from the recovered
equation, and is written independently of the shader:

```
injection = 2 * sigmoid(logits / hc_count)
out       = residual + block_output * injection
normalized = grouped RMSNorm(out), per stream, Gemma-style (1 + w) affine
```

The inputs are a deterministic pattern that is not symmetric, so a transposed
or mis-strided read cannot produce the same answer. The two outputs are
checked separately, because a wrong combine and a wrong norm are different
failures.

## What the run found

The first run failed, and the failure was in the test rather than in the
artifact:

- The descriptor set was written with a buffer but no range. A range of zero is
  not the whole buffer; it is a descriptor over no bytes at all. The shader
  then read zeros and wrote nothing, and reported no error.
- The memory type was chosen with a single mask over two flags, which matches
  when either flag is set, so a host-visible but not host-coherent type could
  be picked.

Both were found by the validation layer
(`VUID-VkDescriptorBufferInfo-range-00341`), which is why it is now enabled in
the test. The artifact was numerically correct from the beginning.

The committed `.spv` is 6540 bytes and a fresh `glslc -O` compile of the
committed `.comp` is 3716 bytes. Both produce identical numbers, so they are
the same shader; the committed one carries more decoration. The test runs
against the committed artifact, because that is the one the tree ships.

## What this does not establish

- It is not an executor binding. The runtime graph still refuses the
  hyperconnection operator, and the model is still `NOT_CERTIFIED`.
- It is an F32 staging proof over a small geometry. The Q8 weight GEMM and the
  bf16 rounding points are separate work, and the reference's rounding points
  are not reproduced here.
- It does not cover the mix path (the down and up projections, the per-stream
  silu, and the sigmoid-gated mean). It covers the combine path only.

## The gate

`Qwen4Exp_HcCombine_Device` runs the artifact and compares it against the
reference. A machine with no GPU is BLOCKED, never PASS.
