# Qwen4Exp PLE short convolution: device execution evidence

The PLE lowering was a static artifact. It had been compiled with `glslc` and
the compile was clean, and it had never been run. It had a real defect, and a
single dispatch would not have found it.

## What ran

- Artifact: `src/deep2/shaders/deep2_qwen4exp_ple.spv`
- Device: AMD Radeon AI PRO R9700, Vulkan 1.4.357
- The validation layer was on for the whole run, and it reported nothing.
- Two dispatches in a row: the first from a cold state, the second from the
  state the first produced.

## The result

```
kernel=4 channels=8
dispatch 1: tokens=6  y max_abs_diff = 5.672672e-08   carry max_abs_diff = 0.000000e+00
dispatch 2: tokens=3  y max_abs_diff = 2.020435e-08   carry max_abs_diff = 0.000000e+00
tolerance                       = 2.000000e-05

RESULT: PASS (the device reproduced the reference)
```

The reference is computed on the host in double precision, from the causal
definition of the convolution, independently of the shader.

## The defect the run found

The committed shader read the carried history from the wrong slot:

```glsl
uint state_index = uint(int(pc.kernel - 1u - tap) + source);
```

`source` is `token - (kernel-1-tap)`, so `state_index` collapses to `token`.
Every tap of a given token therefore read the same slot of the carried
history, and the window was the wrong one.

The slot is the tap. The state holds the `kernel-1` samples immediately before
the dispatch, oldest first, so `state[tap]` is the sample at offset
`tap-(kernel-1)` relative to the start of the dispatch, and that is exactly the
sample the tap wants.

### Why it was invisible

On a cold start every slot of the history is zero, so reading the wrong slot
reads the same value. The defect only appears once real state is carried, which
is the second dispatch.

The two dispatches, run against the **committed** shader:

```
dispatch 1: tokens=6  y max_abs_diff = 5.672672e-08   carry max_abs_diff = 0.000000e+00
dispatch 2: tokens=3  y max_abs_diff = 4.494151e-01   carry max_abs_diff = 0.000000e+00

RESULT: FAIL
```

Dispatch 1 passes on the broken shader. Dispatch 2 does not. A single-dispatch
test would have reported the artifact as correct.

### Why the static checkpoint could not have found it

`glslc` and `spirv-val` say whether a shader compiles and whether the module
is well formed. Neither says whether the causal window is the right one. Only
running two dispatches in a row does.

## The fix

`src/deep2/shaders/deep2_qwen4exp_ple.comp` now reads the slot as the tap, and
the SPIR-V is recompiled from it. The committed `.spv` was 6564 bytes; the
recompiled one is 4148 bytes. The old `.spv` was not the compiled form of the
current `.comp`, so it was stale in the tree.

## What this does not establish

- It is not an executor binding. The runtime graph still refuses the PLE
  operator, and the model is still `NOT_CERTIFIED`.
- It covers the short convolution only. The n-gram embedding, the key and
  value projections and the norms around it are separate work.
- The geometry is kernel 4 and a small channel count, not the canonical 10240
  channels. The shape of the computation is the same and the arithmetic is the
  same, but the canonical geometry is not what was run.

## The gate

`Qwen4Exp_Ple_Device` runs the artifact and compares it against the reference.
A machine with no GPU is BLOCKED, never PASS.
