# The Q5_K decode: where the 15× went, and what is left

## The measurement

The packed GEMV was measured on the R9700 with 1.50 GiB of Q5_K weights in
DEVICE_LOCAL memory, far past the card's last level cache, with one command
buffer, one submit and one fence per projection.

| path | achieved | 27B, one token per weight read | 27B, four tokens per read |
|---|---|---|---|
| per-element decode | 128.3 GB/s | 9.3 tok/s | 37.2 tok/s |
| **four-column decode** | **299.9 GB/s** | **21.7 tok/s** | **87.0 tok/s** |

The same access pattern with no dequantisation at all reads at 1921 GB/s. That
number is roughly three times the card's published DRAM bandwidth, so it is
partly cache-served and it is not a claim about coalescing. What it does
establish, and what the ratio does not depend on, is that the decode and not
the read is what the time goes into.

**Hoisting the sub-block metadata out of the per-element path was worth
2.34×, and the correctness proof still passes: the kernel reproduces ggml's own
`dequantize_row_q5_K` to 3.15e-07 relative error.**

## A process failure worth recording

The first attempt at that change reported no improvement, and the reason was
that the shader had not compiled. The function definition was missing, the
compiler error was on stderr, and the build script filtered it, so an exit
code from an earlier step was read as the compile's. The measurement was taken
against the previous SPIR-V. The same filter hid it a second time.

**The rule this suggests: a shader build must fail the build, and the exit
code that matters is the one from the compile, not the last thing that ran.**

## Where the instructions are

The optimised module is **one function of 195 instructions**, and it is
**73% control flow**: 70 `OpBranch`, 38 `OpBranchConditional`, 35
`OpSelectionMerge`. The arithmetic does not appear in the top sixteen opcodes
at all.

That is the direct consequence of putting five decode paths in one shader and
selecting between them with `pc.type` **at run time, inside the inner loop**.
Every invocation walks the branch chain.

Counted separately, in the unoptimised module, the decode paths differ by
almost an order of magnitude:

| path | instructions |
|---|---|
| `q8_0_weight` | 8 |
| `q2k_weight` | 10 |
| `q4k_weight` | 42 |
| `q4k_dot4` | 60 |
| `q5k_dot4` | 69 |
| `q6k_weight` | 93 |

and the byte reader `getb` is 198 instructions, inlined at every use.

**So the register allocator has to satisfy the worst path, `q6k_weight` at 93
instructions with its four-way branch, for the whole function, and the
occupancy is set by that worst case rather than by the format actually
running.**

## What this says about the next change

**Specialise the shader per format.** One SPIR-V per format, each carrying
exactly one decode path, with no run-time type dispatch at all. That
removes the branch chain that is three quarters of the instructions, lets the
register allocator satisfy only that format's path, and raises occupancy.

**The engine already selects the shader by capability id.**
`VulkanDevice::QuantShaderName(type)` returns a path per format, so this is a
change to the shader set and not to the selection logic. The selection was
built for exactly this.

This is also what the reference implementation does: separate
`mul_mat_vec_q4_K_q8_K`, `q6_K` and `q8_0` kernels, one per format, rather
than one kernel with a type switch.

## What is left after it

At 299.9 GB/s the 27B reaches 87 tokens per second with four-token
verification and 21.7 with one. The card's published bandwidth is 640 GB/s, so
there is roughly another 2× in the read before the decode is the limit again,
and a per-format shader is the change most likely to reach it.

The acceptance criterion does not move: a faster kernel has to reproduce the
model's outputs first, and the proof that this one does is the Q5_K device
test, which compares against ggml's own dequantiser and fails the build if it
does not match.
