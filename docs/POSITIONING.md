# RawrXD — positioning

> **RawrXD turns your PC into a self-contained AI software engineering workstation.**

**Category:** the sovereign AI development environment. Local models, native
inference, autonomous engineering.

The claim is that the vertical stack is owned rather than assembled. Most AI
coding products are `IDE → AI API → model somewhere else`. RawrXD's intended
stack is:

```
IDE → autonomous agent → tools → Deep2 → local models → local hardware
```

and it is now extending into graphics and game development:

```
RawrXD
  → coding environment
  → autonomous engineering agents
  → native local inference
  → GPU compute
  → CLI/API
  → browser/computer interaction
  → build/test/verification
  → vision/image inspection
  → graphics/game development
  → deterministic certification
```

The last two are the new part. An agent is not limited to writing renderer
code: the surrounding system can build it, execute it, capture frames,
inspect those frames, and determine whether the visual result changed.

## What is certified today

These are not aspirations. Each line is a gate that runs and produces
evidence.

| Capability | Gate | Evidence |
|---|---|---|
| Native inference on local hardware | Nemotron-30B runs on the R9700 through the Deep2 Vulkan path (`gpu_calls=2775`, `cpu_calls=0`, 32 tokens generated) | `evidence/nemotron_tps_20261021/` |
| Deterministic world generation | The designer's exact configuration parses, round trips byte for byte, and produces the same world from the same seed | `evidence/sunshine_world_generator_20261021/` |
| Real graphics geometry | Greedy meshing with exact cross-chunk face culling: the emitted boundary quads equal the independently computed count | `tools/voxel_render_certify.cpp` |
| Frame capture and vision | `readImage` decodes a real image and returns a luminance map, a colour map and a coverage legend a text model can reason about | `tools/image_tool_certify.cpp` |
| Agent tool surface | `rawr tools list` exposes the tool to the model; `rawr tools run readImage` executes it under the workspace MOTD gate | `src/agentic/tools/ImageTool.h` |
| Reproducible build | A fresh checkout configures and generates with zero untracked and zero ignored source references | `evidence/d3d12_platform_cert_20261021/` |
| Visual output as evidence | The renderer writes real frames as PNG; the frames are inspected, not asserted about | `evidence/*/voxel_frame.png`, `sunshine_hero.png` |

## What is not certified yet

Stated plainly, because the certification standard here is that a claim
without a gate is not a claim:

- **The Direct3D 12 path cannot execute on the current host.** Every
  `ID3D12Device` view creation removes the device with
  `DXGI_ERROR_UNSUPPORTED` (0x887A0001) on both the AMD Radeon AI PRO R9700
  and the WARP software adapter, while device, queue, allocator, command
  list, fence, descriptor heap and committed resource creation all succeed.
  `tools/voxel_probe.cpp` reproduces it. The renderer is the renderer of
  record; a software reference rasterizer sharing the same matrices,
  vertex layout and shading model is what executes today.
- **Nemotron runs at 3.06 decode TPS, not 40.** The gap is orchestration,
  not arithmetic: 63 command-list submits per token and about 1 GB of
  weights resident against a 23.7 GB model.
- **Autonomous visual iteration is not yet closed.** The pieces exist —
  agent tools, image inspection, build and test invocation, frame capture —
  but the loop of *edit → build → run → look → verify → edit* has not been
  certified end to end.

## Why the last one matters

The meaningful milestone is not that an agent can write renderer code. It is
that a local model, running through RawrXD's own inference runtime, can
modify a native game engine, compile it, execute the game, see its own
graphical result, reason about that result, and iterate.

That requires the whole stack to be ours: the model, the tools, the build,
the runtime, the graphics, and the verification.
