# Gate G01 — Identify authoritative compiled Vulkan adapter class

## Status: IDENTIFIED (PASS)

## Finding
The authoritative, compiled, engine-facing Vulkan adapter class is
**`CPUInference::VulkanCompute`**, defined in
`src/deep2/vulkan_compute_engine_adapter.cpp`.

Evidence:
- `CMakeLists.txt:3030` compiles `src/deep2/vulkan_compute_engine_adapter.cpp`
  into the engine library.
- `Deep2Engine` GPU slots are typed `CPUInference::VulkanCompute`:
  - `Deep2Engine.cpp:14020` `Deep2Engine::getVulkanComputeSlot(...)`
  - `Deep2Engine.cpp:14117-14119` `make_unique<CPUInference::VulkanCompute>()`
- The adapter TU header states it is an **adapter over** `Deep2::VulkanCompute`
  (not a second implementation). It forwards:
  - `InitializeSolo -> Deep2::VulkanCompute::initialize()`
  - `DispatchGEMV/DispatchGEMVQuant -> DispatchGemvDevice/DispatchGemvQuant`
  - `GemvSuccess/GemvWeightUploads/GemvWeightHits -> *Count()`
  - `SetPinResidentBudget -> ApplyWeightWindowPolicy(...)`
  - `GetDeviceInfo -> physicalInfo()`
- The real device/memory/pipeline/shader/quant-kernel implementation is
  **`Deep2::VulkanCompute`** in `src/deep2/vulkan_compute.{h,cpp}` (~6900 lines,
  `deep2_*` shader family), compiled via `CMakeLists.txt:1032`/`1104`
  (`src/deep2/vulkan_compute.cpp`) and `quant_dot_dispatch.cpp` (`:1038`/`:1096`).

## Conclusion
- Engine-facing authoritative adapter: `CPUInference::VulkanCompute`
  (`vulkan_compute_engine_adapter.cpp`).
- Underlying implementation: `Deep2::VulkanCompute` (`vulkan_compute.{h,cpp}`).

## Dependency note (blocks G02-G13 for this agent)
`vulkan_compute_engine_adapter.cpp`, `quant_dot_dispatch.cpp/.hpp`,
`vulkan_compute.cpp/.h`, `Deep2Engine.cpp`, `runtime_graph_executor.cpp` currently
carry **uncommitted edits from the concurrent Strata/Deep2 agent**. Any
implementation of G02-G13 (retention adapter forwarding, QuantDot policy,
benchmark flag, etc.) edits these same files and must be done by that workstream
to avoid clobbering active work. G01 required no edits and is closed read-only.