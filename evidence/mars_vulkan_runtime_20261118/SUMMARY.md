# MARS + Vulkan coexistence evidence

Date: 2026-11-18

## Test

Executable: `build/bin-msvc/Release/mars_vulkan_coexistence_test.exe`

Model: `models/qwen2.5-coder_1.5b-base.gguf`

Configuration: Vulkan initialized by `Deep2Engine::initialize`; enhancements enabled; non-MARS enhancements skipped through `RAWRXD_ENHANCE_SKIP`.

## Observed result

```ini
MARS_TEST_VULKAN=1
MARS_TEST_ACTIVE=1
MARS_TEST_PLACEMENT_REJECTED=1
MARS_TEST_RESULT=PASS
PROCESS_EXIT=0
MARS_SHUTDOWN=clean
MARS_TOTAL_ALLOCATED=0
MARS_TOTAL_FREED=0
```

The test exercises the real engine path. MARS initializes its controller/backend alongside Vulkan, while Vulkan retains ownership of compute buffers. A direct model-placement request is rejected before creating MARS leases, preventing duplicate residency accounting.

## Scope limitation

This validates controller coexistence and ownership protection on the active Vulkan topology. It does not certify dual-GPU MARS tensor placement, MoE routing, or numerical parity. Those remain separate gates.
