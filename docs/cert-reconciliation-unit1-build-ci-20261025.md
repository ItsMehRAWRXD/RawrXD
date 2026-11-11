# Unit 1 — Build/CI Hygiene Certification

Source: `origin/preservation/source-baseline-20261021`
Integration: `integration/cert-reconciliation-20261025`
Recovery branch: `recovery/unit1-build-ci`
Date: 2026-10-25

## Extracted files (provenance)
- `3rdparty/ggml/src/CMakeLists.txt` — MSVC compile-feature fallback; Vulkan backend disabled (header incompatibility)
- `3rdparty/ggml/src/ggml-cpu/CMakeLists.txt` — MSVC compile-feature fallback
- `3rdparty/ggml/src/ggml-vulkan/ggml-vulkan.cpp` — Vulkan 1.3 getProperties API fix (reverted `is_integrated_gpu` hack to original behavior)
- `scripts/build.ps1` — Extra args passthrough
- `.gitignore` — expanded ignore patterns

## Excluded (not build hygiene / unsafe)
- Top-level `CMakeLists.txt` — different project (RawrXD-ModelLoader vs Deep2Engine); rejected.
- `is_integrated_gpu = false` hack — runtime behavior change; reverted.

## Build results
- MSVC configure: PASS (VS 17 2022, MSVC 19.44, Vulkan SDK 1.4.357)
- MSVC build: PARTIAL — core targets built; `production_smoke_test` failed with 3 unresolved `VulkanStagingPipeline` symbols (pre-existing, not introduced by Unit 1).
- CTest: not run (build incomplete).

## Blocker
`production_smoke_test` link failure: `VulkanStagingPipeline::acquire_staging_buffer/release_staging_buffer/enqueue_asynchronous_dma` undefined. Pre-existing on main (source references symbols not implemented). Not caused by Unit 1 changes.

## Certification status
Unit 1: ANALYZED → EXTRACTED → BUILT (partial) → TESTED (blocked) → CERTIFIED (pending blocker resolution)

## Next
Resolve VulkanStagingPipeline symbol implementation (separate task), then rerun build + CTest before promotion.
