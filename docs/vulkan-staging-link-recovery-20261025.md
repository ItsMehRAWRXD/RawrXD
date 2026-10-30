# Vulkan Staging Pipeline Linker Recovery (2026-10-25)

## Root cause
`production_smoke_test` target compiled only `src/tools/production_smoke_test.cpp` and did not include `src/VulkanStagingPipeline.cpp`, which defines `Deep2Rom::Compute::VulkanStagingPipeline` (acquire_staging_buffer, release_staging_buffer, enqueue_asynchronous_dma).

## Fix
Added `src/VulkanStagingPipeline.cpp` to the `production_smoke_test` add_executable source list in CMakeLists.txt (commit b4b07c2e).

## Verification
- Link: PASS (no unresolved externals)
- Smoke test binary runs (prints usage without manifest args - expected)
- No new unresolved symbols

## Provenance
Implementation in src/VulkanStagingPipeline.hpp/.cpp, namespace Deep2Rom::Compute. Already present on main; only CMake registration was missing.
