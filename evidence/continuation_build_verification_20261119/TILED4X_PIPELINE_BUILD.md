# Tiled Q4_K pipeline registration build

- Source change: `vulkan_compute.cpp/.h` registers `deep2_qgemv_tiled4x.spv`, selects it for Q4_K `rows >= 4`, dispatches `(rows+3)/4` workgroups, and destroys it during cleanup.
- Shader correction: per-cohort subgroup reduction and row indexing were fixed; unsupported non-Q4_K types no longer call undefined shader functions.
- Build command: `cmake --build build_sprint_20261119 --target RawrXD-Win32IDE-Native --config Release --parallel 4`
- Build exit: `0`
- Executable SHA-256: `53EC4FF233A81144E509711CE6AEDA1A745398A190DC65B2614A597DEEEFF5CB`
- SPIR-V SHA-256: `DB342B90D313799821E574C5BFE11987C7B7BE5962664C8A5039601EB23CD274`

This proves compilation and host pipeline wiring only. A Vulkan runtime trace containing `[Q4K_TILED4X_DISPATCH]`, same-input parity, and TPS comparison remains required.

```ini
TILED_SHADER_BUILD=PASS
TILED_HOST_PIPELINE_WIRING=PASS_BUILD_ONLY
TILED_RUNTIME_DISPATCH=NOT_VERIFIED
TILED_NUMERICAL_PARITY=NOT_RUN
TILED_TPS=NOT_MEASURED
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
