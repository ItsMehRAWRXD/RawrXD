# Tiled Q4_K shader build

- Shader: `src/deep2/shaders/deep2_qgemv_tiled4x.comp`
- SPIR-V: `src/deep2/shaders/deep2_qgemv_tiled4x.spv`
- SPIR-V SHA-256: `DB342B90D313799821E574C5BFE11987C7B7BE5962664C8A5039601EB23CD274`
- Command: `cmake --build build_sprint_20261119 --target deep2_tiled4x_qgemv_shader --config Release --parallel 1`
- Exit: `0`

The shader is now a CMake-tracked build artifact and its Q4_K-only scope is explicit. Pipeline registration, runtime selection, numerical parity, and performance remain open; no runtime PASS is claimed.

```ini
TILED_SHADER_COMPILE=PASS
TILED_SPIRV_GENERATED=PASS
TILED_PIPELINE_RUNTIME=NOT_VERIFIED
TILED_NUMERICAL_PARITY=NOT_RUN
TILED_TPS=NOT_MEASURED
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
