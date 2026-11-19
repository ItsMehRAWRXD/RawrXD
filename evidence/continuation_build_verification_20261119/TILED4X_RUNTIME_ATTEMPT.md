# Tiled Q4_K runtime acceptance attempt

- Host integration source: `src/deep2/vulkan_compute.cpp/.h`
- Tiled shader source: `src/deep2/shaders/deep2_qgemv_tiled4x.comp`
- Fresh native IDE build: PASS, SHA-256 `53EC4FF233A81144E509711CE6AEDA1A745398A190DC65B2614A597DEEEFF5CB`.
- Certifier build command: `cmake --build build_sprint_20261119 --target deep2_gpu_certify --config Release --parallel 4`
- Certifier build: BLOCKED, exit `1`.
- First error: `src/codec/compression_core.cpp(13,10): error C1083: Cannot open include file: zlib.h`.
- Runtime tiled marker: not observed because the certifier executable was not produced from this build.

The tiled pipeline is registered in the host and the shader target builds, but runtime dispatch, parity, and TPS remain unverified. The current blocker is the isolated certifier's missing zlib include dependency, not a tiled shader error.

```ini
TILED_HOST_WIRING=BUILT
TILED_CERTIFIER_BUILD=BLOCKED_ZLIB
TILED_RUNTIME_DISPATCH=NOT_RUN
TILED_PARITY=NOT_RUN
TILED_TPS=NOT_MEASURED
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
