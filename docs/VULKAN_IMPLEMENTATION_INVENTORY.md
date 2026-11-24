# Vulkan implementation inventory

Status: partial static inventory; RX-001 and RX-003 remain open.

## Confirmed build membership

| Source | Build configuration | Target |
|---|---|---|
| src/VulkanDevice.cpp | CMakeLists.txt | Deep2Engine_Benchmark |
| RawrXD-ModelLoader/src/vulkan_compute.cpp | RawrXD-ModelLoader/CMakeLists.txt | RawrXD-ModelLoader, RawrXD-CLI, model_loader_bench (inspect enclosing disabled guards before enabling) |
| ~dev/rawrxd/src/deep2/vulkan_compute.cpp | ~dev/CMakeLists.txt | rawr_monolith |

Additional pipeline API references discovered by repository search: src/vulkan_compute.cpp, src/vulkan_stubs.cpp, src/agent/self_patch.cpp, ~dev/rawrxd/src/core/sekv_system_edition.cpp. Their production target membership is not established.

## Closure evidence required

- Resolve native IDE target and actual inference call chain.
- Enumerate shader loaders, embedded modules and generated shader artifacts.
- Capture runtime pipeline identities on the actual production executable.
- Verify descriptor layouts, synchronization and buffer ownership against the actual shader ABI.
- Build and execute independent numerical parity tests before closing runtime items.

## Existing changes

ROM backend memory barriers: fccb04c1adf325ecb33a63f6b53f26fd14155cab.
ModelLoader global Qt removal: 0425d92d86a27bb5d62de9476fd51df2cfe684cd.
Shader deployment directory fix: afb059187ed678544ef104168c2a24ad0704a456.
Portable Phi3 fixture gate: 81bdac5ddf08afaee5a25ea18834319dfcbc8881.

No runtime certification is implied. No Qt or new dependencies are permitted.
