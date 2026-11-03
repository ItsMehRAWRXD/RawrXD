# Build receipt

Worktree: `F:\rawrxd`
Configuration: existing `F:\rawrxd\build_ide` MSVC x64/Ninja build
Compiler environment: Visual Studio 2022 BuildTools `VsDevCmd.bat -arch=x64 -host_arch=x64`

Commands:

```text
cmake --build F:\rawrxd\build_ide --target deep2_vulkan_gdn_dispatch_probe --parallel 4
cmake --build F:\rawrxd\build_ide --target deep2_qwen4exp_gdn_probe deep2_qwen4exp_pipeline_probe --parallel 4
cmake --build F:\rawrxd\build_ide --target deep2_engine_lib --parallel 4
ctest --test-dir F:\rawrxd\build_ide -R "deep2_(vulkan_gdn_dispatch|qwen4exp_operator_contract)" --output-on-failure
```

All listed commands completed successfully. `git diff --check` reported no
whitespace errors for the changed source/CMake/probe paths; Git emitted only
the existing LF-to-CRLF normalization notices.

## Artifacts

| Artifact | Size | SHA-256 |
|---|---:|---|
| `build_ide/bin/deep2_vulkan_gdn_dispatch_probe.exe` | 288,256 | `5D7F1D3DB01639C52D0CF85D6B455F8C1A2CECDC97A50705FC86DEF3AB4EDA9B` |
| `build_ide/bin/deep2_qwen4exp_gdn_probe.exe` | 53,760 | `04A9C5C4D4C2C8E534C20BAF9E1984EC4E67F9250FE41CE37F41ADA48AF4299F` |
| `build_ide/bin/deep2_qwen4exp_pipeline_probe.exe` | 34,816 | `26B0426D17A333465BEE63FA99ADBCEBC4BC18B77EE72833C1671FC3D1CD5ABD` |
| `build_ide/deep2_engine_lib.lib` | 57,377,630 | `8818F30AA731E123CAA845A96549EFF37AE5C33CA180F7C4D41B20638B395E1B` |
| `build_ide/rawrxd_gpu_compute.lib` | 9,307,050 | `FB55A0A837DD7C5E2DBCFDD15F058917C0D31E1328D7511CE8820397F823B297` |

