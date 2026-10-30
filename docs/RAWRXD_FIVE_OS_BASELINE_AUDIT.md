# RAWRXD Five-OS Baseline Audit

**Repository:** `F:\rawrxd`
**Commit:** `7e2d3bf58b` (evidence(gpu): auto PnP bounce Code10 still Error; cold boot required)
**Audit date:** 2026-10-27
**Auditor:** Kilo (primary implementation agent)

## 1. Repository State

### Git Status
- **HEAD:** `7e2d3bf58b` on branch `fix/deep2-multimodel-safety-20261025`
- **Modified files (tracked):** CMakeLists.txt, src/cpu_inference_engine_impl.cpp, tools/agentic_loop_bridge_recovery_smoke.cpp, tools/deep2_agentic_loop.cpp, .rawr/projects/proj_a66154bdb6a1ed87/*.jsonl, .rawr/projects/proj_a66154bdb6a1ed87/*.json, .rawrxd/ledger/agent_session.json, __linearw_range_trace.txt, agentic_ws/plain_logits.gpu.f32
- **Untracked files:** Extensive — WorldForge_Drop{3,4,5}/, build_attempt{1-6}.txt, build_*/ directories, cert_*/, evidence/*, evidence/deep2_fused_lmhead_verify_qwen3_20261026/, evidence/cpu_inference_qwen3_certified_baseline.json, evidence/gguf_residency_qwen3_cpu_20261025.json, many tmp_build/ directories, receipt*.json, nemotron_*.txt, ollama_*.txt, reap_*.json, replay_*.txt, shaders_phase*/, tests/gpu_code31_reset_probe.cpp, tmp_build/**, and many more

### Build Output Locations
- **Primary build dir:** `F:\rawrxd\build_ide\` (CMake + Ninja, MSVC x64)
- **Deploy artifacts:** `F:\rawrxd\deploy\` (RawrXD-Win32IDE.exe 35MB, ggml.dll, llama.dll, etc.)
- **Binaries:** `F:\rawrxd\build_ide\bin-msvc\`, `F:\rawrxd\build_ide\bin\`

## 2. Five OS Targets (from Source Evidence)

The five operating systems are identified from `docs/UNIVERSAL_PLATFORM_GAP_MATRIX.md` and `CMakePresets.json`:

| # | OS | Architecture | Status | Primary Gap |
|---|----|-------------|--------|-------------|
| 1 | Windows | x86-64 | IMPLEMENTED_AND_TESTED | Preserve regression coverage |
| 2 | Linux | x86-64 / ARM64 | IMPLEMENTED_UNTESTED | Native compile/link and runtime proof |
| 3 | macOS | x86-64 / ARM64 | IMPLEMENTED_UNTESTED | Apple toolchain and runtime proof |
| 4 | Android | ARM64 (arm64-v8a) | PARTIAL | NDK integration and APK packaging |
| 5 | iOS | ARM64 | PARTIAL | Xcode, SDK, signing, deployment |

### CMake Presets (from `CMakePresets.json`)
| Preset | Generator | Target | CMake Toolchain File | Status |
|--------|-----------|--------|---------------------|--------|
| `ninja-release` | Ninja | Host (Windows x64) | None (MSVC) | Available |
| `linux-ninja-release` | Ninja | Linux x64/ARM64 | None (host toolchain) | Available on Linux/WSL |
| `darwin-ninja-release` | Ninja | macOS x64/ARM64 | None (host toolchain) | Available on macOS |
| `android-ndk-release` | Ninja | Android arm64-v8a | `$env{ANDROID_NDK}/build/cmake/android.toolchain.cmake` | Requires ANDROID_NDK |
| `ios-xcode-release` | Xcode | iOS ARM64 | `CMAKE_SYSTEM_NAME=iOS` | Requires Xcode on macOS |

## 3. Compiler / Linker Toolchain Inventory (this host: Windows)

### Installed Toolchains
| Tool | Path | Version |
|------|------|---------|
| MSVC cl.exe | `C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\cl.exe` | 14.44.35207 |
| link.exe | `C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\link.exe` | 14.44.35207 |
| MASM ml64.exe | `C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\ml64.exe` | 14.44.35207 |
| Ninja | `C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe` | Latest |
| CMake | Available | Latest |
| Vulkan SDK | `C:\VulkanSDK\1.4.357.0` | 1.4.357.0 |

### NOT Installed on this host
- Clang (for Linux cross-compile)
- Android NDK
- Xcode / macOS SDK
- lld-link, ld64, lld

## 4. Tri-Format Emitter Investigation

### Critical Finding: Missing Headers

The following headers are **referenced in 42+ documentation locations** but **do NOT exist anywhere** in the repository:

| Header | Referenced Functions | Docs Count | Exists |
|--------|---------------------|------------|--------|
| `include/rawrxd/sovereign_emit_formats.hpp` | `composePe64MinimalImage`, `composeElf64MinimalImage`, `composeMacho64MinimalImage`, `emitBlueprintFromManifest`, `emitMinimalHeaderFromManifest` | 20+ | **MISSING** |
| `include/rawrxd/sovereign_target_manifest.hpp` | `TargetManifest` C++ definition | 3+ | **MISSING** |
| `include/rawrxd/sovereign_lab_blob_io.hpp` | `readWholeFile`, `tryExtractCoffSection`, `tryExtractElf64ProgBitsSection` | 5+ | **MISSING** |

### Existing Toolchain Code

| Component | Location | Status |
|-----------|----------|--------|
| Phase 2 PE linker (research) | `_pre_merge_backup/toolchain/from_scratch/phase2_linker/` | EXISTS (backup only, not in main tree) |
| PE writer | `_pre_merge_backup/toolchain/from_scratch/phase2_linker/pe_writer.c` | 443 lines, complete PE32+ writer |
| COFF reader | `_pre_merge_backup/toolchain/from_scratch/phase2_linker/coff_reader.c` | EXISTS |
| Section merger | `_pre_merge_backup/toolchain/from_scratch/phase2_linker/section_merge.c` | EXISTS |
| Relocation resolver | `_pre_merge_backup/toolchain/from_scratch/phase2_linker/reloc_resolver.c` | EXISTS |
| `toolchain/` directory | **NOT IN MAIN TREE** | MISSING from main source |

### Classification
- **Tri-format emitter (PE/ELF/Mach-O compose functions):** STUB — documented but not implemented in main tree
- **Phase 2 PE linker:** PARTIAL — exists in backup, not integrated into CMake build
- **Target manifest C++ struct:** STUB — documented in spec, no header implementation

## 5. Build System

### CMakeLists.txt
- **Size:** 5,862 lines (monolithic)
- **Project:** `RawrXD-ModelLoader VERSION 1.0.13`
- **C++ Standard:** C++20
- **64-bit only:** Enforced (`CMAKE_SIZEOF_VOID_P EQUAL 8`)
- **MSVC runtime:** `/MD` (dynamic CRT) for all configs
- **MASM:** Enabled for custom ZLIB implementation
- **Qt:** Optional (`RAWRXD_BUILD_WIN32IDE_QT` defaults OFF)

### Major Targets (from CMakeLists.txt)
- `RawrXD-Win32IDE-Native` — Native Qt-free Win32 IDE (MSVC only)
- `RawrXD-Agent` — Autonomous coding agent
- `RawrXD-Compiler` — CLI compiler tool (Qt-dependent)
- `RawrXD-CLI` — Command-line interface
- `RawrXD-IDE` — Qt IDE
- `RawrXD-SimpleIDE` — Simple IDE
- `RawrXD-Chromatic` — D3D11 demo
- `deep2_engine_lib` — Deep2 inference engine library
- `rawrxd_deep2_engine` — Deep2 engine executable
- `cpu_inference_engine` — Static library (CPU inference)
- ~40+ Deep2 tools and test executables
- ~20+ Agent/IDE tools

## 6. Evidence Locations

| Evidence Type | Path |
|---------------|------|
| CPU inference Qwen3 baseline | `evidence/cpu_inference_qwen3_certified_baseline.json` |
| GGUF residency Qwen3 CPU | `evidence/gguf_residency_qwen3_cpu_20261025.json` |
| Deep2 fused LM head verify | `evidence/deep2_fused_lmhead_verify_qwen3_20261026/` |
| Reap runtime current | `evidence/reap_runtime_current_20261026_qwen3_cpu_*.json` |
| Reap continuous | `evidence/reap_continuous_20261025.json` |
| Reap family smoke | `evidence/reap_family_smoke_20261026.json` |
| Reap topology | `evidence/reap_topology_*.json` |
| Parity current | `evidence/parity_current_20261026_cpu/`, `evidence/parity_current_20261026_gpu/` |
| Certified baseline snapshot | `evidence/certified_baseline_snapshot/` |

## 7. Known Blockers

1. **Tri-format emitter headers missing:** `sovereign_emit_formats.hpp`, `sovereign_target_manifest.hpp`, `sovereign_lab_blob_io.hpp` referenced in docs but not in source tree
2. **Phase 2 linker in backup only:** `toolchain/from_scratch/phase2_linker/` exists in `_pre_merge_backup/` but not integrated into main CMake build
3. **Android NDK not available:** No `ANDROID_NDK` environment variable, no NDK installed on this Windows host
4. **macOS/iOS toolchains not available:** No Xcode, no macOS host, no ld64/codesign
5. **Linux not available on this host:** No WSL2, no Linux VM, no clang cross-compiler
6. **Working tree dirty:** Many modified and untracked files must be preserved

## 8. Classification Summary

| Component | Classification |
|-----------|---------------|
| Windows build (MSVC/Ninja) | IMPLEMENTED_AND_TESTED |
| Linux CMake preset | IMPLEMENTED_UNTESTED |
| macOS CMake preset | IMPLEMENTED_UNTESTED |
| Android NDK CMake preset | PARTIAL (no NDK on host) |
| iOS Xcode CMake preset | PARTIAL (no Xcode on host) |
| Tri-format emitter headers | STUB (documented, not implemented) |
| Phase 2 PE linker | PARTIAL (backup only) |
| Target manifest C++ struct | STUB |
| CPU inference (Qwen3 8B) | IMPLEMENTED_UNTESTED (fixes applied, e2e not retested post-fix) |
| Deep2 engine | IMPLEMENTED_UNTESTED |
| REAP | IMPLEMENTED_UNTESTED |
