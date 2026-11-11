# RawrXD Unlinked Stub Files Report

**Generated:** 2026-07-20  
**Analyzer:** find_stubs_v2.py

---

## Executive Summary

| Metric | Count |
|--------|-------|
| **Files Linked in CMakeLists.txt** | 898 |
| **Total Source Files Found** | 9,886 |
| **Unlinked Stub Files** | **9,001** |
| **Linkage Rate** | 9.1% |

---

## Breakdown by Extension

| Extension | Count | Percentage |
|-----------|-------|--------------|
| `.cpp` | 3,739 | 41.5% |
| `.h` | 2,120 | 23.6% |
| `.hpp` | 1,732 | 19.2% |
| `.asm` | 1,161 | 12.9% |
| `.c` | 249 | 2.8% |
| **TOTAL** | **9,001** | **100%** |

---

## Key Directories with Unlinked Files

### 1. `asm/` Directory (Assembly Files)
**Unlinked:** 1,161+ files

Key unlinked ASM files:
- `CommandPaletteRenderer.asm`
- `FlashAttentionV2_MASM.asm`
- `GGUF_MASM_Adapter.cpp/.h`
- `MatMul_Q4_Q8.asm`
- `RawrXD_120B_Loader.asm`
- `RawrXD_ChatLoop.asm` / `RawrXD_ChatLoop_v2.asm`
- `RawrXD_Detokenizer.asm` / `RawrXD_Detokenizer_v2.asm`
- `RawrXD_Inference.asm`
- `RawrXD_Tokenizer.asm`
- `SovereignMemoryBridge.cpp/.hpp`
- `Sovereign_CPUFeatures.cpp/.hpp`
- `Sovereign_FlashAttention_Intrinsics.cpp`
- `Sovereign_GEMM_Stub.asm`
- `Sovereign_KernelDispatch.cpp/.h`
- `Sovereign_KernelRegistration.cpp/.hpp`
- `Sovereign_KernelRegistry.cpp/.hpp`
- `Sovereign_LayerNorm*.asm` (multiple variants)
- `Sovereign_Q4K_Dequant.asm`
- `Sovereign_Q4Q8_MatMul_AVX512.asm` / `v2`
- `Sovereign_RMSNorm.asm/.h`
- `Sovereign_RoPE.asm/.h`
- `Sovereign_Transformer_Oracle.cpp`
- `Win32IDE_Sidebar_Core.asm`
- Various test and benchmark files

### 2. `include/` Directory (Headers)
**Unlinked:** 2,120+ header files

Key unlinked headers:
- `ASMKernelThreadGate.h`
- `ASMThermalBridge.h`
- `AdvancedCodingAgent.h`
- `AgenticComposer.h`
- `BinaryStream.hpp`
- `BounceTPS.h`
- `CLI11.hpp`
- `CoTMASMBridge.hpp`
- `CodebaseContextAnalyzer.h`
- `CodebaseVectorIndex.h`
- `CompletionEngine.h`
- `DirectionlessLoader.h`
- `EventBus.h`
- `ExtensionEngine_bridge.h`
- `ExtensionInstaller.hpp`
- `ExtensionLoader.hpp`
- `ExtensionManifest.hpp`
- `ExtensionUIState.hpp`
- `FailureModeFirewall.h`
- `GGUFChecksumValidator.h`
- `GGUFVisionHardener.h`
- `GGUF_REVERSE_STREAM_BRIDGE.h`
- `GhostCompletionContext.h`
- `GitMCPBridge.h`
- `HotPatchTPS.h`
- `IDETheme.h`
- `LanguageServerIntegration.h`
- `MultiFileRewriteEngine.h`
- `MultiModalModelRouter.h`
- `NeuralHeatmapRenderer.h`
- `P2PRelay.h`
- `PathResolver.h`

### 3. `src/` Subdirectories
**Unlinked:** 3,739+ .cpp files

Major unlinked source areas:
- `src/agent/` - Agent implementations
- `src/agentic/` - Agentic framework
- `src/core/` - Core engine components
- `src/engine/` - Inference engines
- `src/inference/` - Inference pipelines
- `src/win32app/` - Win32 IDE components
- `src/qtapp/` - Qt application components
- `src/sovereign/` - Sovereign puppeteer
- `src/tools/` - Tool implementations
- `src/security/` - Security components
- `src/memory/` - Memory management
- `src/websocket/` - WebSocket server
- `src/server/` - HTTP server components

---

## Analysis

### Why So Many Unlinked Files?

1. **Archive Directories**: Many files exist in `.archived_orphans/`, `.archive/`, `history/` directories
2. **Experimental Code**: Numerous prototype/experimental implementations
3. **Version Variants**: Multiple versions of same functionality (v1, v2, _fixed, _debug, etc.)
4. **Platform-Specific**: Code for different platforms/backends not currently active
5. **Feature Branches**: Code for features not yet integrated

### Impact on Build

- **CMakeLists.txt** references only **898** files
- **9,001** files are "orphaned" - present but not compiled
- This represents **90.9%** of the codebase being inactive

### Potential Issues

1. **Code Rot**: Unlinked code may become stale
2. **Build Confusion**: Hard to know which files are actually used
3. **Binary Bloat**: If accidentally linked, could increase binary size
4. **Maintenance**: Difficult to maintain unused code

---

## Recommendations

### Immediate Actions

1. **Archive Cleanup**: Move truly obsolete files to `.archive/` or delete
2. **Documentation**: Document which directories contain active vs. archived code
3. **CMakeLists.txt Review**: Verify the 898 linked files are the correct set

### Short-term

4. **Stub Integration**: Review high-value stubs for integration:
   - `Sovereign_*` kernel files
   - `RawrXD_ChatLoop*.asm`
   - `FlashAttentionV2_MASM.asm`
   - Extension system headers

5. **Test Files**: Organize test files and link appropriate ones

### Long-term

6. **Code Audit**: Review all 9,001 unlinked files for:
   - Duplicates (keep newest)
   - Obsolete code (delete)
   - Valuable prototypes (integrate or document)

7. **Directory Restructure**: Consider:
   ```
   src/
     active/     # Currently linked
     staging/    # Ready for integration
     archive/    # Historical reference
     experimental/ # Prototypes
   ```

---

## Full Report

Complete list of all 9,001 unlinked files:  
**`d:\RawrXD\UNLINKED_STUBS_FULL.txt`**

---

## Scripts Created

1. **`find_stubs.py`** - Initial scanner (found 9,884 unlinked)
2. **`find_stubs_v2.py`** - Improved scanner (found 9,001 unlinked)
3. **`find_unlinked_stubs.ps1`** - PowerShell version
4. **`find_unlinked_stubs_fast.ps1`** - Fast PowerShell version

---

*Report generated by RawrXD Stub Analyzer v2.0*
