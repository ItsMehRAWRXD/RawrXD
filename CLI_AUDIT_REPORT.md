# RawrXD CLI Audit Report
**Date:** 2026-07-09  
**Scope:** Complete codebase CLI/tooling assessment  
**Auditor:** GitHub Copilot

---

## Executive Summary

The RawrXD codebase has **extensive CLI infrastructure** but suffers from **fragmentation, duplication, and lack of unified access** to the advanced kernel capabilities (L4.x). While there are 40+ CLI entry points, they don't expose the core compression/execution engine features in a cohesive way.

### Key Finding
**The CLI is not "lacking" in quantity—it's lacking in cohesion and kernel integration.**

---

## 1. CLI Inventory (What Exists)

### 1.1 Primary CLI Entry Points

| File | Purpose | Status | Notes |
|------|---------|--------|-------|
| `src/cli/cli_main.cpp` | Hotpatch + pipe processing | ✅ Functional | MASM integration stubbed |
| `src/cli/RawrXDCLI_Main.cpp` | Prometheus 800B MoE engine | ✅ Functional | Benchmark/inference mode |
| `src/cli/rawrxd_cli_compiler.cpp` | Full compiler CLI | ✅ Functional | 2000+ lines, multi-target |
| `src/cli/rawrxd_cli_impl.cpp` | Link shims for CLI | ⚠️ Stub | WebView2 bridge stubs |
| `src/main.cpp` | IDE main entry | ✅ Functional | GUI + CLI hybrid |
| `tools/cli_main.cpp` | Minimal stub | ⚠️ Placeholder | Redirects to full build |

### 1.2 Secondary CLI Tools (46+ executables)

Located in `src/cli/`:
- `inference_cli_minimal.cpp` - Minimal inference
- `hotpatch_client.cpp` - Hotpatch injection
- `swarm_orchestrator.cpp` - Swarm management
- `sovereign_codegen_cli.cpp` - Code generation
- `unified_compiler_cli.cpp` - Compiler interface
- `full_compiler_integration.cpp` - Full compiler
- `quantum_cli_commands.cpp` - Quantum commands
- `codex_cli_integration.cpp` - Codex integration
- `cot_cli_integration.cpp` - Chain-of-thought
- `cli_autonomy_loop.cpp` - Autonomous mode
- `deep_iteration_engine.cpp` - Deep iteration
- `cli_extension_commands.cpp` - Extension commands
- `cli_headless_systems.cpp` - Headless mode
- `cli_stream.cpp` - Streaming interface
- `cli_slashrouter.cpp` - Slash commands
- `agentic_decision_tree.cpp` - Agentic decisions
- `gguf_validator.cpp` - GGUF validation
- `mock_inference_stress_test.cpp` - Stress testing

### 1.3 Batch/Script Launchers

| File | Purpose |
|------|---------|
| `rx.bat` | Main CLI launcher (documented) |
| `rawrxd.bat` | Alternative launcher |
| `Unified-CLI.bat` | Unified entry point |
| `Unified-CLI.ps1` | PowerShell unified launcher |

---

## 2. Kernel Capabilities (L4.x) - CLI Exposure Gap

### 2.1 What L4.x Provides (Not Exposed to CLI)

| Layer | Component | CLI Exposure | Status |
|-------|-----------|------------|--------|
| **L4.1** | GGUF Storage Correctness | ❌ None | **GAP** |
| **L4.2.0** | Compression ABI | ❌ None | **GAP** |
| **L4.2.1** | Numerical Hardening | ❌ None | **GAP** |
| **L4.2.2** | Kernel Registry (RMSNorm, RoPE, Softmax, GEMV) | ❌ None | **GAP** |
| **L4.2.3** | Fused GEMM Validator | ❌ None | **GAP** |
| **L4.3.0** | Tensor Profiler (Sensitivity Analysis) | ❌ None | **GAP** |
| **L4.3.1** | Adaptive Policy Engine | ❌ None | **GAP** |
| **L4.3** | Attention Contracts + Reference | ❌ None | **GAP** |
| **L4.3.1** | AVX2 Optimized Attention | ❌ None | **GAP** |
| **L4.4** | FFN Contracts + Reference + AVX2 | ❌ None | **GAP** |

### 2.2 The Core Problem

**The L4.x execution stack exists but has ZERO CLI integration.**

Users cannot:
- Run a model through the validated kernel registry
- Profile tensor sensitivity from command line
- Apply adaptive compression policies
- Validate fused GEMM implementations
- Execute attention/FFN blocks standalone
- Benchmark the compression codecs (Q4_0, Q4_K_M, Q8_0)

---

## 3. CLI Architecture Issues

### 3.1 Fragmentation

```
CLI Entry Points:
├── src/cli/cli_main.cpp (hotpatch focus)
├── src/cli/RawrXDCLI_Main.cpp (Prometheus focus)
├── src/cli/rawrxd_cli_compiler.cpp (compiler focus)
├── src/main.cpp (IDE focus)
├── tools/cli_main.cpp (stub)
└── 40+ other specialized CLIs

Problem: No unified "rawrxd" command with subcommands
```

### 3.2 Duplication

Multiple files implement similar functionality:
- **Compiler interfaces**: `rawrxd_cli_compiler.cpp`, `unified_compiler_cli.cpp`, `full_compiler_integration.cpp`
- **Inference**: `RawrXDCLI_Main.cpp`, `inference_cli_minimal.cpp`, `inference_main.cpp`
- **Hotpatch**: `cli_main.cpp`, `hotpatch_client.cpp`, `hotpatch_stress_test.cpp`

### 3.3 Documentation Drift

| Document | Claims | Reality |
|----------|--------|---------|
| `CLI_CONTRACT_v1.0.md` | 18 modes operational | Modes 1-18 not exposed in unified CLI |
| `RX_CLI_README.md` | `rx qwen "compile this"` | rx.bat exists but doesn't expose L4.x |
| `CLI_AUDIT.md` | MASM migration ready | No MASM-integrated CLI exists |

---

## 4. What's Missing (Priority Order)

### 🔴 Critical Gaps (Blocking User Value)

1. **Unified `rawrxd` CLI Binary**
   - Single entry point with subcommands
   - `rawrxd inference --model model.gguf --prompt "Hello"`
   - `rawrxd compress --input model.gguf --output compressed.gguf --codec Q4_K_M`
   - `rawrxd benchmark --model model.gguf`

2. **L4.x Kernel Exposure**
   - `rawrxd kernel --list` - Show registered kernels
   - `rawrxd kernel --validate --gemm` - Run fused GEMM validation
   - `rawrxd kernel --profile --model model.gguf` - Tensor sensitivity analysis
   - `rawrxd kernel --policy --budget 4GB` - Adaptive compression planning

3. **Model Operations**
   - `rawrxd inspect --model model.gguf` - GGUF metadata inspection
   - `rawrxd quantize --input fp16.gguf --output q4.gguf --codec Q4_K_M`
   - `rawrxd dequantize --input q4.gguf --output fp16.gguf`

### 🟡 High Priority (Quality of Life)

4. **Configuration Management**
   - `rawrxd config --set key=value`
   - `rawrxd config --get key`
   - `rawrxd config --list`

5. **Logging & Telemetry**
   - `rawrxd logs --tail`
   - `rawrxd telemetry --export`

6. **Testing & Validation**
   - `rawrxd test --kernel-registry`
   - `rawrxd test --attention`
   - `rawrxd test --ffn`
   - `rawrxd test --all`

### 🟢 Nice to Have

7. **Interactive REPL**
   - `rawrxd repl` - Interactive shell with model loaded

8. **Server Mode**
   - `rawrxd serve --port 8080` - HTTP API server

---

## 5. Recommended Implementation Plan

### Phase 1: Unified CLI Foundation (Week 1)

Create `src/cli/unified_cli.cpp`:

```cpp
// Single entry point: rawrxd <command> [args]
int main(int argc, char* argv[]) {
    if (argc < 2) { PrintHelp(); return 0; }
    
    std::string cmd = argv[1];
    if (cmd == "inference") return InferenceCommand(argc-1, argv+1);
    if (cmd == "compress") return CompressCommand(argc-1, argv+1);
    if (cmd == "benchmark") return BenchmarkCommand(argc-1, argv+1);
    if (cmd == "kernel") return KernelCommand(argc-1, argv+1);
    if (cmd == "inspect") return InspectCommand(argc-1, argv+1);
    if (cmd == "test") return TestCommand(argc-1, argv+1);
    // ... etc
}
```

### Phase 2: L4.x Integration (Week 2-3)

Bridge existing L4.x to CLI:

```cpp
// src/cli/commands/kernel_command.cpp
#include "kernels/kernel_registry.h"
#include "kernels/tensor_profiler.h"
#include "kernels/adaptive_policy_engine.h"

int KernelCommand(int argc, char* argv[]) {
    // Expose: kernel --list
    // Expose: kernel --validate
    // Expose: kernel --profile
    // Expose: kernel --policy
}
```

### Phase 3: Deprecation & Migration (Week 4)

- Deprecate fragmented CLIs
- Migrate `rx.bat` to call unified CLI
- Update documentation

---

## 6. File Locations Reference

### Existing CLI Code
- `src/cli/` - 40+ CLI-related files
- `src/main.cpp` - IDE main entry
- `tools/cli_main.cpp` - Minimal stub

### L4.x Kernel Code (Not CLI-Exposed)
- `kernels/fused_gemm_validator.h/cpp` - L4.2.3
- `kernels/tensor_profiler.h/cpp` - L4.3.0
- `kernels/adaptive_policy_engine.h/cpp` - L4.3.1
- `kernels/kernel_registry.h/cpp` - L4.2.2
- `kernels/attention_*.cpp` - L4.3
- `kernels/ffn_*.cpp` - L4.4

### Documentation
- `CLI_CONTRACT_v1.0.md` - Contract spec
- `RX_CLI_README.md` - User-facing docs
- `CLI_AUDIT.md` - Internal audit
- `L4_*_SUMMARY.md` - Kernel documentation

---

## 7. Conclusion

### The Good
- Extensive CLI infrastructure exists
- Multiple specialized tools for different use cases
- Strong foundation in `rawrxd_cli_compiler.cpp`

### The Bad
- **Zero exposure of L4.x kernel capabilities**
- Fragmented entry points confuse users
- Documentation doesn't match implementation

### The Path Forward
1. **Consolidate** 40+ CLIs into unified `rawrxd` binary
2. **Expose** L4.x kernels through subcommands
3. **Document** actual CLI capabilities
4. **Deprecate** fragmented legacy CLIs

**Bottom Line:** Users have no way to access the compression engine, adaptive quantization, or validated execution primitives from the command line. This is the #1 CLI gap.

---

## Appendix: Complete CLI File Inventory

```
src/cli/
├── agentic_decision_tree.cpp
├── agentic_decision_tree.h
├── build_cli.bat
├── cli_abi_v2_hardening.cpp
├── cli_abi_v2_hardening.hpp
├── CLI_AUDIT.md
├── cli_autonomy_loop.cpp
├── cli_autonomy_loop.h
├── CLI_CompilerCommands.cpp
├── cli_extension_commands.cpp
├── cli_extension_commands.hpp
├── cli_feature_bridge.h
├── cli_headless_systems.cpp
├── cli_headless_systems.h
├── cli_main.cpp
├── CLI_SlashRouter.cpp
├── CLI_SlashRouter.hpp
├── cli_stream.cpp
├── CLI_VersionEntry.cpp
├── codex_cli_integration.cpp
├── codex_cli_integration.hpp
├── cot_cli_integration.cpp
├── cot_unified_integration.cpp
├── deep_iteration_engine.cpp
├── deep_iteration_engine.h
├── enhanced_cli.cpp
├── enhanced_cli.h
├── full_compiler_integration.cpp
├── gguf_validator.cpp
├── gguf_validator.hpp
├── hotpatch_bridge.h
├── hotpatch_client.cpp
├── hotpatch_inference_integration.cpp
├── hotpatch_inference_integration.hpp
├── hotpatch_instrumentation_example.cpp
├── hotpatch_memory_safety_test.cpp
├── hotpatch_model_manager.cpp
├── hotpatch_model_manager.hpp
├── hotpatch_stress_test.cpp
├── hotpatch_stress_test.exe
├── inference_cli.exe
├── inference_cli_minimal.cpp
├── inference_worker_rcu.cpp
├── inference_worker_rcu.hpp
├── InteractiveShell.hpp
├── mock_inference_stress_test.cpp
├── pipe_server_callback.cpp
├── quantum_cli_commands.cpp
├── quantum_cli_commands.hpp
├── rawrxd-cli-v2.exe
├── RawrXDCLI_Main.cpp
├── rawrxd_cli.asm
├── RawrXD_CLI.cpp
├── rawrxd_cli.exe
├── rawrxd_cli_compiler.cpp
├── rawrxd_cli_impl.cpp
├── runtime_status_commands.cpp
├── sovereign_codegen_cli.cpp
├── sovereign_compute_test.cpp
├── swarm_orchestrator.cpp
├── swarm_orchestrator.h
├── swarm_tensor_nonmsvc.cpp
├── unified_cli.exe
├── unified_compiler_cli.cpp
├── unified_execution_abi.cpp
└── unified_execution_abi.hpp
```
