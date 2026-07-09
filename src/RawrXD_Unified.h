// RawrXD_Unified.h - MASTER HEADER FOR ALL CS TOOLS ON DRIVE D
// Version: 4.0 - Complete Unification
// Date: 2026-07-08
// Total Tools: 200+ executables, 10,000+ sources, 500+ scripts

#ifndef RAWRXD_UNIFIED_H
#define RAWRXD_UNIFIED_H

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <direct.h>
#include <process.h>

// ============================================
// VERSION INFO
// ============================================
#define UNIFIED_VERSION "4.0"
#define UNIFIED_DATE "2026-07-08"
#define TOTAL_EXECUTABLES 205
#define TOTAL_CATALOGED 10705

// ============================================
// PATH DEFINITIONS - CORE IDE & RUNTIME
// ============================================

// Main IDE Variants
#define PATH_RAWRXD_HYBRID      "d:\\rawrxd\\RawrXD_Hybrid.exe"
#define PATH_RAWRXD_IDE         "d:\\rawrxd\\RawrXD_IDE.exe"
#define PATH_RAWRXD_IDE_UNIFIED "d:\\rawrxd\\RawrXD_IDE_unified.exe"
#define PATH_RAWRXD_GUI         "d:\\rawrxd\\RawrXD.exe"
#define PATH_RAWRXD_FIXED       "d:\\rawrxd\\RawrXD_fixed.exe"
#define PATH_RAWRXD_PRODUCTION  "d:\\rawrxd\\RawrXD_Production.exe"

// Versioned IDE Series
#define PATH_RAWRXD_V320        "d:\\rawrxd\\RawrXD_v3.2.0_FileOpeningFixed.exe"
#define PATH_RAWRXD_V310        "d:\\rawrxd\\RawrXD_v3.1.0.exe"
#define PATH_RAWRXD_V3013       "d:\\rawrxd\\RawrXD_v3.0.13.0.exe"
#define PATH_RAWRXD_V3012       "d:\\rawrxd\\RawrXD_v3.0.12.0.exe"
#define PATH_RAWRXD_V3011       "d:\\rawrxd\\RawrXD_v3.0.11.0.exe"
#define PATH_RAWRXD_V3010       "d:\\rawrxd\\RawrXD_v3.0.10.0.exe"
#define PATH_RAWRXD_V309        "d:\\rawrxd\\RawrXD_v3.0.9.0.exe"

// Sovereign Series
#define PATH_SOVEREIGN_CLI      "d:\\rawrxd\\sovereign_cli.exe"
#define PATH_SOVEREIGN_V2       "d:\\rawrxd\\sovereign_v2.exe"
#define PATH_SOVEREIGN_RUNTIME  "d:\\rawrxd\\sovereign_runtime.exe"
#define PATH_SOVEREIGN_THINKING "d:\\rawrxd\\sovereign_thinking_demo.exe"
#define PATH_SOV_SMOKE_TEST     "d:\\rawrxd\\_sov_smoke_test.exe"

// Titan Engine Series
#define PATH_TITAN_800B         "d:\\rawrxd\\TITAN_800B_PRODUCTION.exe"
#define PATH_TITAN_SWARM        "d:\\rawrxd\\TITAN_SWARM_DEPLOY.exe"
#define PATH_TITAN_FULL         "d:\\rawrxd\\TITAN_FULL_INTEGRATION.exe"
#define PATH_TITAN_CLEAN        "d:\\rawrxd\\titan_clean.exe"
#define PATH_TITAN_SOVEREIGN    "d:\\rawrxd\\Titan_Sovereign_Engine_Final.exe"
#define PATH_TITAN_4D           "d:\\rawrxd\\RawrXD_Titan_4D.exe"

// Autonomous & Special
#define PATH_RAWRXD_AUTONOMOUS  "d:\\rawrxd\\RAWRXD_IDE_AUTONOMOUS.exe"
#define PATH_RAWRXD_AUTONOMOUS_GCC "d:\\rawrxd\\RAWRXD_IDE_AUTONOMOUS_gcc.exe"
#define PATH_SUNSHINE_HOTPATCH  "d:\\rawrxd\\Sunshine_Hotpatch.exe"
#define PATH_AGENT_AGENT        "d:\\rawrxd\\AgentAgent.exe"

// Amphibious Kernel
#define PATH_AMPHIBIOUS_AGENT   "d:\\rawrxd\\RawrXD_Amphibious_FullKernel_Agent.exe"
#define PATH_AMPHIBIOUS_FULL    "d:\\rawrxd\\RawrXD_Amphibious_FullKernel.exe"

// ============================================
// PATH DEFINITIONS - 50+ COMPILERS
// ============================================

// Native Toolchain
#define PATH_CC                 "d:\\rawrxd\\native_toolchain\\c_compiler_minimal.exe"
#define PATH_ASM                "d:\\rawrxd\\native_toolchain\\minimal_assembler_fixed.exe"
#define PATH_LD                 "d:\\rawrxd\\native_toolchain\\linker_with_relocations.exe"

// Language Compilers (RawrXD versions)
#define PATH_PYTHON_COMP        "d:\\rawrxd\\compilers\\python_compiler_real.exe"
#define PATH_JS_COMP            "d:\\rawrxd\\compilers\\javascript_compiler_real.exe"
#define PATH_BASH_COMP          "d:\\rawrxd\\compilers\\bash_compiler_real.exe"
#define PATH_POWERSHELL_COMP    "d:\\rawrxd\\compilers\\powershell_compiler_real.exe"
#define PATH_CSHARP_COMP        "d:\\rawrxd\\compilers\\csharp_compiler_real.exe"
#define PATH_JAVA_COMP          "d:\\rawrxd\\compilers\\java_compiler_real.exe"
#define PATH_EON_COMP           "d:\\rawrxd\\compilers\\eon_compiler_real.exe"
#define PATH_RUST_COMP          "d:\\rawrxd\\compilers\\rust_compiler_real.exe"
#define PATH_GO_COMP            "d:\\rawrxd\\compilers\\go_compiler_real.exe"
#define PATH_RUBY_COMP          "d:\\rawrxd\\compilers\\ruby_compiler_real.exe"
#define PATH_PHP_COMP           "d:\\rawrxd\\compilers\\php_compiler_real.exe"
#define PATH_TYPESCRIPT_COMP    "d:\\rawrxd\\compilers\\typescript_compiler_real.exe"
#define PATH_LUA_COMP           "d:\\rawrxd\\compilers\\lua_compiler_real.exe"
#define PATH_PERL_COMP          "d:\\rawrxd\\compilers\\perl_compiler_real.exe"
#define PATH_KOTLIN_COMP        "d:\\rawrxd\\compilers\\kotlin_compiler_real.exe"
#define PATH_SCALA_COMP         "d:\\rawrxd\\compilers\\scala_compiler_real.exe"
#define PATH_SWIFT_COMP         "d:\\rawrxd\\compilers\\swift_compiler_real.exe"
#define PATH_CPP_COMP           "d:\\rawrxd\\compilers\\cpp_compiler_real.exe"
#define PATH_C_COMP             "d:\\rawrxd\\compilers\\c_compiler_real.exe"
#define PATH_FORTRAN_COMP       "d:\\rawrxd\\compilers\\fortran_compiler_real.exe"
#define PATH_COBOL_COMP         "d:\\rawrxd\\compilers\\cobol_compiler_real.exe"
#define PATH_JULIA_COMP         "d:\\rawrxd\\compilers\\julia_compiler_real.exe"
#define PATH_DART_COMP          "d:\\rawrxd\\compilers\\dart_compiler_real.exe"
#define PATH_R_COMP             "d:\\rawrxd\\compilers\\r_compiler_real.exe"
#define PATH_MATLAB_COMP        "d:\\rawrxd\\compilers\\matlab_compiler_real.exe"
#define PATH_GROOVY_COMP        "d:\\rawrxd\\compilers\\groovy_compiler_real.exe"
#define PATH_CLOJURE_COMP       "d:\\rawrxd\\compilers\\clojure_compiler_real.exe"
#define PATH_HASKELL_COMP       "d:\\rawrxd\\compilers\\haskell_compiler_real.exe"
#define PATH_ERLANG_COMP        "d:\\rawrxd\\compilers\\erlang_compiler_real.exe"
#define PATH_ELIXIR_COMP        "d:\\rawrxd\\compilers\\elixir_compiler_real.exe"
#define PATH_OCAML_COMP         "d:\\rawrxd\\compilers\\ocaml_compiler_real.exe"
#define PATH_LISP_COMP          "d:\\rawrxd\\compilers\\lisp_compiler_real.exe"
#define PATH_SCHEME_COMP        "d:\\rawrxd\\compilers\\scheme_compiler_real.exe"
#define PATH_FSHARP_COMP        "d:\\rawrxd\\compilers\\fsharp_compiler_real.exe"
#define PATH_VB_COMP            "d:\\rawrxd\\compilers\\vb_compiler_real.exe"
#define PATH_OBJC_COMP          "d:\\rawrxd\\compilers\\objc_compiler_real.exe"
#define PATH_D_COMP             "d:\\rawrxd\\compilers\\d_compiler_real.exe"
#define PATH_NIM_COMP           "d:\\rawrxd\\compilers\\nim_compiler_real.exe"
#define PATH_ZIG_COMP           "d:\\rawrxd\\compilers\\zig_compiler_real.exe"
#define PATH_CRYSTAL_COMP       "d:\\rawrxd\\compilers\\crystal_compiler_real.exe"
#define PATH_V_COMP             "d:\\rawrxd\\compilers\\v_compiler_real.exe"
#define PATH_ODIN_COMP          "d:\\rawrxd\\compilers\\odin_compiler_real.exe"

// Build Tools
#define PATH_RAWRXD_COMPILER    "d:\\rawrxd\\build\\rawrxd_compiler.exe"
#define PATH_RAWRXD_LINKER      "d:\\rawrxd\\build\\rawrxd_linker.exe"
#define PATH_RAWRXD_COFFDUMP    "d:\\rawrxd\\build\\rawrxd_coffdump.exe"
#define PATH_PIPELINE_ORCH      "d:\\rawrxd\\build\\pipeline_orchestrator.exe"
#define PATH_BUILD_AUTO         "d:\\rawrxd\\build\\build_automation.exe"

// ============================================
// PATH DEFINITIONS - TESTING & BENCHMARKING
// ============================================

// Titan Tests
#define PATH_TI_TEST            "d:\\rawrxd\\ti_test.exe"
#define PATH_TI_LOAD_TEST       "d:\\rawrxd\\ti_load_test.exe"
#define PATH_TITAN_LOG_ANALYZER "d:\\rawrxd\\Titan_Log_Analyzer.exe"

// Phase Tests
#define PATH_TEST_PHASE19       "d:\\rawrxd\\test_phase19.exe"
#define PATH_TEST_PHASE20       "d:\\rawrxd\\test_phase20.exe"
#define PATH_TEST_PHASE21       "d:\\rawrxd\\test_phase21.exe"
#define PATH_TEST_PHASE22       "d:\\rawrxd\\test_phase22.exe"
#define PATH_TEST_PHASE23       "d:\\rawrxd\\test_phase23.exe"
#define PATH_TEST_PHASE24       "d:\\rawrxd\\test_phase24.exe"
#define PATH_TEST_PHASE25       "d:\\rawrxd\\test_phase25.exe"
#define PATH_TEST_PHASE26       "d:\\rawrxd\\test_phase26.exe"

// Phase 3C
#define PATH_PHASE3C_QUICK      "d:\\rawrxd\\Phase3CQuick.exe"
#define PATH_PHASE3C_CONTENTION "d:\\rawrxd\\Phase3CContention2.exe"

// Stress Tests
#define PATH_SOAK1024           "d:\\rawrxd\\Soak1024.exe"
#define PATH_CONTENTION3        "d:\\rawrxd\\Contention3.exe"
#define PATH_LOCK_TEST          "d:\\rawrxd\\LockTest.exe"
#define PATH_GOLDEN             "d:\\rawrxd\\Golden.exe"
#define PATH_IDX72              "d:\\rawrxd\\Idx72.exe"

// Benchmarks
#define PATH_RAWRXD_BENCHMARK   "d:\\rawrxd\\RawrXD_Benchmark.exe"
#define PATH_STANDALONE_BENCH   "d:\\rawrxd\\standalone_benchmark.exe"
#define PATH_BENCHMARK_KERNEL   "d:\\rawrxd\\benchmark_kernel.exe"
#define PATH_PATTERN_MICROBENCH "d:\\rawrxd\\pattern_microbench.exe"
#define PATH_PERF_RUNNER        "d:\\rawrxd\\performance_runner.exe"

// Specialized Tests
#define PATH_TEST_RBTREE        "d:\\rawrxd\\test_rbtree.exe"
#define PATH_TEST_AGENT_HOTPATCH "d:\\rawrxd\\test_agent_hot_patcher.exe"
#define PATH_TEST_FUSION        "d:\\rawrxd\\test_fusion.exe"
#define PATH_TEST_DIAGNOSTIC    "d:\\rawrxd\\test_diagnostic.exe"
#define PATH_SWARM_LINK_TEST    "d:\\rawrxd\\swarm_link_test.exe"

// ============================================
// PATH DEFINITIONS - MODEL & INFERENCE
// ============================================

#define PATH_TEST_MODEL_LOADING "d:\\rawrxd\\test_model_loading.exe"
#define PATH_TEST_BLOCKED_GEMM  "d:\\rawrxd\\test_blocked_gemm.exe"
#define PATH_TEST_BLOCKED_GEMM2 "d:\\rawrxd\\test_blocked_gemm2.exe"
#define PATH_TEST_GEMM          "d:\\rawrxd\\test_gemm.exe"
#define PATH_TEST_GEMM_V2       "d:\\rawrxd\\test_gemm_v2.exe"
#define PATH_TEST_GEMM_DEBUG    "d:\\rawrxd\\test_gemm_debug.exe"
#define PATH_TEST_RMSNORM       "d:\\rawrxd\\test_rmsnorm.exe"
#define PATH_VERIFY_RMSNORM     "d:\\rawrxd\\verify_rmsnorm.exe"

// LoRA Tools
#define PATH_TEST_LORA_KERNEL   "d:\\rawrxd\\test_lora_kernel.exe"
#define PATH_TEST_LORA_PROGRESSIVE "d:\\rawrxd\\test_lora_progressive.exe"
#define PATH_TEST_LORA_MINIMAL  "d:\\rawrxd\\test_lora_minimal.exe"
#define PATH_TEST_LORA_DIAGNOSTIC "d:\\rawrxd\\test_lora_diagnostic.exe"
#define PATH_SIMPLE_LORA_TEST   "d:\\rawrxd\\simple_lora_test.exe"

// HTTP/Network
#define PATH_TEST_HTTP_CHAT     "d:\\rawrxd\\test_http_chat_integration.exe"
#define PATH_TEST_P2P           "d:\\rawrxd\\test_p2p.exe"
#define PATH_TEST_P2P_NEW       "d:\\rawrxd\\test_p2p_new.exe"

// ============================================
// PATH DEFINITIONS - GPU & COMPUTE
// ============================================

#define PATH_TEST_GPU_BACKEND   "d:\\rawrxd\\test_gpu_backend.exe"

// ============================================
// PATH DEFINITIONS - DEBUG & DEVELOPMENT
// ============================================

#define PATH_DEBUG_RMSNORM      "d:\\rawrxd\\debug_rmsnorm.exe"
#define PATH_DEBUG_ACCUMULATORS "d:\\rawrxd\\debug_accumulators.exe"
#define PATH_DEBUG_MICROKERNEL  "d:\\rawrxd\\debug_microkernel.exe"
#define PATH_DEBUG_RAX          "d:\\rawrxd\\debug_rax.exe"
#define PATH_DEBUG_HANG         "d:\\rawrxd\\debug_hang.exe"
#define PATH_MINIMAL_TEST       "d:\\rawrxd\\minimal_test.exe"
#define PATH_DIRECT_TEST        "d:\\rawrxd\\direct_test.exe"
#define PATH_TEST_STUB          "d:\\rawrxd\\test_stub.exe"
#define PATH_RRAWRWRA_EDITOR    "d:\\rawrxd\\rrawrawra_editor_v2.exe"
#define PATH_BATCH3_DEMO        "d:\\rawrxd\\batch3_simple_demo.exe"

// ============================================
// TOOL STRUCTURE
// ============================================

struct Tool {
    const char* id;
    const char* name;
    const char* path;
    const char* type;       // "ide", "compiler", "test", "benchmark", "model", "gpu", "debug", "build"
    const char* category;   // "core", "language", "testing", "ml", "compute", "dev", "system"
    const char* language; // For compilers: "C", "Python", etc. NULL otherwise
    int priority;           // 0=P0, 1=P1, 2=P2, 3=P3
    BOOL available;
};

// ============================================
// FUNCTION DECLARATIONS
// ============================================

// Initialization
void InitTools(struct Tool* tools);
void PrintBanner(void);
void PrintTools(struct Tool* tools);
void PrintToolsByCategory(struct Tool* tools);
void PrintToolsByType(struct Tool* tools);
void PrintCompilers(struct Tool* tools);

// Tool Management
BOOL CheckTool(struct Tool* tools, const char* id);
struct Tool* GetTool(struct Tool* tools, const char* id);
BOOL LaunchTool(struct Tool* tools, const char* id, const char* args);
BOOL LaunchToolAsync(struct Tool* tools, const char* id, const char* args);

// Build System
BOOL BuildC(struct Tool* tools, const char* sourceFile, const char* outputFile);
BOOL BuildProject(struct Tool* tools, const char* projectPath);

// Batch Operations
void RunBatchTests(struct Tool* tools, const char* category);
void RunBatchBenchmarks(struct Tool* tools);
void RunAllCompilers(struct Tool* tools);
void RunAllTests(struct Tool* tools);
void RunAllByType(struct Tool* tools, const char* type);

// Display
void ShowHelp(void);
void ShowStatus(struct Tool* tools);
void ShowCategories(void);
void ShowLanguages(void);

// Main Loop
void RunCLILoop(struct Tool* tools);
int ProcessCommand(struct Tool* tools, char* input);

#endif // RAWRXD_UNIFIED_H
