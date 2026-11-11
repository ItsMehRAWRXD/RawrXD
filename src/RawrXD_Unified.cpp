// RawrXD_Unified.cpp - MASTER UNIFICATION CLI FOR ALL CS TOOLS
// Version: 4.0 - Complete Drive D Unification
// Total Components: 200+ executables, 10,000+ sources, 500+ scripts

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "RawrXD_Unified.h"
#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")

// ============================================
// MASTER TOOL REGISTRY - ALL 200+ TOOLS
// ============================================

struct Tool g_tools[] = {
    // ============================================
    // CORE IDE & RUNTIME (P0 - Critical)
    // ============================================
    {"ide", "RawrXD IDE", PATH_RAWRXD_GUI, "ide", "core", NULL, 0, FALSE},
    {"hybrid", "RawrXD Hybrid IDE", PATH_RAWRXD_HYBRID, "ide", "core", NULL, 0, FALSE},
    {"sovereign", "Sovereign CLI", PATH_SOVEREIGN_CLI, "ide", "core", NULL, 0, FALSE},
    {"sov2", "Sovereign v2", PATH_SOVEREIGN_V2, "ide", "core", NULL, 0, FALSE},
    {"sov-runtime", "Sovereign Runtime", PATH_SOVEREIGN_RUNTIME, "ide", "core", NULL, 0, FALSE},
    {"sov-thinking", "Sovereign Thinking Demo", PATH_SOVEREIGN_THINKING, "ide", "core", NULL, 0, FALSE},
    {"sov-smoke", "Sovereign Smoke Test", PATH_SOV_SMOKE_TEST, "test", "core", NULL, 0, FALSE},
    
    // Titan Engine
    {"titan", "Titan 800B Production", PATH_TITAN_800B, "ide", "core", NULL, 0, FALSE},
    {"titan-swarm", "Titan Swarm Deploy", PATH_TITAN_SWARM, "ide", "core", NULL, 0, FALSE},
    {"titan-full", "Titan Full Integration", PATH_TITAN_FULL, "ide", "core", NULL, 0, FALSE},
    {"titan-clean", "Titan Clean", PATH_TITAN_CLEAN, "ide", "core", NULL, 0, FALSE},
    {"titan-sov", "Titan Sovereign Engine", PATH_TITAN_SOVEREIGN, "ide", "core", NULL, 0, FALSE},
    {"titan-4d", "Titan 4D", PATH_TITAN_4D, "ide", "core", NULL, 0, FALSE},
    
    // Production & Special
    {"production", "RawrXD Production", PATH_RAWRXD_PRODUCTION, "ide", "core", NULL, 0, FALSE},
    {"autonomous", "RawrXD Autonomous", PATH_RAWRXD_AUTONOMOUS, "ide", "core", NULL, 0, FALSE},
    {"autonomous-gcc", "RawrXD Autonomous GCC", PATH_RAWRXD_AUTONOMOUS_GCC, "ide", "core", NULL, 0, FALSE},
    {"hotpatch", "Sunshine Hotpatch", PATH_SUNSHINE_HOTPATCH, "ide", "core", NULL, 0, FALSE},
    {"agent-agent", "Agent Agent", PATH_AGENT_AGENT, "ide", "core", NULL, 0, FALSE},
    
    // Amphibious Kernel
    {"amphibious", "RawrXD Amphibious Kernel", PATH_AMPHIBIOUS_FULL, "gpu", "core", NULL, 0, FALSE},
    {"amphibious-agent", "RawrXD Amphibious Agent", PATH_AMPHIBIOUS_AGENT, "gpu", "core", NULL, 0, FALSE},
    
    // Versioned IDE
    {"rawrxd-v320", "RawrXD v3.2.0", PATH_RAWRXD_V320, "ide", "core", NULL, 1, FALSE},
    {"rawrxd-v310", "RawrXD v3.1.0", PATH_RAWRXD_V310, "ide", "core", NULL, 1, FALSE},
    {"rawrxd-v3013", "RawrXD v3.0.13", PATH_RAWRXD_V3013, "ide", "core", NULL, 1, FALSE},
    {"rawrxd-v3012", "RawrXD v3.0.12", PATH_RAWRXD_V3012, "ide", "core", NULL, 1, FALSE},
    {"rawrxd-v3011", "RawrXD v3.0.11", PATH_RAWRXD_V3011, "ide", "core", NULL, 1, FALSE},
    {"rawrxd-v3010", "RawrXD v3.0.10", PATH_RAWRXD_V3010, "ide", "core", NULL, 1, FALSE},
    {"rawrxd-v309", "RawrXD v3.0.9", PATH_RAWRXD_V309, "ide", "core", NULL, 1, FALSE},
    {"rawrxd-fixed", "RawrXD Fixed", PATH_RAWRXD_FIXED, "ide", "core", NULL, 1, FALSE},
    {"rawrxd-ide-uni", "RawrXD IDE Unified", PATH_RAWRXD_IDE_UNIFIED, "ide", "core", NULL, 1, FALSE},
    
    // ============================================
    // NATIVE TOOLCHAIN (P0)
    // ============================================
    {"cc", "C Compiler (Native)", PATH_CC, "compiler", "system", "C", 0, FALSE},
    {"asm", "Native Assembler", PATH_ASM, "compiler", "system", "ASM", 0, FALSE},
    {"ld", "Native Linker", PATH_LD, "compiler", "system", "LD", 0, FALSE},
    
    // ============================================
    // 50+ LANGUAGE COMPILERS (P1)
    // ============================================
    {"python", "Python Compiler", PATH_PYTHON_COMP, "compiler", "language", "Python", 1, FALSE},
    {"javascript", "JavaScript Compiler", PATH_JS_COMP, "compiler", "language", "JavaScript", 1, FALSE},
    {"js", "JavaScript Compiler", PATH_JS_COMP, "compiler", "language", "JavaScript", 1, FALSE},
    {"bash", "Bash Compiler", PATH_BASH_COMP, "compiler", "language", "Bash", 1, FALSE},
    {"powershell", "PowerShell Compiler", PATH_POWERSHELL_COMP, "compiler", "language", "PowerShell", 1, FALSE},
    {"ps", "PowerShell Compiler", PATH_POWERSHELL_COMP, "compiler", "language", "PowerShell", 1, FALSE},
    {"csharp", "C# Compiler", PATH_CSHARP_COMP, "compiler", "language", "C#", 1, FALSE},
    {"cs", "C# Compiler", PATH_CSHARP_COMP, "compiler", "language", "C#", 1, FALSE},
    {"java", "Java Compiler", PATH_JAVA_COMP, "compiler", "language", "Java", 1, FALSE},
    {"eon", "Eon Compiler", PATH_EON_COMP, "compiler", "language", "Eon", 1, FALSE},
    {"rust", "Rust Compiler", PATH_RUST_COMP, "compiler", "language", "Rust", 1, FALSE},
    {"go", "Go Compiler", PATH_GO_COMP, "compiler", "language", "Go", 1, FALSE},
    {"ruby", "Ruby Compiler", PATH_RUBY_COMP, "compiler", "language", "Ruby", 1, FALSE},
    {"php", "PHP Compiler", PATH_PHP_COMP, "compiler", "language", "PHP", 1, FALSE},
    {"typescript", "TypeScript Compiler", PATH_TYPESCRIPT_COMP, "compiler", "language", "TypeScript", 1, FALSE},
    {"ts", "TypeScript Compiler", PATH_TYPESCRIPT_COMP, "compiler", "language", "TypeScript", 1, FALSE},
    {"lua", "Lua Compiler", PATH_LUA_COMP, "compiler", "language", "Lua", 1, FALSE},
    {"perl", "Perl Compiler", PATH_PERL_COMP, "compiler", "language", "Perl", 1, FALSE},
    {"kotlin", "Kotlin Compiler", PATH_KOTLIN_COMP, "compiler", "language", "Kotlin", 1, FALSE},
    {"scala", "Scala Compiler", PATH_SCALA_COMP, "compiler", "language", "Scala", 1, FALSE},
    {"swift", "Swift Compiler", PATH_SWIFT_COMP, "compiler", "language", "Swift", 1, FALSE},
    {"cpp", "C++ Compiler", PATH_CPP_COMP, "compiler", "language", "C++", 1, FALSE},
    {"c", "C Compiler", PATH_C_COMP, "compiler", "language", "C", 1, FALSE},
    {"fortran", "Fortran Compiler", PATH_FORTRAN_COMP, "compiler", "language", "Fortran", 1, FALSE},
    {"cobol", "COBOL Compiler", PATH_COBOL_COMP, "compiler", "language", "COBOL", 1, FALSE},
    {"julia", "Julia Compiler", PATH_JULIA_COMP, "compiler", "language", "Julia", 1, FALSE},
    {"dart", "Dart Compiler", PATH_DART_COMP, "compiler", "language", "Dart", 1, FALSE},
    {"r", "R Compiler", PATH_R_COMP, "compiler", "language", "R", 1, FALSE},
    {"matlab", "MATLAB Compiler", PATH_MATLAB_COMP, "compiler", "language", "MATLAB", 1, FALSE},
    {"groovy", "Groovy Compiler", PATH_GROOVY_COMP, "compiler", "language", "Groovy", 1, FALSE},
    {"clojure", "Clojure Compiler", PATH_CLOJURE_COMP, "compiler", "language", "Clojure", 1, FALSE},
    {"haskell", "Haskell Compiler", PATH_HASKELL_COMP, "compiler", "language", "Haskell", 1, FALSE},
    {"erlang", "Erlang Compiler", PATH_ERLANG_COMP, "compiler", "language", "Erlang", 1, FALSE},
    {"elixir", "Elixir Compiler", PATH_ELIXIR_COMP, "compiler", "language", "Elixir", 1, FALSE},
    {"ocaml", "OCaml Compiler", PATH_OCAML_COMP, "compiler", "language", "OCaml", 1, FALSE},
    {"lisp", "Lisp Compiler", PATH_LISP_COMP, "compiler", "language", "Lisp", 1, FALSE},
    {"scheme", "Scheme Compiler", PATH_SCHEME_COMP, "compiler", "language", "Scheme", 1, FALSE},
    {"fsharp", "F# Compiler", PATH_FSHARP_COMP, "compiler", "language", "F#", 1, FALSE},
    {"fs", "F# Compiler", PATH_FSHARP_COMP, "compiler", "language", "F#", 1, FALSE},
    {"vb", "VB Compiler", PATH_VB_COMP, "compiler", "language", "VB", 1, FALSE},
    {"objc", "Objective-C Compiler", PATH_OBJC_COMP, "compiler", "language", "Objective-C", 1, FALSE},
    {"d", "D Compiler", PATH_D_COMP, "compiler", "language", "D", 1, FALSE},
    {"nim", "Nim Compiler", PATH_NIM_COMP, "compiler", "language", "Nim", 1, FALSE},
    {"zig", "Zig Compiler", PATH_ZIG_COMP, "compiler", "language", "Zig", 1, FALSE},
    {"crystal", "Crystal Compiler", PATH_CRYSTAL_COMP, "compiler", "language", "Crystal", 1, FALSE},
    {"v", "V Compiler", PATH_V_COMP, "compiler", "language", "V", 1, FALSE},
    {"odin", "Odin Compiler", PATH_ODIN_COMP, "compiler", "language", "Odin", 1, FALSE},
    
    // ============================================
    // BUILD TOOLS (P1)
    // ============================================
    {"rawrxd-cc", "RawrXD Compiler", PATH_RAWRXD_COMPILER, "build", "system", NULL, 1, FALSE},
    {"rawrxd-ld", "RawrXD Linker", PATH_RAWRXD_LINKER, "build", "system", NULL, 1, FALSE},
    {"coffdump", "COFF Dump", PATH_RAWRXD_COFFDUMP, "build", "system", NULL, 1, FALSE},
    {"pipeline", "Pipeline Orchestrator", PATH_PIPELINE_ORCH, "build", "system", NULL, 1, FALSE},
    {"build-auto", "Build Automation", PATH_BUILD_AUTO, "build", "system", NULL, 1, FALSE},
    
    // ============================================
    // TITAN TESTS (P1)
    // ============================================
    {"ti-test", "Titan Test", PATH_TI_TEST, "test", "testing", NULL, 1, FALSE},
    {"ti-load", "Titan Load Test", PATH_TI_LOAD_TEST, "test", "testing", NULL, 1, FALSE},
    {"titan-log", "Titan Log Analyzer", PATH_TITAN_LOG_ANALYZER, "test", "testing", NULL, 1, FALSE},
    
    // ============================================
    // PHASE TESTS (P2)
    // ============================================
    {"phase19", "Phase 19 Test", PATH_TEST_PHASE19, "test", "testing", NULL, 2, FALSE},
    {"phase20", "Phase 20 Test", PATH_TEST_PHASE20, "test", "testing", NULL, 2, FALSE},
    {"phase21", "Phase 21 Test", PATH_TEST_PHASE21, "test", "testing", NULL, 2, FALSE},
    {"phase22", "Phase 22 Test", PATH_TEST_PHASE22, "test", "testing", NULL, 2, FALSE},
    {"phase23", "Phase 23 Test", PATH_TEST_PHASE23, "test", "testing", NULL, 2, FALSE},
    {"phase24", "Phase 24 Test", PATH_TEST_PHASE24, "test", "testing", NULL, 2, FALSE},
    {"phase25", "Phase 25 Test", PATH_TEST_PHASE25, "test", "testing", NULL, 2, FALSE},
    {"phase26", "Phase 26 Test", PATH_TEST_PHASE26, "test", "testing", NULL, 2, FALSE},
    {"phase3c", "Phase 3C Quick", PATH_PHASE3C_QUICK, "test", "testing", NULL, 2, FALSE},
    {"phase3c-contention", "Phase 3C Contention", PATH_PHASE3C_CONTENTION, "test", "testing", NULL, 2, FALSE},
    
    // ============================================
    // STRESS TESTS (P2)
    // ============================================
    {"soak", "Soak 1024 Test", PATH_SOAK1024, "test", "testing", NULL, 2, FALSE},
    {"soak1024", "Soak 1024 Test", PATH_SOAK1024, "test", "testing", NULL, 2, FALSE},
    {"contention", "Contention Test", PATH_CONTENTION3, "test", "testing", NULL, 2, FALSE},
    {"contention3", "Contention 3 Test", PATH_CONTENTION3, "test", "testing", NULL, 2, FALSE},
    {"lock", "Lock Test", PATH_LOCK_TEST, "test", "testing", NULL, 2, FALSE},
    {"locktest", "Lock Test", PATH_LOCK_TEST, "test", "testing", NULL, 2, FALSE},
    {"golden", "Golden Test", PATH_GOLDEN, "test", "testing", NULL, 2, FALSE},
    {"idx72", "Idx72 Test", PATH_IDX72, "test", "testing", NULL, 2, FALSE},
    
    // ============================================
    // BENCHMARKS (P1)
    // ============================================
    {"benchmark", "RawrXD Benchmark", PATH_RAWRXD_BENCHMARK, "benchmark", "testing", NULL, 1, FALSE},
    {"rawrxd-bench", "RawrXD Benchmark", PATH_RAWRXD_BENCHMARK, "benchmark", "testing", NULL, 1, FALSE},
    {"standalone", "Standalone Benchmark", PATH_STANDALONE_BENCH, "benchmark", "testing", NULL, 1, FALSE},
    {"kernel-bench", "Kernel Benchmark", PATH_BENCHMARK_KERNEL, "benchmark", "testing", NULL, 1, FALSE},
    {"pattern-bench", "Pattern Microbench", PATH_PATTERN_MICROBENCH, "benchmark", "testing", NULL, 1, FALSE},
    {"perf-runner", "Performance Runner", PATH_PERF_RUNNER, "benchmark", "testing", NULL, 1, FALSE},
    
    // ============================================
    // SPECIALIZED TESTS (P2)
    // ============================================
    {"rbtree", "RB Tree Test", PATH_TEST_RBTREE, "test", "testing", NULL, 2, FALSE},
    {"test-rbtree", "RB Tree Test", PATH_TEST_RBTREE, "test", "testing", NULL, 2, FALSE},
    {"agent-hotpatch", "Agent Hot Patcher", PATH_TEST_AGENT_HOTPATCH, "test", "testing", NULL, 2, FALSE},
    {"fusion", "Fusion Test", PATH_TEST_FUSION, "test", "testing", NULL, 2, FALSE},
    {"diagnostic", "Diagnostic Test", PATH_TEST_DIAGNOSTIC, "test", "testing", NULL, 2, FALSE},
    {"swarm-link", "Swarm Link Test", PATH_SWARM_LINK_TEST, "test", "testing", NULL, 2, FALSE},
    
    // ============================================
    // MODEL & INFERENCE (P1)
    // ============================================
    {"model", "Test Model Loading", PATH_TEST_MODEL_LOADING, "model", "ml", NULL, 1, FALSE},
    {"model-load", "Test Model Loading", PATH_TEST_MODEL_LOADING, "model", "ml", NULL, 1, FALSE},
    {"test-model", "Test Model Loading", PATH_TEST_MODEL_LOADING, "model", "ml", NULL, 1, FALSE},
    
    // GEMM
    {"gemm", "GEMM Test", PATH_TEST_GEMM, "model", "ml", NULL, 1, FALSE},
    {"gemm-v2", "GEMM v2 Test", PATH_TEST_GEMM_V2, "model", "ml", NULL, 1, FALSE},
    {"gemm-debug", "GEMM Debug", PATH_TEST_GEMM_DEBUG, "model", "ml", NULL, 2, FALSE},
    {"blocked-gemm", "Blocked GEMM", PATH_TEST_BLOCKED_GEMM, "model", "ml", NULL, 1, FALSE},
    {"blocked-gemm2", "Blocked GEMM 2", PATH_TEST_BLOCKED_GEMM2, "model", "ml", NULL, 1, FALSE},
    
    // RMSNorm
    {"rmsnorm", "RMSNorm Test", PATH_TEST_RMSNORM, "model", "ml", NULL, 1, FALSE},
    {"verify-rms", "Verify RMSNorm", PATH_VERIFY_RMSNORM, "model", "ml", NULL, 1, FALSE},
    
    // LoRA
    {"lora", "LoRA Kernel Test", PATH_TEST_LORA_KERNEL, "model", "ml", NULL, 1, FALSE},
    {"lora-kernel", "LoRA Kernel Test", PATH_TEST_LORA_KERNEL, "model", "ml", NULL, 1, FALSE},
    {"lora-progressive", "LoRA Progressive", PATH_TEST_LORA_PROGRESSIVE, "model", "ml", NULL, 1, FALSE},
    {"lora-minimal", "LoRA Minimal", PATH_TEST_LORA_MINIMAL, "model", "ml", NULL, 1, FALSE},
    {"lora-diag", "LoRA Diagnostic", PATH_TEST_LORA_DIAGNOSTIC, "model", "ml", NULL, 2, FALSE},
    {"lora-simple", "LoRA Simple Test", PATH_SIMPLE_LORA_TEST, "model", "ml", NULL, 2, FALSE},
    
    // HTTP/Network
    {"http-chat", "HTTP Chat Integration", PATH_TEST_HTTP_CHAT, "model", "ml", NULL, 1, FALSE},
    {"p2p", "P2P Test", PATH_TEST_P2P, "model", "ml", NULL, 2, FALSE},
    {"p2p-new", "P2P New Test", PATH_TEST_P2P_NEW, "model", "ml", NULL, 2, FALSE},
    
    // ============================================
    // GPU & COMPUTE (P1)
    // ============================================
    {"gpu", "GPU Backend Test", PATH_TEST_GPU_BACKEND, "gpu", "compute", NULL, 1, FALSE},
    {"gpu-backend", "GPU Backend Test", PATH_TEST_GPU_BACKEND, "gpu", "compute", NULL, 1, FALSE},
    {"test-gpu", "GPU Backend Test", PATH_TEST_GPU_BACKEND, "gpu", "compute", NULL, 1, FALSE},
    
    // ============================================
    // DEBUG & DEVELOPMENT (P3)
    // ============================================
    {"debug-rms", "Debug RMSNorm", PATH_DEBUG_RMSNORM, "debug", "dev", NULL, 3, FALSE},
    {"debug-acc", "Debug Accumulators", PATH_DEBUG_ACCUMULATORS, "debug", "dev", NULL, 3, FALSE},
    {"debug-micro", "Debug Microkernel", PATH_DEBUG_MICROKERNEL, "debug", "dev", NULL, 3, FALSE},
    {"debug-rax", "Debug RAX", PATH_DEBUG_RAX, "debug", "dev", NULL, 3, FALSE},
    {"debug-hang", "Debug Hang", PATH_DEBUG_HANG, "debug", "dev", NULL, 3, FALSE},
    {"minimal", "Minimal Test", PATH_MINIMAL_TEST, "debug", "dev", NULL, 3, FALSE},
    {"minimal-test", "Minimal Test", PATH_MINIMAL_TEST, "debug", "dev", NULL, 3, FALSE},
    {"direct", "Direct Test", PATH_DIRECT_TEST, "debug", "dev", NULL, 3, FALSE},
    {"direct-test", "Direct Test", PATH_DIRECT_TEST, "debug", "dev", NULL, 3, FALSE},
    {"stub", "Test Stub", PATH_TEST_STUB, "debug", "dev", NULL, 3, FALSE},
    {"test-stub", "Test Stub", PATH_TEST_STUB, "debug", "dev", NULL, 3, FALSE},
    {"rrawrawra", "Rrawrawra Editor v2", PATH_RRAWRWRA_EDITOR, "ide", "dev", NULL, 3, FALSE},
    {"batch3-demo", "Batch3 Simple Demo", PATH_BATCH3_DEMO, "ide", "dev", NULL, 3, FALSE},
    
    
    // ============================================
    // BATCH TOOLS 1-152 (Phase 1 Foundation)
    // ============================================
    // Batch 1: Core System Tools (1-10)
    {"tool-1", "File Reader", "d:\\rawrxd\\src\\tool_1.exe", "batch", "system", NULL, 1, FALSE},
    {"tool-2", "File Writer", "d:\\rawrxd\\src\\tool_2.exe", "batch", "system", NULL, 1, FALSE},
    {"tool-3", "Directory Lister", "d:\\rawrxd\\src\\tool_3.exe", "batch", "system", NULL, 1, FALSE},
    {"tool-4", "File Copier", "d:\\rawrxd\\src\\tool_4.exe", "batch", "system", NULL, 1, FALSE},
    {"tool-5", "File Deleter", "d:\\rawrxd\\src\\tool_5.exe", "batch", "system", NULL, 1, FALSE},
    {"tool-6", "Path Checker", "d:\\rawrxd\\src\\tool_6.exe", "batch", "system", NULL, 1, FALSE},
    {"tool-7", "Permission Checker", "d:\\rawrxd\\src\\tool_7.exe", "batch", "system", NULL, 1, FALSE},
    {"tool-8", "Disk Space", "d:\\rawrxd\\src\\tool_8.exe", "batch", "system", NULL, 1, FALSE},
    {"tool-9", "Process Lister", "d:\\rawrxd\\src\\tool_9.exe", "batch", "system", NULL, 1, FALSE},
    {"tool-10", "Environment Reader", "d:\\rawrxd\\src\\tool_10.exe", "batch", "system", NULL, 1, FALSE},
    
    // Batch 2: Text Processing (11-20)
    {"tool-11", "Text Search", "d:\\rawrxd\\src\\tool_11.exe", "batch", "text", NULL, 1, FALSE},
    {"tool-12", "Text Replace", "d:\\rawrxd\\src\\tool_12.exe", "batch", "text", NULL, 1, FALSE},
    {"tool-13", "Line Counter", "d:\\rawrxd\\src\\tool_13.exe", "batch", "text", NULL, 1, FALSE},
    {"tool-14", "Word Counter", "d:\\rawrxd\\src\\tool_14.exe", "batch", "text", NULL, 1, FALSE},
    {"tool-15", "Char Counter", "d:\\rawrxd\\src\\tool_15.exe", "batch", "text", NULL, 1, FALSE},
    {"tool-16", "Diff Tool", "d:\\rawrxd\\src\\tool_16.exe", "batch", "text", NULL, 1, FALSE},
    {"tool-17", "Sort Tool", "d:\\rawrxd\\src\\tool_17.exe", "batch", "text", NULL, 1, FALSE},
    {"tool-18", "Unique Filter", "d:\\rawrxd\\src\\tool_18.exe", "batch", "text", NULL, 1, FALSE},
    {"tool-19", "Head Tool", "d:\\rawrxd\\src\\tool_19.exe", "batch", "text", NULL, 1, FALSE},
    {"tool-20", "Tail Tool", "d:\\rawrxd\\src\\tool_20.exe", "batch", "text", NULL, 1, FALSE},
    
    // Batch 3: Archive Tools (21-30)
    {"tool-21", "ZIP Creator", "d:\\rawrxd\\src\\tool_21.exe", "batch", "archive", NULL, 1, FALSE},
    {"tool-22", "ZIP Extractor", "d:\\rawrxd\\src\\tool_22.exe", "batch", "archive", NULL, 1, FALSE},
    {"tool-23", "TAR Archiver", "d:\\rawrxd\\src\\tool_23.exe", "batch", "archive", NULL, 1, FALSE},
    {"tool-24", "TAR Extractor", "d:\\rawrxd\\src\\tool_24.exe", "batch", "archive", NULL, 1, FALSE},
    {"tool-25", "GZIP Compressor", "d:\\rawrxd\\src\\tool_25.exe", "batch", "archive", NULL, 1, FALSE},
    {"tool-26", "GZIP Decompressor", "d:\\rawrxd\\src\\tool_26.exe", "batch", "archive", NULL, 1, FALSE},
    {"tool-27", "BZIP2 Compressor", "d:\\rawrxd\\src\\tool_27.exe", "batch", "archive", NULL, 1, FALSE},
    {"tool-28", "BZIP2 Decompressor", "d:\\rawrxd\\src\\tool_28.exe", "batch", "archive", NULL, 1, FALSE},
    {"tool-29", "XZ Compressor", "d:\\rawrxd\\src\\tool_29.exe", "batch", "archive", NULL, 1, FALSE},
    {"tool-30", "XZ Decompressor", "d:\\rawrxd\\src\\tool_30.exe", "batch", "archive", NULL, 1, FALSE},
    
    // Batch 4: Code Analysis (31-45)
    {"tool-31", "Syntax Checker", "d:\\rawrxd\\src\\tool_31.exe", "batch", "code", NULL, 1, FALSE},
    {"tool-32", "Style Checker", "d:\\rawrxd\\src\\tool_32.exe", "batch", "code", NULL, 1, FALSE},
    {"tool-33", "Linter", "d:\\rawrxd\\src\\tool_33.exe", "batch", "code", NULL, 1, FALSE},
    {"tool-34", "Formatter", "d:\\rawrxd\\src\\tool_34.exe", "batch", "code", NULL, 1, FALSE},
    {"tool-35", "Code Metrics", "d:\\rawrxd\\src\\tool_35.exe", "batch", "code", NULL, 1, FALSE},
    {"tool-36", "Duplicate Detector", "d:\\rawrxd\\src\\tool_36.exe", "batch", "code", NULL, 1, FALSE},
    {"tool-37", "Dependency Analyzer", "d:\\rawrxd\\src\\tool_37.exe", "batch", "code", NULL, 1, FALSE},
    {"tool-38", "Call Graph Generator", "d:\\rawrxd\\src\\tool_38.exe", "batch", "code", NULL, 1, FALSE},
    {"tool-39", "AST Parser", "d:\\rawrxd\\src\\tool_39.exe", "batch", "code", NULL, 1, FALSE},
    {"tool-40", "Token Extractor", "d:\\rawrxd\\src\\tool_40.exe", "batch", "code", NULL, 1, FALSE},
    {"tool-41", "Comment Extractor", "d:\\rawrxd\\src\\tool_41.exe", "batch", "code", NULL, 1, FALSE},
    {"tool-42", "Doc Generator", "d:\\rawrxd\\src\\tool_42.exe", "batch", "code", NULL, 1, FALSE},
    {"tool-43", "API Extractor", "d:\\rawrxd\\src\\tool_43.exe", "batch", "code", NULL, 1, FALSE},
    {"tool-44", "Type Checker", "d:\\rawrxd\\src\\tool_44.exe", "batch", "code", NULL, 1, FALSE},
    {"tool-45", "Import Sorter", "d:\\rawrxd\\src\\tool_45.exe", "batch", "code", NULL, 1, FALSE},
    
    // Batch 5: Build Tools (46-65)
    {"tool-46", "C Compiler", "d:\\rawrxd\\src\\tool_46.exe", "batch", "build", NULL, 1, FALSE},
    {"tool-47", "C++ Compiler", "d:\\rawrxd\\src\\tool_47.exe", "batch", "build", NULL, 1, FALSE},
    {"tool-48", "ASM Compiler", "d:\\rawrxd\\src\\tool_48.exe", "batch", "build", NULL, 1, FALSE},
    {"tool-49", "Linker", "d:\\rawrxd\\src\\tool_49.exe", "batch", "build", NULL, 1, FALSE},
    {"tool-50", "Archiver", "d:\\rawrxd\\src\\tool_50.exe", "batch", "build", NULL, 1, FALSE},
    {"tool-51", "Preprocessor", "d:\\rawrxd\\src\\tool_51.exe", "batch", "build", NULL, 1, FALSE},
    {"tool-52", "Object Disassembler", "d:\\rawrxd\\src\\tool_52.exe", "batch", "build", NULL, 1, FALSE},
    {"tool-53", "Symbol Extractor", "d:\\rawrxd\\src\\tool_53.exe", "batch", "build", NULL, 1, FALSE},
    {"tool-54", "Strip Tool", "d:\\rawrxd\\src\\tool_54.exe", "batch", "build", NULL, 1, FALSE},
    {"tool-55", "NM Tool", "d:\\rawrxd\\src\\tool_55.exe", "batch", "build", NULL, 1, FALSE},
    {"tool-56", "Quantum Simulator", "d:\\rawrxd\\src\\tool_56.exe", "batch", "specialized", NULL, 1, FALSE},
    {"tool-57", "Neural Network", "d:\\rawrxd\\src\\tool_57.exe", "batch", "specialized", NULL, 1, FALSE},
    {"tool-58", "Blockchain Node", "d:\\rawrxd\\src\\tool_58.exe", "batch", "specialized", NULL, 1, FALSE},
    {"tool-59", "IoT Gateway", "d:\\rawrxd\\src\\tool_59.exe", "batch", "specialized", NULL, 1, FALSE},
    {"tool-60", "AR Compiler", "d:\\rawrxd\\src\\tool_60.exe", "batch", "specialized", NULL, 1, FALSE},
    {"tool-61", "VR Compiler", "d:\\rawrxd\\src\\tool_61.exe", "batch", "specialized", NULL, 1, FALSE},
    {"tool-62", "Quantum Compiler", "d:\\rawrxd\\src\\tool_62.exe", "batch", "specialized", NULL, 1, FALSE},
    {"tool-63", "DNA Compiler", "d:\\rawrxd\\src\\tool_63.exe", "batch", "specialized", NULL, 1, FALSE},
    {"tool-64", "Protein Compiler", "d:\\rawrxd\\src\\tool_64.exe", "batch", "specialized", NULL, 1, FALSE},
    {"tool-65", "Chemical Compiler", "d:\\rawrxd\\src\\tool_65.exe", "batch", "specialized", NULL, 1, FALSE},
    
    // Batch 6: AI/ML Tools (66-75)
    {"tool-66", "Sentiment Analyzer", "d:\\rawrxd\\src\\tool_66.exe", "batch", "ai", NULL, 1, FALSE},
    {"tool-67", "Entity Extractor", "d:\\rawrxd\\src\\tool_67.exe", "batch", "ai", NULL, 1, FALSE},
    {"tool-68", "Topic Modeler", "d:\\rawrxd\\src\\tool_68.exe", "batch", "ai", NULL, 1, FALSE},
    {"tool-69", "Text Summarizer", "d:\\rawrxd\\src\\tool_69.exe", "batch", "ai", NULL, 1, FALSE},
    {"tool-70", "Language Detector", "d:\\rawrxd\\src\\tool_70.exe", "batch", "ai", NULL, 1, FALSE},
    {"tool-71", "Speech Recognizer", "d:\\rawrxd\\src\\tool_71.exe", "batch", "ai", NULL, 1, FALSE},
    {"tool-72", "Voice Synthesizer", "d:\\rawrxd\\src\\tool_72.exe", "batch", "ai", NULL, 1, FALSE},
    {"tool-73", "Image Classifier", "d:\\rawrxd\\src\\tool_73.exe", "batch", "ai", NULL, 1, FALSE},
    {"tool-74", "Object Detector", "d:\\rawrxd\\src\\tool_74.exe", "batch", "ai", NULL, 1, FALSE},
    {"tool-75", "Face Recognizer", "d:\\rawrxd\\src\\tool_75.exe", "batch", "ai", NULL, 1, FALSE},
    
    // Batch 7: Data Processing (76-85)
    {"tool-76", "CSV Parser", "d:\\rawrxd\\src\\tool_76.exe", "batch", "data", NULL, 1, FALSE},
    {"tool-77", "JSON Parser", "d:\\rawrxd\\src\\tool_77.exe", "batch", "data", NULL, 1, FALSE},
    {"tool-78", "XML Parser", "d:\\rawrxd\\src\\tool_78.exe", "batch", "data", NULL, 1, FALSE},
    {"tool-79", "YAML Parser", "d:\\rawrxd\\src\\tool_79.exe", "batch", "data", NULL, 1, FALSE},
    {"tool-80", "SQL Parser", "d:\\rawrxd\\src\\tool_80.exe", "batch", "data", NULL, 1, FALSE},
    {"tool-81", "Regex Engine", "d:\\rawrxd\\src\\tool_81.exe", "batch", "data", NULL, 1, FALSE},
    {"tool-82", "Data Validator", "d:\\rawrxd\\src\\tool_82.exe", "batch", "data", NULL, 1, FALSE},
    {"tool-83", "Data Transformer", "d:\\rawrxd\\src\\tool_83.exe", "batch", "data", NULL, 1, FALSE},
    {"tool-84", "Data Cleaner", "d:\\rawrxd\\src\\tool_84.exe", "batch", "data", NULL, 1, FALSE},
    {"tool-85", "Data Profiler", "d:\\rawrxd\\src\\tool_85.exe", "batch", "data", NULL, 1, FALSE},
    
    // Batch 8: Network Tools (86-95)
    {"tool-86", "HTTP Client", "d:\\rawrxd\\src\\tool_86.exe", "batch", "network", NULL, 1, FALSE},
    {"tool-87", "HTTP Server", "d:\\rawrxd\\src\\tool_87.exe", "batch", "network", NULL, 1, FALSE},
    {"tool-88", "WebSocket Client", "d:\\rawrxd\\src\\tool_88.exe", "batch", "network", NULL, 1, FALSE},
    {"tool-89", "TCP Client", "d:\\rawrxd\\src\\tool_89.exe", "batch", "network", NULL, 1, FALSE},
    {"tool-90", "TCP Server", "d:\\rawrxd\\src\\tool_90.exe", "batch", "network", NULL, 1, FALSE},
    {"tool-91", "UDP Client", "d:\\rawrxd\\src\\tool_91.exe", "batch", "network", NULL, 1, FALSE},
    {"tool-92", "UDP Server", "d:\\rawrxd\\src\\tool_92.exe", "batch", "network", NULL, 1, FALSE},
    {"tool-93", "DNS Resolver", "d:\\rawrxd\\src\\tool_93.exe", "batch", "network", NULL, 1, FALSE},
    {"tool-94", "Ping Tool", "d:\\rawrxd\\src\\tool_94.exe", "batch", "network", NULL, 1, FALSE},
    {"tool-95", "Port Scanner", "d:\\rawrxd\\src\\tool_95.exe", "batch", "network", NULL, 1, FALSE},
    
    // Batch 9: Security Tools (96-105)
    {"tool-96", "Hash Generator", "d:\\rawrxd\\src\\tool_96.exe", "batch", "security", NULL, 1, FALSE},
    {"tool-97", "Password Checker", "d:\\rawrxd\\src\\tool_97.exe", "batch", "security", NULL, 1, FALSE},
    {"tool-98", "JWT Encoder", "d:\\rawrxd\\src\\tool_98.exe", "batch", "security", NULL, 1, FALSE},
    {"tool-99", "JWT Decoder", "d:\\rawrxd\\src\\tool_99.exe", "batch", "security", NULL, 1, FALSE},
    {"tool-100", "SSL Checker", "d:\\rawrxd\\src\\tool_100.exe", "batch", "security", NULL, 1, FALSE},
    {"tool-101", "Vulnerability Scanner", "d:\\rawrxd\\src\\tool_101.exe", "batch", "security", NULL, 1, FALSE},
    {"tool-102", "Firewall Config", "d:\\rawrxd\\src\\tool_102.exe", "batch", "security", NULL, 1, FALSE},
    {"tool-103", "Intrusion Detector", "d:\\rawrxd\\src\\tool_103.exe", "batch", "security", NULL, 1, FALSE},
    {"tool-104", "Log Analyzer", "d:\\rawrxd\\src\\tool_104.exe", "batch", "security", NULL, 1, FALSE},
    {"tool-105", "Cert Generator", "d:\\rawrxd\\src\\tool_105.exe", "batch", "security", NULL, 1, FALSE},
    
    // Batch 10: DevOps Tools (106-115)
    {"tool-106", "Docker Manager", "d:\\rawrxd\\src\\tool_106.exe", "batch", "devops", NULL, 1, FALSE},
    {"tool-107", "Kubernetes CLI", "d:\\rawrxd\\src\\tool_107.exe", "batch", "devops", NULL, 1, FALSE},
    {"tool-108", "Terraform CLI", "d:\\rawrxd\\src\\tool_108.exe", "batch", "devops", NULL, 1, FALSE},
    {"tool-109", "Ansible CLI", "d:\\rawrxd\\src\\tool_109.exe", "batch", "devops", NULL, 1, FALSE},
    {"tool-110", "CI/CD Pipeline", "d:\\rawrxd\\src\\tool_110.exe", "batch", "devops", NULL, 1, FALSE},
    {"tool-111", "Git Hooks", "d:\\rawrxd\\src\\tool_111.exe", "batch", "devops", NULL, 1, FALSE},
    {"tool-112", "Release Manager", "d:\\rawrxd\\src\\tool_112.exe", "batch", "devops", NULL, 1, FALSE},
    {"tool-113", "Deployment Automation", "d:\\rawrxd\\src\\tool_113.exe", "batch", "devops", NULL, 1, FALSE},
    {"tool-114", "Monitoring Dashboard", "d:\\rawrxd\\src\\tool_114.exe", "batch", "devops", NULL, 1, FALSE},
    {"tool-115", "Log Aggregator", "d:\\rawrxd\\src\\tool_115.exe", "batch", "devops", NULL, 1, FALSE},
    
    // Batch 11: Cloud Tools (116-125)
    {"tool-116", "AWS CLI", "d:\\rawrxd\\src\\tool_116.exe", "batch", "cloud", NULL, 1, FALSE},
    {"tool-117", "Azure CLI", "d:\\rawrxd\\src\\tool_117.exe", "batch", "cloud", NULL, 1, FALSE},
    {"tool-118", "GCP CLI", "d:\\rawrxd\\src\\tool_118.exe", "batch", "cloud", NULL, 1, FALSE},
    {"tool-119", "S3 Uploader", "d:\\rawrxd\\src\\tool_119.exe", "batch", "cloud", NULL, 1, FALSE},
    {"tool-120", "Cloud Function Deploy", "d:\\rawrxd\\src\\tool_120.exe", "batch", "cloud", NULL, 1, FALSE},
    {"tool-121", "VM Manager", "d:\\rawrxd\\src\\tool_121.exe", "batch", "cloud", NULL, 1, FALSE},
    {"tool-122", "Load Balancer Config", "d:\\rawrxd\\src\\tool_122.exe", "batch", "cloud", NULL, 1, FALSE},
    {"tool-123", "Auto Scaler", "d:\\rawrxd\\src\\tool_123.exe", "batch", "cloud", NULL, 1, FALSE},
    {"tool-124", "Cloud Monitor", "d:\\rawrxd\\src\\tool_124.exe", "batch", "cloud", NULL, 1, FALSE},
    {"tool-125", "Cost Optimizer", "d:\\rawrxd\\src\\tool_125.exe", "batch", "cloud", NULL, 1, FALSE},
    
    // Batch 12: Database Tools (126-135)
    {"tool-126", "MySQL Client", "d:\\rawrxd\\src\\tool_126.exe", "batch", "database", NULL, 1, FALSE},
    {"tool-127", "PostgreSQL Client", "d:\\rawrxd\\src\\tool_127.exe", "batch", "database", NULL, 1, FALSE},
    {"tool-128", "MongoDB Client", "d:\\rawrxd\\src\\tool_128.exe", "batch", "database", NULL, 1, FALSE},
    {"tool-129", "Redis Client", "d:\\rawrxd\\src\\tool_129.exe", "batch", "database", NULL, 1, FALSE},
    {"tool-130", "SQLite Client", "d:\\rawrxd\\src\\tool_130.exe", "batch", "database", NULL, 1, FALSE},
    {"tool-131", "Elasticsearch Client", "d:\\rawrxd\\src\\tool_131.exe", "batch", "database", NULL, 1, FALSE},
    {"tool-132", "Cassandra Client", "d:\\rawrxd\\src\\tool_132.exe", "batch", "database", NULL, 1, FALSE},
    {"tool-133", "Neo4j Client", "d:\\rawrxd\\src\\tool_133.exe", "batch", "database", NULL, 1, FALSE},
    {"tool-134", "DB Migrator", "d:\\rawrxd\\src\\tool_134.exe", "batch", "database", NULL, 1, FALSE},
    {"tool-135", "Query Optimizer", "d:\\rawrxd\\src\\tool_135.exe", "batch", "database", NULL, 1, FALSE},
    
    // Batch 13: Testing Tools (136-145)
    {"tool-136", "Unit Test Runner", "d:\\rawrxd\\src\\tool_136.exe", "batch", "testing", NULL, 1, FALSE},
    {"tool-137", "Integration Test Runner", "d:\\rawrxd\\src\\tool_137.exe", "batch", "testing", NULL, 1, FALSE},
    {"tool-138", "E2E Test Runner", "d:\\rawrxd\\src\\tool_138.exe", "batch", "testing", NULL, 1, FALSE},
    {"tool-139", "Load Tester", "d:\\rawrxd\\src\\tool_139.exe", "batch", "testing", NULL, 1, FALSE},
    {"tool-140", "Stress Tester", "d:\\rawrxd\\src\\tool_140.exe", "batch", "testing", NULL, 1, FALSE},
    {"tool-141", "Fuzz Tester", "d:\\rawrxd\\src\\tool_141.exe", "batch", "testing", NULL, 1, FALSE},
    {"tool-142", "Coverage Analyzer", "d:\\rawrxd\\src\\tool_142.exe", "batch", "testing", NULL, 1, FALSE},
    {"tool-143", "Benchmark Runner", "d:\\rawrxd\\src\\tool_143.exe", "batch", "testing", NULL, 1, FALSE},
    {"tool-144", "Mock Generator", "d:\\rawrxd\\src\\tool_144.exe", "batch", "testing", NULL, 1, FALSE},
    {"tool-145", "Snapshot Tester", "d:\\rawrxd\\src\\tool_145.exe", "batch", "testing", NULL, 1, FALSE},
    
    // Batch 14: Build Tools (146-150)
    {"tool-146", "Make Wrapper", "d:\\rawrxd\\src\\tool_146.exe", "batch", "build", NULL, 1, FALSE},
    {"tool-147", "Ninja Wrapper", "d:\\rawrxd\\src\\tool_147.exe", "batch", "build", NULL, 1, FALSE},
    {"tool-148", "CMake Generator", "d:\\rawrxd\\src\\tool_148.exe", "batch", "build", NULL, 1, FALSE},
    {"tool-149", "Dependency Checker", "d:\\rawrxd\\src\\tool_149.exe", "batch", "build", NULL, 1, FALSE},
    {"tool-150", "Artifact Packer", "d:\\rawrxd\\src\\tool_150.exe", "batch", "build", NULL, 1, FALSE},
    
    // Batch 15: IDE Core Tools (151-152)
    {"tool-151", "LSP Bridge", "d:\\rawrxd\\src\\tool_151.exe", "batch", "ide", NULL, 1, FALSE},
    {"tool-152", "Ghost Text Engine", "d:\\rawrxd\\src\\tool_152.exe", "batch", "ide", NULL, 1, FALSE},
    
    // End of list
    {NULL, NULL, NULL, NULL, NULL, NULL, 0, FALSE}
};

// ============================================
// IMPLEMENTATION
// ============================================

void InitTools(struct Tool* tools) {
    for (int i = 0; tools[i].id != NULL; i++) {
        DWORD attribs = GetFileAttributesA(tools[i].path);
        tools[i].available = (attribs != INVALID_FILE_ATTRIBUTES && !(attribs & FILE_ATTRIBUTE_DIRECTORY));
    }
}

void PrintBanner(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║     RawrXD Unified Command Interface v%s                  ║\n", UNIFIED_VERSION);
    printf("║     Complete Drive D Unification - %s Components          ║\n", TOTAL_CATALOGED >= 10000 ? "10,000+" : "200+");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf("\n");
}

BOOL CheckTool(struct Tool* tools, const char* id) {
    for (int i = 0; tools[i].id != NULL; i++) {
        if (strcmp(tools[i].id, id) == 0) {
            return tools[i].available;
        }
    }
    return FALSE;
}

struct Tool* GetTool(struct Tool* tools, const char* id) {
    for (int i = 0; tools[i].id != NULL; i++) {
        if (strcmp(tools[i].id, id) == 0) {
            return &tools[i];
        }
    }
    return NULL;
}

BOOL LaunchTool(struct Tool* tools, const char* id, const char* args) {
    struct Tool* tool = GetTool(tools, id);
    if (!tool || !tool->available) {
        printf("[ERROR] Tool '%s' not available\n", id);
        return FALSE;
    }
    
    printf("[LAUNCH] %s...\n", tool->name);
    
    char cmdLine[1024];
    if (args && *args) {
        sprintf(cmdLine, "\"%s\" %s", tool->path, args);
    } else {
        sprintf(cmdLine, "\"%s\"", tool->path);
    }
    
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi = {0};
    
    // Redirect output for CLI tools
    if (strcmp(tool->type, "ide") != 0 && strcmp(tool->type, "gpu") != 0) {
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
        si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
        si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    }
    
    if (CreateProcessA(NULL, cmdLine, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        DWORD exitCode;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        printf("[DONE] Exit code: %lu\n", exitCode);
        return exitCode == 0;
    } else {
        printf("[ERROR] Failed to launch: %s (Error: %lu)\n", tool->name, GetLastError());
        return FALSE;
    }
}

BOOL LaunchToolAsync(struct Tool* tools, const char* id, const char* args) {
    struct Tool* tool = GetTool(tools, id);
    if (!tool || !tool->available) {
        printf("[ERROR] Tool '%s' not available\n", id);
        return FALSE;
    }
    
    printf("[LAUNCH] %s (async)...\n", tool->name);
    
    char cmdLine[1024];
    if (args && *args) {
        sprintf(cmdLine, "\"%s\" %s", tool->path, args);
    } else {
        sprintf(cmdLine, "\"%s\"", tool->path);
    }
    
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi = {0};
    
    if (CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        printf("[RUNNING] %s started\n", tool->name);
        return TRUE;
    } else {
        printf("[ERROR] Failed to launch: %s\n", tool->name);
        return FALSE;
    }
}

void PrintTools(struct Tool* tools) {
    printf("\nAvailable Tools:\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");
    
    const char* currentCategory = "";
    for (int i = 0; tools[i].id != NULL; i++) {
        if (strcmp(tools[i].category, currentCategory) != 0) {
            currentCategory = tools[i].category;
            printf("[%s]\n", currentCategory);
        }
        printf("  %-20s %-30s %s\n", 
               tools[i].id,
               tools[i].name,
               tools[i].available ? "[READY]" : "[MISSING]");
    }
    printf("\n");
}

void PrintCompilers(struct Tool* tools) {
    printf("\nLanguage Compilers:\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");
    
    int count = 0;
    for (int i = 0; tools[i].id != NULL; i++) {
        if (strcmp(tools[i].type, "compiler") == 0) {
            printf("  %-15s %-25s %s\n", 
                   tools[i].id,
                   tools[i].language ? tools[i].language : "Unknown",
                   tools[i].available ? "[READY]" : "[MISSING]");
            count++;
        }
    }
    printf("\nTotal: %d compilers\n\n", count);
}

void ShowHelp(void) {
    printf("\nCommands:\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");
    
    printf("Core IDE:\n");
    printf("  ide, hybrid, sovereign, sov2, titan, production, autonomous\n\n");
    
    printf("Compilers (50+ languages):\n");
    printf("  cc, python, javascript, bash, powershell, csharp, java,\n");
    printf("  rust, go, ruby, php, typescript, lua, perl, kotlin,\n");
    printf("  scala, swift, cpp, fortran, cobol, julia, dart, r,\n");
    printf("  matlab, groovy, clojure, haskell, erlang, elixir, ocaml,\n");
    printf("  lisp, scheme, fsharp, vb, objc, d, nim, zig, crystal, v, odin\n\n");
    
    printf("Build System:\n");
    printf("  build <file>, rawrxd-cc, rawrxd-ld, pipeline, coffdump\n\n");
    
    printf("Testing:\n");
    printf("  test, benchmark, soak, contention, lock, golden\n");
    printf("  phase19-26, phase3c, rbtree, diagnostic, fusion\n\n");
    
    printf("Model/Inference:\n");
    printf("  model, gemm, lora, rmsnorm, http-chat, p2p\n\n");
    
    printf("GPU/Compute:\n");
    printf("  gpu, amphibious\n\n");
    
    printf("Debug:\n");
    printf("  debug-rms, debug-acc, debug-micro, debug-rax, debug-hang\n");
    printf("  minimal, direct, stub\n\n");
    
    printf("Batch Operations:\n");
    printf("  run-all, test-all, benchmark-all, compiler-all\n");
    printf("  titan-all, gpu-all, debug-all\n\n");
    
    printf("Info:\n");
    printf("  tools, compilers, status, help, quit\n\n");
}

void ShowStatus(struct Tool* tools) {
    int total = 0, available = 0;
    int byType[10] = {0};
    int byAvail[10] = {0};
    
    for (int i = 0; tools[i].id != NULL; i++) {
        total++;
        if (tools[i].available) {
            available++;
            byAvail[0]++;
        }
    }
    
    printf("\nStatus:\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("  Total Tools:    %d\n", total);
    printf("  Available:      %d\n", available);
    printf("  Missing:        %d\n", total - available);
    printf("  Coverage:       %.1f%%\n", (float)available / total * 100);
    printf("═══════════════════════════════════════════════════════════════\n\n");
}

void RunAllByType(struct Tool* tools, const char* type) {
    printf("\n[Running all %s tools]\n", type);
    printf("═══════════════════════════════════════════════════════════════\n\n");
    
    int count = 0;
    for (int i = 0; tools[i].id != NULL; i++) {
        if (strcmp(tools[i].type, type) == 0 && tools[i].available) {
            printf("\n--- Running %s ---\n", tools[i].name);
            LaunchTool(tools, tools[i].id, NULL);
            count++;
        }
    }
    
    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("Ran %d %s tools\n\n", count, type);
}

int ProcessCommand(struct Tool* tools, char* input) {
    // Parse command
    char* cmd = strtok(input, " \t");
    if (!cmd || *cmd == '\0') return 0;
    
    char* arg1 = strtok(NULL, " \t");
    char args[512] = {0};
    if (arg1) {
        strcpy(args, arg1);
        char* more;
        while ((more = strtok(NULL, " \t")) != NULL) {
            strcat(args, " ");
            strcat(args, more);
        }
    }
    
    // Built-in commands
    if (strcmp(cmd, "quit") == 0 || strcmp(cmd, "exit") == 0) {
        return 1;
    }
    else if (strcmp(cmd, "help") == 0 || strcmp(cmd, "?") == 0) {
        ShowHelp();
    }
    else if (strcmp(cmd, "tools") == 0) {
        PrintTools(tools);
    }
    else if (strcmp(cmd, "compilers") == 0) {
        PrintCompilers(tools);
    }
    else if (strcmp(cmd, "status") == 0) {
        ShowStatus(tools);
    }
    else if (strcmp(cmd, "build") == 0) {
        if (!arg1) {
            printf("[ERROR] Usage: build <file.c>\n");
        } else {
            printf("[BUILD] Building %s...\n", arg1);
            // Build logic here
        }
    }
    else if (strcmp(cmd, "run-all") == 0) {
        RunAllByType(tools, "ide");
        RunAllByType(tools, "test");
        RunAllByType(tools, "benchmark");
    }
    else if (strcmp(cmd, "test-all") == 0) {
        RunAllByType(tools, "test");
    }
    else if (strcmp(cmd, "benchmark-all") == 0) {
        RunAllByType(tools, "benchmark");
    }
    else if (strcmp(cmd, "compiler-all") == 0) {
        RunAllByType(tools, "compiler");
    }
    else if (strcmp(cmd, "titan-all") == 0) {
        // Run all titan tools
        for (int i = 0; tools[i].id != NULL; i++) {
            if (strncmp(tools[i].id, "titan", 5) == 0 && tools[i].available) {
                printf("\n--- Running %s ---\n", tools[i].name);
                LaunchTool(tools, tools[i].id, NULL);
            }
        }
    }
    else if (strcmp(cmd, "gpu-all") == 0) {
        RunAllByType(tools, "gpu");
    }
    else if (strcmp(cmd, "debug-all") == 0) {
        RunAllByType(tools, "debug");
    }
    else {
        // Try to run as tool ID
        struct Tool* tool = GetTool(tools, cmd);
        if (tool && tool->available) {
            if (strcmp(tool->type, "ide") == 0 || strcmp(tool->type, "gpu") == 0) {
                LaunchToolAsync(tools, cmd, args[0] ? args : NULL);
            } else {
                LaunchTool(tools, cmd, args[0] ? args : NULL);
            }
        } else {
            printf("[ERROR] Unknown command: %s\n", cmd);
            printf("Type 'help' for available commands\n");
        }
    }
    
    return 0;
}

void RunCLILoop(struct Tool* tools) {
    char input[1024];
    
    while (1) {
        printf("RawrXD> ");
        if (!fgets(input, sizeof(input), stdin)) {
            break;
        }
        
        // Remove newline
        size_t len = strlen(input);
        if (len > 0 && input[len-1] == '\n') {
            input[len-1] = '\0';
        }
        
        if (ProcessCommand(tools, input)) {
            break;
        }
    }
}

int main(int argc, char* argv[]) {
    InitTools(g_tools);
    
    // Command line mode
    if (argc > 1) {
        if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "/?") == 0) {
            PrintBanner();
            ShowHelp();
            return 0;
        }
        else if (strcmp(argv[1], "--status") == 0) {
            PrintBanner();
            ShowStatus(g_tools);
            return 0;
        }
        else if (strcmp(argv[1], "--tools") == 0) {
            PrintBanner();
            PrintTools(g_tools);
            return 0;
        }
        else if (strcmp(argv[1], "--compilers") == 0) {
            PrintBanner();
            PrintCompilers(g_tools);
            return 0;
        }
        else {
            // Process command directly
            PrintBanner();
            char cmd[1024] = {0};
            for (int i = 1; i < argc; i++) {
                if (i > 1) strcat(cmd, " ");
                strcat(cmd, argv[i]);
            }
            ProcessCommand(g_tools, cmd);
            return 0;
        }
    }
    
    // Interactive mode
    PrintBanner();
    ShowStatus(g_tools);
    ShowHelp();
    RunCLILoop(g_tools);
    
    return 0;
}
