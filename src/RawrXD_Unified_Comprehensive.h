// RawrXD_Unified_Comprehensive.h - COMPLETE DRIVE D UNIFICATION
// Version: 5.0 - Comprehensive Edition
// Date: 2026-07-08
// Total Components: 500+ tools, 10,000+ sources

#ifndef RAWRXD_UNIFIED_COMPREHENSIVE_H
#define RAWRXD_UNIFIED_COMPREHENSIVE_H

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define UNIFIED_VERSION "5.0"
#define UNIFIED_DATE "2026-07-08"
#define TOTAL_TOOLS_ESTIMATE 500

// ============================================
// PATH DEFINITIONS - D:\RAWRXD\ (Original 152)
// ============================================
// (Previous paths from RawrXD_Unified.h)
#define PATH_RAWRXD_HYBRID      "d:\\rawrxd\\RawrXD_Hybrid.exe"
#define PATH_SOVEREIGN_CLI      "d:\\rawrxd\\sovereign_cli.exe"
#define PATH_TITAN_800B         "d:\\rawrxd\\TITAN_800B_PRODUCTION.exe"
// ... (all previous paths)

// ============================================
// PATH DEFINITIONS - D:\SRC\MAIN\ (MASM Tests)
// ============================================

// Compressed File Tests
#define PATH_COMPRESSED_FILE_TEST   "d:\\src\\main\\Compressed_File_Test.exe"
#define PATH_COMPRESSED_TEST        "d:\\src\\main\\Compressed_Test.exe"
#define PATH_CURRENT_DIR_TEST       "d:\\src\\main\\Current_Dir_Test.exe"

// Debug Tests
#define PATH_DEBUG_FILE             "d:\\src\\main\\Debug_File.exe"
#define PATH_DEBUG_MINIMAL          "d:\\src\\main\\Debug_Minimal.exe"
#define PATH_DIRECT_TEST            "d:\\src\\main\\Direct_Test.exe"

// Frame & Path Tests
#define PATH_FRAME_TEST             "d:\\src\\main\\Frame_Test.exe"
#define PATH_HARDCODED_PATH_TEST    "d:\\src\\main\\Hardcoded_Path_Test.exe"
#define PATH_HEX_PATH_FRAME_TEST    "d:\\src\\main\\Hex_Path_Frame_Test.exe"
#define PATH_HEX_PATH_TEST          "d:\\src\\main\\Hex_Path_Test.exe"
#define PATH_LONG_PATH_TEST         "d:\\src\\main\\Long_Path_Test.exe"
#define PATH_OFFSET_PATH_TEST       "d:\\src\\main\\Offset_Path_Test.exe"
#define PATH_RELATIVE_PATH_TEST     "d:\\src\\main\\Relative_Path_Test.exe"

// Minimal Tests
#define PATH_MINIMAL_DIRECT         "d:\\src\\main\\Minimal_Direct.exe"
#define PATH_MINIMAL_FILE_TEST      "d:\\src\\main\\Minimal_File_Test.exe"
#define PATH_MINIMAL_WORKING        "d:\\src\\main\\Minimal_Working.exe"

// Native & Working Tests
#define PATH_NATIVE_TEST            "d:\\src\\main\\Native_Test.exe"
#define PATH_SAME_FILE_TEST         "d:\\src\\main\\Same_File_Test.exe"
#define PATH_SIMPLEST_TEST          "d:\\src\\main\\Simplest_Test.exe"
#define PATH_WORKING_FILE_TEST      "d:\\src\\main\\Working_File_Test.exe"
#define PATH_WORKING_LOADER_TEST    "d:\\src\\main\\Working_Loader_Test.exe"

// Chaos Tests
#define PATH_RAWRXD_CHAOS_FINAL     "d:\\src\\main\\RawrXD_Chaos_Final.exe"
#define PATH_RAWRXD_CHAOS_MSGBOX    "d:\\src\\main\\RawrXD_Chaos_MsgBox.exe"
#define PATH_RAWRXD_CHAOS_TEST      "d:\\src\\main\\RawrXD_Chaos_Test.exe"
#define PATH_RAWRXD_SOV_CHAOS      "d:\\src\\main\\RawrXD_Sovereign_Chaos.exe"

// Sovereign Tests
#define PATH_SOV_GEMV_TEST          "d:\\src\\main\\Sovereign_GEMV_Test.exe"
#define PATH_SOV_GGUF_LOADER        "d:\\src\\main\\Sovereign_GGUF_Loader.exe"
#define PATH_SOV_HEARTBEAT_PROBE    "d:\\src\\main\\Sovereign_Heartbeat_Probe.exe"
#define PATH_SOV_LAYER0_FIXED       "d:\\src\\main\\Sovereign_Layer0_Fixed.exe"
#define PATH_SOV_LAYER0_MINIMAL     "d:\\src\\main\\Sovereign_Layer0_Minimal.exe"
#define PATH_SOV_LAYER0_TEST        "d:\\src\\main\\Sovereign_Layer0_Test.exe"
#define PATH_SOV_LAYER0_UNIFIED     "d:\\src\\main\\Sovereign_Layer0_Unified.exe"
#define PATH_SOV_LAYER0_WORKING     "d:\\src\\main\\Sovereign_Layer0_Working.exe"
#define PATH_SOV_PHASED_DIAG        "d:\\src\\main\\Sovereign_Phased_Diagnostic.exe"
#define PATH_SOV_PROFILER           "d:\\src\\main\\Sovereign_Profiler.exe"
#define PATH_SOV_SMOKE_TEST         "d:\\src\\main\\Sovereign_Smoke_Test.exe"
#define PATH_SOV_SMOKE_TEST_FINAL   "d:\\src\\main\\Sovereign_Smoke_Test_Final.exe"
#define PATH_SOV_SMOKE_TEST_MINIMAL "d:\\src\\main\\Sovereign_Smoke_Test_Minimal.exe"
#define PATH_SOV_SMOKE_TEST_SIMPLE  "d:\\src\\main\\Sovereign_Smoke_Test_Simple.exe"
#define PATH_SOV_TRANSFORMER        "d:\\src\\main\\Sovereign_Transformer.exe"

// File Tests
#define PATH_TEST_FILE_OPEN         "d:\\src\\main\\Test_File_Open.exe"
#define PATH_TEST_SIMPLE_FILE       "d:\\src\\main\\Test_Simple_File.exe"
#define PATH_EXACT_WORKING_TEST     "d:\\src\\main\\Exact_Working_Test.exe"

// ============================================
// PATH DEFINITIONS - D:\SRC\ASM\ (Sovereign Engine)
// ============================================

// MCP Server
#define PATH_MCP_SERVER             "d:\\src\\asm\\MCP_Server.exe"

// Sovereign Engine
#define PATH_SOV_ENGINE             "d:\\src\\asm\\Sovereign_Engine.exe"
#define PATH_SOV_ENGINE_DEMO        "d:\\src\\asm\\Sovereign_Engine_Demo.exe"
#define PATH_SOV_ENGINE_FULL        "d:\\src\\asm\\Sovereign_Engine_Full.exe"
#define PATH_SOV_ENGINE_STATUS      "d:\\src\\asm\\Sovereign_Engine_Status.exe"
#define PATH_SOV_FINAL              "d:\\src\\asm\\Sovereign_Final.exe"

// Dummy Graph Variants
#define PATH_SOV_DUMMYGRAPH         "d:\\src\\asm\\Sovereign_DummyGraph.exe"
#define PATH_SOV_DUMMYGRAPH_7K      "d:\\src\\asm\\Sovereign_DummyGraph_7Kernels.exe"
#define PATH_SOV_DUMMYGRAPH_BASIC   "d:\\src\\asm\\Sovereign_DummyGraph_Basic.exe"
#define PATH_SOV_DUMMYGRAPH_FINAL   "d:\\src\\asm\\Sovereign_DummyGraph_Final.exe"
#define PATH_SOV_DUMMYGRAPH_MINIMAL "d:\\src\\asm\\Sovereign_DummyGraph_Minimal.exe"
#define PATH_SOV_DUMMYGRAPH_SIMPLE  "d:\\src\\asm\\Sovereign_DummyGraph_Simple.exe"
#define PATH_SOV_DUMMYGRAPH_STABLE  "d:\\src\\asm\\Sovereign_DummyGraph_Stable.exe"
#define PATH_SOV_DUMMYGRAPH_TEST1   "d:\\src\\asm\\Sovereign_DummyGraph_Test1.exe"
#define PATH_SOV_DUMMYGRAPH_TEST2   "d:\\src\\asm\\Sovereign_DummyGraph_Test2.exe"
#define PATH_SOV_DUMMYGRAPH_WORKING "d:\\src\\asm\\Sovereign_DummyGraph_Working.exe"

// Golden Spike
#define PATH_SOV_GOLDEN_SPIKE       "d:\\src\\asm\\Sovereign_Golden_Spike.exe"

// IPC Server
#define PATH_SOV_IPC_SERVER         "d:\\src\\asm\\Sovereign_IPC_Server.exe"

// Kernel Tests
#define PATH_SOV_KERNEL_GEMM_AVX512 "d:\\src\\asm\\Sovereign_Kernel_GEMM_AVX512.exe"

// MCP
#define PATH_SOV_MCP                "d:\\src\\asm\\Sovereign_MCP.exe"

// Smoke
#define PATH_SOV_SMOKE              "d:\\src\\asm\\Sovereign_Smoke.exe"

// Socket Tests
#define PATH_SOV_SOCKET             "d:\\src\\asm\\Sovereign_Socket.exe"
#define PATH_SOV_SOCKET_P2          "d:\\src\\asm\\Sovereign_Socket_Phase2.exe"
#define PATH_SOV_SOCKET_P3          "d:\\src\\asm\\Sovereign_Socket_Phase3.exe"
#define PATH_SOV_SOCKET_P4          "d:\\src\\asm\\Sovereign_Socket_Phase4.exe"
#define PATH_SOV_SOCKET_P4_MINIMAL  "d:\\src\\asm\\Sovereign_Socket_Phase4_Minimal.exe"
#define PATH_SOV_SOCKET_P5          "d:\\src\\asm\\Sovereign_Socket_Phase5.exe"
#define PATH_SOV_SOCKET_P6          "d:\\src\\asm\\Sovereign_Socket_Phase6.exe"
#define PATH_SOV_SOCKET_P6_TEST     "d:\\src\\asm\\Sovereign_Socket_Phase6_Test.exe"

// SPSC Unit Test
#define PATH_SOV_SPSC_UNITTEST      "d:\\src\\asm\\Sovereign_SPSC_UnitTest.exe"

// Toy Model Variants
#define PATH_SOV_TOYMODEL_COMPLETE  "d:\\src\\asm\\Sovereign_ToyModel_Complete.exe"
#define PATH_SOV_TOYMODEL_FINAL     "d:\\src\\asm\\Sovereign_ToyModel_Final.exe"
#define PATH_SOV_TOYMODEL_MINIMAL   "d:\\src\\asm\\Sovereign_ToyModel_Minimal.exe"
#define PATH_SOV_TOYMODEL_SIMPLE    "d:\\src\\asm\\Sovereign_ToyModel_Simple.exe"
#define PATH_SOV_TOYMODEL_STABLE    "d:\\src\\asm\\Sovereign_ToyModel_Stable.exe"
#define PATH_SOV_TOYMODEL_TINY      "d:\\src\\asm\\Sovereign_ToyModel_Tiny.exe"
#define PATH_SOV_TOYMODEL_VALIDATED "d:\\src\\asm\\Sovereign_ToyModel_Validated.exe"
#define PATH_SOV_TOYMODEL_WORKING   "d:\\src\\asm\\Sovereign_ToyModel_Working.exe"

// Transformer
#define PATH_SOV_TRANSFORMER_ASM    "d:\\src\\asm\\Sovereign_Transformer.exe"

// v1.1 Graph
#define PATH_SOV_V1_1_GRAPH         "d:\\src\\asm\\Sovereign_v1.1_Graph.exe"

// WarmUp Orchestrator
#define PATH_SOV_WARMUP_ORCHESTRATOR "d:\\src\\asm\\Sovereign_WarmUp_Orchestrator.exe"

// ============================================
// PATH DEFINITIONS - D:\SRC\TOOLS\
// ============================================

#define PATH_BRIDGE_STAGE2          "d:\\src\\tools\\bridge_stage2.exe"
#define PATH_CODEX_NATIVE_BRIDGE    "d:\\src\\tools\\codex_native_bridge.exe"

// ============================================
// TOOL STRUCTURE
// ============================================

struct Tool {
    const char* id;
    const char* name;
    const char* path;
    const char* type;
    const char* category;
    const char* location;
    int priority;
    BOOL available;
};

// Function declarations
void InitTools(struct Tool* tools);
void PrintBanner(void);
void PrintTools(struct Tool* tools);
void PrintToolsByLocation(struct Tool* tools);
struct Tool* GetTool(struct Tool* tools, const char* id);
BOOL LaunchTool(struct Tool* tools, const char* id, const char* args);
void RunCLILoop(struct Tool* tools);
void ShowHelp(void);
void ShowStatus(struct Tool* tools);

#endif
