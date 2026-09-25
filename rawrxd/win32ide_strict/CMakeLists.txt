# ============================================================================
# RawrXD-Win32IDE Strict Minimal Build
# ============================================================================
# Only includes verified non-stub files for:
# 1. Win32 entry point (main_win32.cpp)
# 2. Frozen native toolchain (InstructionEncoderX64, RawrCOFFWriter, RawrPE64Linker)
# 3. JIT assembler
# 4. RawrXD Backend common types
#
# Zero stubs, zero demo code, zero fallback.
# Certification target: RAWRXD_WIN32IDE_STRICT_001
# ============================================================================

cmake_minimum_required(VERSION 3.20)
project(RawrXD-Win32IDE LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Subsystem: Windows (not Console)
add_executable(${PROJECT_NAME} WIN32)

# Prevent Windows.h min/max macro collision with std::max / std::min
target_compile_definitions(${PROJECT_NAME} PRIVATE NOMINMAX)

# Vulkan SDK include path (required for GPU forward and agentic gate)
if(EXISTS "C:/VulkanSDK/1.4.357.0/Include/vulkan/vulkan.h")
    target_include_directories(${PROJECT_NAME} PRIVATE "C:/VulkanSDK/1.4.357.0/Include")
elseif(EXISTS "D:/VulkanSDK/1.4.357.0/Include/vulkan/vulkan.h")
    target_include_directories(${PROJECT_NAME} PRIVATE "D:/VulkanSDK/1.4.357.0/Include")
else()
    message(FATAL_ERROR "Vulkan SDK not found. Install Vulkan SDK or set VULKAN_SDK environment variable.")
endif()

# Autoclosure header location
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/../src/closure)
# Expert cache headers
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/../src/deep2/expert_cache)

# Strict source closure - ONLY these files
target_sources(${PROJECT_NAME} PRIVATE
    # Entry point (real Win32 window + message pump)
    ${CMAKE_SOURCE_DIR}/../src/win32app/main_win32.cpp

    # IDE-native toolchain gate (RAWRXD_WIN32IDE_TOOLCHAIN_001)
    ${CMAKE_SOURCE_DIR}/../src/win32app/ide_toolchain_gate.cpp

    # IDE-native local inference gate (RAWRXD_WIN32IDE_INFERENCE_001)
    ${CMAKE_SOURCE_DIR}/../src/win32app/ide_inference_gate.cpp

    # IDE-native agentic streaming gate (RAWRXD_WIN32IDE_AGENT_001)
    ${CMAKE_SOURCE_DIR}/../src/win32app/ide_agentic_gate.cpp

    # IDE stub closure recovery — full implementations (RAWRXD_IDE_STUB_CLOSURE_RECOVERY_001)
    ${CMAKE_SOURCE_DIR}/../src/win32app/Win32IDE_Commands.cpp
    ${CMAKE_SOURCE_DIR}/../src/win32app/Win32IDE_Sidebar.cpp
    ${CMAKE_SOURCE_DIR}/../src/win32app/Win32IDE_MCPHooks.cpp
    ${CMAKE_SOURCE_DIR}/../src/win32app/Win32IDE_Core.cpp
    ${CMAKE_SOURCE_DIR}/../src/win32app/Win32IDE_EditorEngine.cpp
    ${CMAKE_SOURCE_DIR}/../src/win32app/Win32IDE_FileOps.cpp
    ${CMAKE_SOURCE_DIR}/../src/win32app/Win32IDE_TabManager.cpp
    ${CMAKE_SOURCE_DIR}/../src/win32app/Win32IDE_ShellLayout.cpp
    ${CMAKE_SOURCE_DIR}/../src/win32app/Win32IDE_ChatPanel.cpp
    ${CMAKE_SOURCE_DIR}/../src/win32app/Win32IDE_AgentPanel.cpp
    ${CMAKE_SOURCE_DIR}/../src/win32app/Win32IDE_TerminalSplit.cpp
    ${CMAKE_SOURCE_DIR}/../src/win32app/Win32IDE_GitPanel.cpp
    ${CMAKE_SOURCE_DIR}/../src/win32app/Win32IDE_SearchPanel.cpp
    ${CMAKE_SOURCE_DIR}/../src/win32app/Win32IDE_SyntaxHighlight.cpp
    ${CMAKE_SOURCE_DIR}/../src/win32app/Win32IDE_GhostText.cpp
    ${CMAKE_SOURCE_DIR}/../src/win32app/Win32IDE_Settings.cpp
    ${CMAKE_SOURCE_DIR}/../src/win32app/Win32IDE_Session.cpp
    ${CMAKE_SOURCE_DIR}/../src/win32app/Win32IDE_LSPClient.cpp
    ${CMAKE_SOURCE_DIR}/../src/win32app/Win32IDE_MCP.cpp
    ${CMAKE_SOURCE_DIR}/../src/win32app/Win32IDE_Watchdog.cpp
    ${CMAKE_SOURCE_DIR}/../src/win32app/Win32IDE_AutoSave.cpp
    ${CMAKE_SOURCE_DIR}/../src/win32app/Win32IDE_BuildRunner.cpp
    ${CMAKE_SOURCE_DIR}/../src/win32app/Win32IDE_StatusBar.cpp
    ${CMAKE_SOURCE_DIR}/../src/win32app/Win32IDE_AgenticBridge.cpp
    ${CMAKE_SOURCE_DIR}/../src/win32app/Win32IDE_StreamingUX.cpp
    ${CMAKE_SOURCE_DIR}/../src/win32app/Win32IDE_Logger.cpp
    ${CMAKE_SOURCE_DIR}/../src/win32app/Win32IDE_logMessage.cpp

    # Frozen native toolchain
    ${CMAKE_SOURCE_DIR}/../src/compiler_backend/InstructionEncoderX64.cpp
    ${CMAKE_SOURCE_DIR}/../src/compiler_backend/RawrCOFFWriter.cpp
    ${CMAKE_SOURCE_DIR}/../src/compiler_backend/RawrPE64Linker.cpp

    # JIT Assembler
    ${CMAKE_SOURCE_DIR}/../src/sovereign/puppeteer/JITAssembler.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/Deep2Engine.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/Tokenizer.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/Sampler.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/GGUFLoader.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/QuantKernelRegistry.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/Deep2DualGpuRowSplit.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/vulkan_compute.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/Deep2Engine_GpuMoEMLA.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/Deep2Engine_Speculative.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/Deep2Engine_VulkanRuntime.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/strict_gpu_violations.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/Deep2Engine_GpuForward.cpp
    # Expert cache (RAWRXD_EXPERT_CACHE_004/005)
    ${CMAKE_SOURCE_DIR}/../src/deep2/expert_cache/ExpertCache.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/expert_cache/ExpertTensorCatalog.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/expert_cache/PackedExpertSlicer.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/expert_cache/VulkanExpertTransport.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/expert_cache/HostStagingRing.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/expert_cache/Deep2ExpertCacheBridge.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/expert_cache/ExpertScheduler.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/expert_cache/Deep2StackGuard.cpp
    # RAWRXD_EXPERT_CACHE_006
    ${CMAKE_SOURCE_DIR}/../src/deep2/expert_cache/Deep2MultiGpuExpertCache.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/expert_cache/ExpertCacheBenchmark.cpp
    # Elastic residency manager (DEEP2_LAYER0_ELASTIC_RESIDENCY_001)
    ${CMAKE_SOURCE_DIR}/../src/deep2/ElasticResidencyManager.cpp
    # Production profiler (DEEP2_LAYER0_PRODUCTION_PROFILER_001)
    ${CMAKE_SOURCE_DIR}/../src/deep2/ProductionProfiler.cpp
    # Cyclone scheduler (DEEP2_LAYER0_CYCLONE_001)
    ${CMAKE_SOURCE_DIR}/../src/deep2/CycloneScheduler.cpp
    # Agentic streaming stack (RAWRXD_WIN32IDE_AGENT_001)
    ${CMAKE_SOURCE_DIR}/../src/agentic/StreamingResultChannel.cpp
    ${CMAKE_SOURCE_DIR}/../src/ai/streaming_inference_engine.cpp
    ${CMAKE_SOURCE_DIR}/../src/agentic_model_streamer_bridge.cpp
    ${CMAKE_SOURCE_DIR}/../src/agentic/streaming_command_handler.cpp
    ${CMAKE_SOURCE_DIR}/../src/runtime/shared/BP1BraidStreamer.cpp
    # Agentic Gate
    ${CMAKE_SOURCE_DIR}/../src/win32app/ide_agentic_gate.cpp
    # Autonomous Bounded Closure (RAWRXD_AUTOCLOSURE_001)
    ${CMAKE_SOURCE_DIR}/../src/closure/RawrXDAutoClosure.cpp
    # Tool Authority
    ${CMAKE_SOURCE_DIR}/../src/deep2/AgentToolAuthority.cpp
    # Batch A providers (DEEP2_LAYER0_LINK_CLOSURE_001)
    ${CMAKE_SOURCE_DIR}/../src/deep2/Chamber.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/ToroidalKVCache.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/PlasmaGovernor.cpp
    # Batch A1 providers (DEEP2_LAYER0_PROVIDER_CLOSURE_002)
    ${CMAKE_SOURCE_DIR}/../src/deep2/NVMeStream.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/BP16Streamer.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/CompressedKVCache.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/mars/MARSController.cpp
    # SG-01 to SG-10 speculative special graph (RAWRXD_SPECULATIVE_SPECIAL_GRAPH_001)
    ${CMAKE_SOURCE_DIR}/../src/deep2/speculative/SpecialGraph.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/speculative/SpeculativeBatch.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/speculative/SpeculativeExecutor.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/speculative/KvTransaction.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/speculative/VerifyBatch.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/speculative/DraftPolicy.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/speculative/AcceptanceOracle.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/speculative/DualGpuOverlap.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/speculative/SpeculativeCert.cpp
    # RAWRXD_AGENTIC_E2E_001
    ${CMAKE_SOURCE_DIR}/../src/agentic/RawrXDAgenticE2E.cpp
)

# --- Standalone Layer 0 provider tests ---
add_executable(RawrXD-Win32IDE-Tests
    ${CMAKE_SOURCE_DIR}/../tests/deep2/test_layer0_providers.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/Chamber.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/ToroidalKVCache.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/PlasmaGovernor.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/CycloneScheduler.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/ElasticResidencyManager.cpp
)
set_property(TARGET RawrXD-Win32IDE-Tests PROPERTY CXX_STANDARD 20)

# --- DEEP2_LAYER0_FINAL_001 integrated evidence capture ---
add_executable(RawrXD-Layer0-Final-Evidence
    ${CMAKE_SOURCE_DIR}/../tests/deep2/test_layer0_final_evidence.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/Chamber.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/ToroidalKVCache.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/PlasmaGovernor.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/CycloneScheduler.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/ElasticResidencyManager.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/ProductionProfiler.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/NVMeStream.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/BP16Streamer.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/CompressedKVCache.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/mars/MARSController.cpp
)
set_property(TARGET RawrXD-Layer0-Final-Evidence PROPERTY CXX_STANDARD 20)
target_include_directories(RawrXD-Layer0-Final-Evidence PRIVATE
    ${CMAKE_SOURCE_DIR}/../tests/deep2
    ${CMAKE_SOURCE_DIR}/../src
    ${CMAKE_SOURCE_DIR}/../include
)

# --- ProductionProfiler isolated test ---
add_executable(RawrXD-ProductionProfiler-Test
    ${CMAKE_SOURCE_DIR}/../tests/deep2/ProductionProfiler_test.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/ProductionProfiler.cpp
)
set_property(TARGET RawrXD-ProductionProfiler-Test PROPERTY CXX_STANDARD 20)
target_include_directories(RawrXD-ProductionProfiler-Test PRIVATE
    ${CMAKE_SOURCE_DIR}/../tests/deep2
    ${CMAKE_SOURCE_DIR}/../src
    ${CMAKE_SOURCE_DIR}/../include
)
target_include_directories(RawrXD-Win32IDE-Tests PRIVATE
    ${CMAKE_SOURCE_DIR}/../tests/deep2
    ${CMAKE_SOURCE_DIR}/../src
    ${CMAKE_SOURCE_DIR}/../include
)

# Include directories for the backend headers
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_SOURCE_DIR}/../src/win32app
    ${CMAKE_SOURCE_DIR}/../src/compiler_backend
    ${CMAKE_SOURCE_DIR}/../src/sovereign/puppeteer
    ${CMAKE_SOURCE_DIR}/../src/core
    ${CMAKE_SOURCE_DIR}/../include
    ${CMAKE_SOURCE_DIR}/../src
    ${CMAKE_SOURCE_DIR}/../src/deep2/speculative
    ${CMAKE_SOURCE_DIR}/../src/deep2/special_graph
    ${CMAKE_SOURCE_DIR}/../src/agentic
    ${CMAKE_SOURCE_DIR}/../src/core
    ${CMAKE_SOURCE_DIR}/../src/screenpilot
    # Vulkan SDK header for Deep2 real GPU backend
    "C:/VulkanSDK/1.4.357.0/Include"
)

# Vulkan SDK library for Deep2 GPU backend
target_link_directories(${PROJECT_NAME} PRIVATE "C:/VulkanSDK/1.4.357.0/Lib")
target_link_libraries(${PROJECT_NAME} PRIVATE vulkan-1.lib dxgi psapi shell32 ole32 comdlg32)
set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS "/STACK:16777216")
# Certification: verify no STUB files are linked
set(STRICT_IDE_SOURCES
    main_win32.cpp
    InstructionEncoderX64.cpp
    RawrCOFFWriter.cpp
    RawrPE64Linker.cpp
    JITAssembler.cpp
)

foreach(src ${STRICT_IDE_SOURCES})
    if(NOT EXISTS "${CMAKE_SOURCE_DIR}/../src/compiler_backend/${src}")
        if(NOT EXISTS "${CMAKE_SOURCE_DIR}/../src/sovereign/puppeteer/${src}")
            if(NOT EXISTS "${CMAKE_SOURCE_DIR}/../src/win32app/${src}")
                message(FATAL_ERROR "Strict source missing: ${src}")
            endif()
        endif()
    endif()
endforeach()

message(STATUS "RAWRXD_WIN32IDE_STRICT: source closure verified for ${PROJECT_NAME}")

# --- Q2_K Single-Tensor Oracle ---
add_executable(test_q2k_single_tensor_oracle
    ${CMAKE_SOURCE_DIR}/../src/deep2/test_q2k_single_tensor_oracle.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/Deep2Engine.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/Tokenizer.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/Sampler.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/GGUFLoader.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/QuantKernelRegistry.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/Deep2DualGpuRowSplit.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/vulkan_compute.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/Deep2Engine_GpuMoEMLA.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/Deep2Engine_Speculative.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/Deep2Engine_VulkanRuntime.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/strict_gpu_violations.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/Deep2Engine_GpuForward.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/ElasticResidencyManager.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/ProductionProfiler.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/CycloneScheduler.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/NVMeStream.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/BP16Streamer.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/CompressedKVCache.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/mars/MARSController.cpp
    ${CMAKE_SOURCE_DIR}/../src/agentic/StreamingResultChannel.cpp
    ${CMAKE_SOURCE_DIR}/../src/ai/streaming_inference_engine.cpp
    ${CMAKE_SOURCE_DIR}/../src/agentic_model_streamer_bridge.cpp
    ${CMAKE_SOURCE_DIR}/../src/agentic/streaming_command_handler.cpp
    ${CMAKE_SOURCE_DIR}/../src/runtime/shared/BP1BraidStreamer.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/AgentToolAuthority.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/Chamber.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/ToroidalKVCache.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/PlasmaGovernor.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/SovereignOutOfCoreRuntime.cpp
)
target_include_directories(test_q2k_single_tensor_oracle PRIVATE
    ${CMAKE_SOURCE_DIR}/../src/deep2
    ${CMAKE_SOURCE_DIR}/../src/deep2/expert_cache
    ${CMAKE_SOURCE_DIR}/../src/tokenizer
    ${CMAKE_SOURCE_DIR}/../include
    ${CMAKE_SOURCE_DIR}/../src
    "C:/VulkanSDK/1.4.357.0/Include"
)
target_link_directories(test_q2k_single_tensor_oracle PRIVATE "C:/VulkanSDK/1.4.357.0/Lib")
target_compile_definitions(test_q2k_single_tensor_oracle PRIVATE NOMINMAX)
if(MSVC)
    target_compile_options(test_q2k_single_tensor_oracle PRIVATE /arch:AVX2 /EHsc /W4 /std:c++20)
endif()
target_link_libraries(test_q2k_single_tensor_oracle PRIVATE vulkan-1.lib dxgi psapi)
set_target_properties(test_q2k_single_tensor_oracle PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
)
message(STATUS "[Deep2] Q2_K single-tensor oracle: test_q2k_single_tensor_oracle")
