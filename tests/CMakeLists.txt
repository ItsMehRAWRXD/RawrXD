<<<<<<< HEAD
# ============================================================
# RawrXD Test Suite - CTest Registration
# ============================================================
# This file registers tests defined in the parent CMakeLists.txt with CTest
# and adds additional tests not already defined there.
#
# Tests ALREADY defined in parent CMakeLists.txt (do NOT redefine):
# - test_gguf_loader
# - test_gguf_loader_simple  
# - test_agent_coordinator
# - test_agent_coordinator_integration
# - quant_correctness_tests
# - quant_engine_test
# - quant_scalar_smoke
# - test_kv_cache
# - test_chat_streaming
# - test_terminal
# - test_ide_main
# - test_header

cmake_minimum_required(VERSION 3.20)

# Enable testing
enable_testing()

# ============================================================================
# Google Test Setup - Use prebuilt from build-master
# ============================================================================
if(EXISTS "${CMAKE_SOURCE_DIR}/build-master/lib/gtest.lib")
    # Use prebuilt gtest from build-master
    add_library(gtest STATIC IMPORTED)
    set_target_properties(gtest PROPERTIES
        IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/build-master/lib/gtest.lib"
        INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/build-master/_deps/googletest-src/googletest/include"
    )
    message(STATUS "  ✓ Using prebuilt gtest from build-master")
else()
    find_package(GTest QUIET)
    if(NOT GTest_FOUND)
        # Fetch Google Test if not found
        include(FetchContent)
        FetchContent_Declare(
            googletest
            GIT_REPOSITORY https://github.com/google/googletest.git
            GIT_TAG v1.14.0
        )
        # For Windows: Prevent overriding the parent project's compiler/linker settings
        set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
        FetchContent_MakeAvailable(googletest)
    endif()
endif()

# ============================================================================
# Common Test Link Libraries
# ============================================================================
set(RAWRXD_TEST_COMMON_LIBS gtest)
if(WIN32)
    list(APPEND RAWRXD_TEST_COMMON_LIBS 
        wintrust    # For WinVerifyTrust
        crypt32     # For ImageEnumerateCertificates
    )
endif()

message(STATUS "========================================")
message(STATUS "Registering Tests with CTest")
message(STATUS "========================================")

# Register existing tests from parent CMakeLists.txt with CTest
# These targets already exist, we just register them for ctest discovery
if(TARGET test_gguf_loader)
    add_test(NAME test_gguf_loader COMMAND test_gguf_loader)
    message(STATUS "  ✓ Registered test_gguf_loader")
endif()

if(TARGET test_gguf_loader_simple)
    add_test(NAME test_gguf_loader_simple COMMAND test_gguf_loader_simple)
    message(STATUS "  ✓ Registered test_gguf_loader_simple")
endif()

if(TARGET test_agent_coordinator)
    add_test(NAME test_agent_coordinator COMMAND test_agent_coordinator)
    message(STATUS "  ✓ Registered test_agent_coordinator")
endif()

if(TARGET test_agent_coordinator_integration)
    add_test(NAME test_agent_coordinator_integration COMMAND test_agent_coordinator_integration)
    message(STATUS "  ✓ Registered test_agent_coordinator_integration")
endif()

if(TARGET quant_correctness_tests)
    add_test(NAME quant_correctness_tests COMMAND quant_correctness_tests)
    message(STATUS "  ✓ Registered quant_correctness_tests")
endif()

if(TARGET quant_engine_test)
    add_test(NAME quant_engine_test COMMAND quant_engine_test)
    message(STATUS "  ✓ Registered quant_engine_test")
endif()

if(TARGET quant_scalar_smoke)
    add_test(NAME quant_scalar_smoke COMMAND quant_scalar_smoke)
    message(STATUS "  ✓ Registered quant_scalar_smoke")
endif()

if(TARGET test_kv_cache)
    add_test(NAME test_kv_cache COMMAND test_kv_cache)
    message(STATUS "  ✓ Registered test_kv_cache")
endif()

# ============================================================
# NEW TESTS - Qt-free, C++20 native test framework
# ============================================================

# AI Completions Test
if(NOT TARGET test_ai_completions AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_ai_completions.cpp")
    add_executable(test_ai_completions test_ai_completions.cpp)
    target_include_directories(test_ai_completions PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(test_ai_completions PRIVATE ${RAWRXD_TEST_COMMON_LIBS})
    # Link against InferenceEngine library if available
    if(TARGET InferenceEngine)
        target_link_libraries(test_ai_completions PRIVATE InferenceEngine)
    endif()
    set_target_properties(test_ai_completions PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests" CXX_STANDARD 20)
    add_test(NAME test_ai_completions COMMAND test_ai_completions)
    message(STATUS "  ✓ Added test_ai_completions")
endif()

# LLM Connectivity Test - Uses WinHTTP-based client (no curl dependency)
if(NOT TARGET test_llm_connectivity AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_llm_connectivity.cpp")
    add_executable(test_llm_connectivity test_llm_connectivity.cpp 
        ${CMAKE_SOURCE_DIR}/src/agent/llm_http_client.cpp)
    target_include_directories(test_llm_connectivity PRIVATE 
        ${CMAKE_SOURCE_DIR}/include 
        ${CMAKE_SOURCE_DIR}/src 
        ${CMAKE_SOURCE_DIR}/src/agent)
    set_target_properties(test_llm_connectivity PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests" CXX_STANDARD 20)
    if(WIN32)
        target_link_libraries(test_llm_connectivity PRIVATE ws2_32 winhttp)
    endif()
    add_test(NAME test_llm_connectivity COMMAND test_llm_connectivity)
    message(STATUS "  ✓ Added test_llm_connectivity")
endif()

# Tool Registry Test
if(NOT TARGET test_tool_registry AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_tool_registry.cpp")
    add_executable(test_tool_registry test_tool_registry.cpp tool_registry_full_impl.cpp)
    target_include_directories(test_tool_registry PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src)
    set_target_properties(test_tool_registry PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests" CXX_STANDARD 20)
    add_test(NAME test_tool_registry COMMAND test_tool_registry)
    message(STATUS "  ✓ Added test_tool_registry")
endif()

# Voice Processor Test
if(NOT TARGET test_voice_processor AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_voice_processor.cpp")
    add_executable(test_voice_processor test_voice_processor.cpp)
    target_include_directories(test_voice_processor PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(test_voice_processor PRIVATE ${RAWRXD_TEST_COMMON_LIBS})
    set_target_properties(test_voice_processor PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests" CXX_STANDARD 20)
    add_test(NAME test_voice_processor COMMAND test_voice_processor)
    message(STATUS "  ✓ Added test_voice_processor")
endif()

# Zero Retention Manager Test
if(NOT TARGET test_zero_retention_manager AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_zero_retention_manager.cpp")
    add_executable(test_zero_retention_manager test_zero_retention_manager.cpp ${CMAKE_SOURCE_DIR}/src/terminal/zero_retention_manager.cpp)
    target_include_directories(test_zero_retention_manager PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(test_zero_retention_manager PRIVATE ${RAWRXD_TEST_COMMON_LIBS})
    set_target_properties(test_zero_retention_manager PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests" CXX_STANDARD 20)
    add_test(NAME test_zero_retention_manager COMMAND test_zero_retention_manager)
    message(STATUS "  ✓ Added test_zero_retention_manager")
endif()

# GUI Components Test
if(NOT TARGET test_gui_components AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_gui_components.cpp")
    add_executable(test_gui_components test_gui_components.cpp)
    target_include_directories(test_gui_components PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src)
    set_target_properties(test_gui_components PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests" CXX_STANDARD 20)
    add_test(NAME test_gui_components COMMAND test_gui_components)
    message(STATUS "  ✓ Added test_gui_components")
endif()

# Semantic Diff Analyzer Test
if(NOT TARGET test_semantic_diff_analyzer AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_semantic_diff_analyzer.cpp")
    add_executable(test_semantic_diff_analyzer test_semantic_diff_analyzer.cpp)
    target_include_directories(test_semantic_diff_analyzer PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src)
    set_target_properties(test_semantic_diff_analyzer PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests" CXX_STANDARD 20)
    add_test(NAME test_semantic_diff_analyzer COMMAND test_semantic_diff_analyzer)
    message(STATUS "  ✓ Added test_semantic_diff_analyzer")
endif()

# AI Merge Resolver Test
if(NOT TARGET test_ai_merge_resolver AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_ai_merge_resolver.cpp")
    add_executable(test_ai_merge_resolver test_ai_merge_resolver.cpp)
    target_include_directories(test_ai_merge_resolver PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src)
    set_target_properties(test_ai_merge_resolver PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests" CXX_STANDARD 20)
    if(WIN32)
        target_link_libraries(test_ai_merge_resolver PRIVATE ws2_32 winhttp)
    endif()
    add_test(NAME test_ai_merge_resolver COMMAND test_ai_merge_resolver)
    message(STATUS "  ✓ Added test_ai_merge_resolver")
endif()

# Sandboxed Terminal Test
if(NOT TARGET test_sandboxed_terminal AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_sandboxed_terminal.cpp")
    add_executable(test_sandboxed_terminal test_sandboxed_terminal.cpp)
    target_include_directories(test_sandboxed_terminal PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src)
    set_target_properties(test_sandboxed_terminal PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests" CXX_STANDARD 20)
    add_test(NAME test_sandboxed_terminal COMMAND test_sandboxed_terminal)
    message(STATUS "  ✓ Added test_sandboxed_terminal")
endif()

# Agentic File Operations Test
if(NOT TARGET test_agentic_file_operations AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_agentic_file_operations.cpp")
    add_executable(test_agentic_file_operations test_agentic_file_operations.cpp)
    target_include_directories(test_agentic_file_operations PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src)
    set_target_properties(test_agentic_file_operations PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests" CXX_STANDARD 20)
    add_test(NAME test_agentic_file_operations COMMAND test_agentic_file_operations)
    message(STATUS "  ✓ Added test_agentic_file_operations")
endif()

# Model Registry Test
if(NOT TARGET model_registry_test AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/model_registry_test.cpp")
    add_executable(model_registry_test model_registry_test.cpp)
    target_include_directories(model_registry_test PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src)
    set_target_properties(model_registry_test PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests" CXX_STANDARD 20)
    add_test(NAME model_registry_test COMMAND model_registry_test)
    message(STATUS "  ✓ Added model_registry_test")
endif()

# GGUF Integration Test
if(NOT TARGET test_gguf_integration AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_gguf_integration.cpp")
    add_executable(test_gguf_integration test_gguf_integration.cpp)
    target_include_directories(test_gguf_integration PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(test_gguf_integration PRIVATE ${RAWRXD_TEST_COMMON_LIBS})
    # Link against InferenceEngine library if available
    if(TARGET InferenceEngine)
        target_link_libraries(test_gguf_integration PRIVATE InferenceEngine)
    endif()
    set_target_properties(test_gguf_integration PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests" CXX_STANDARD 20)
    add_test(NAME test_gguf_integration COMMAND test_gguf_integration)
    message(STATUS "  ✓ Added test_gguf_integration")
endif()

if(NOT TARGET test_swarm_scheduler_pin AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_swarm_scheduler_pin.cpp")
    add_executable(test_swarm_scheduler_pin
        test_swarm_scheduler_pin.cpp
        swarm_scheduler_rawr_loader_link_stub.cpp
        ${CMAKE_SOURCE_DIR}/src/core/swarm_scheduler.cpp
        ${CMAKE_SOURCE_DIR}/src/logging/Logger.cpp
    )
    target_include_directories(test_swarm_scheduler_pin PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src)
    set_target_properties(test_swarm_scheduler_pin PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests" CXX_STANDARD 23)
    add_test(NAME test_swarm_scheduler_pin COMMAND test_swarm_scheduler_pin)
    message(STATUS "  ✓ Added test_swarm_scheduler_pin")
endif()

# Deterministic Replay Gate - IDE determinism validation
if(NOT TARGET deterministic_replay_gate AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/deterministic_replay_gate.cpp")
    add_executable(deterministic_replay_gate deterministic_replay_gate.cpp)
    target_include_directories(deterministic_replay_gate PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src)
    set_target_properties(deterministic_replay_gate PROPERTIES 
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests" 
        CXX_STANDARD 20
    )
    if(WIN32)
        target_link_libraries(deterministic_replay_gate PRIVATE kernel32 user32)
    endif()
    add_test(NAME deterministic_replay_gate COMMAND deterministic_replay_gate)
    set_tests_properties(deterministic_replay_gate PROPERTIES
        TIMEOUT 120
        LABELS "deterministic;ide;ghosttext"
    )
    message(STATUS "  ✓ Added deterministic_replay_gate")
endif()

# VAL-063: Inference Gateway Certification Harness
if(NOT TARGET VAL063_InferenceGatewayHarness AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/VAL063_InferenceGatewayHarness.cpp")
    add_executable(VAL063_InferenceGatewayHarness VAL063_InferenceGatewayHarness.cpp)
    target_include_directories(VAL063_InferenceGatewayHarness PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src)
    set_target_properties(VAL063_InferenceGatewayHarness PROPERTIES 
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests" 
        CXX_STANDARD 20
    )
    if(WIN32)
        target_link_libraries(VAL063_InferenceGatewayHarness PRIVATE kernel32 user32 psapi)
    endif()
    add_test(NAME VAL063_InferenceGatewayHarness COMMAND VAL063_InferenceGatewayHarness)
    set_tests_properties(VAL063_InferenceGatewayHarness PROPERTIES
        TIMEOUT 300
        LABELS "certification;val-063;inference;gateway"
    )
    message(STATUS "  ✓ Added VAL063_InferenceGatewayHarness")
endif()

if(NOT TARGET test_swarm_expert_heatmap_stress AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_swarm_expert_heatmap_stress.cpp")
    add_executable(test_swarm_expert_heatmap_stress
        test_swarm_expert_heatmap_stress.cpp
        swarm_scheduler_rawr_loader_link_stub.cpp
        ${CMAKE_SOURCE_DIR}/src/core/swarm_scheduler.cpp
        ${CMAKE_SOURCE_DIR}/src/logging/Logger.cpp
    )
    target_include_directories(test_swarm_expert_heatmap_stress PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src)
    set_target_properties(test_swarm_expert_heatmap_stress PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests" CXX_STANDARD 23)
    add_test(NAME test_swarm_expert_heatmap_stress COMMAND test_swarm_expert_heatmap_stress)
    message(STATUS "  ✓ Added test_swarm_expert_heatmap_stress")
endif()

if(NOT TARGET test_moe_mixture_reference AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_moe_mixture_reference.cpp")
    add_executable(test_moe_mixture_reference test_moe_mixture_reference.cpp)
    target_include_directories(test_moe_mixture_reference PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src)
    set_target_properties(test_moe_mixture_reference PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests" CXX_STANDARD 20)
    add_test(NAME test_moe_mixture_reference COMMAND test_moe_mixture_reference)
    message(STATUS "  ✓ Added test_moe_mixture_reference")
endif()

if(NOT TARGET test_moe_down_project_policy AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_moe_down_project_policy.cpp")
    add_executable(test_moe_down_project_policy test_moe_down_project_policy.cpp)
    target_include_directories(test_moe_down_project_policy PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src)
    set_target_properties(test_moe_down_project_policy PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests" CXX_STANDARD 20)
    add_test(NAME test_moe_down_project_policy COMMAND test_moe_down_project_policy)
    message(STATUS "  ✓ Added test_moe_down_project_policy")
endif()

if(NOT TARGET test_moe_plan_row_mixture_pack_cache AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_moe_plan_row_mixture_pack_cache.cpp")
    add_executable(test_moe_plan_row_mixture_pack_cache test_moe_plan_row_mixture_pack_cache.cpp)
    target_include_directories(test_moe_plan_row_mixture_pack_cache PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src)
    set_target_properties(test_moe_plan_row_mixture_pack_cache PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests" CXX_STANDARD 20)
    add_test(NAME test_moe_plan_row_mixture_pack_cache COMMAND test_moe_plan_row_mixture_pack_cache)
    message(STATUS "  ✓ Added test_moe_plan_row_mixture_pack_cache")
endif()

if(NOT TARGET moe_grouped_gemm_bench AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/moe_grouped_gemm_bench.cpp")
    add_executable(moe_grouped_gemm_bench moe_grouped_gemm_bench.cpp)
    target_include_directories(moe_grouped_gemm_bench PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src)
    set_target_properties(moe_grouped_gemm_bench PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests" CXX_STANDARD 20)
    message(STATUS "  ✓ Added moe_grouped_gemm_bench (manual / CI microbench; not registered in CTest)")
endif()

if(NOT TARGET test_basic_profiler AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/performance/test_basic_profiler.cpp")
    add_executable(test_basic_profiler
        performance/test_basic_profiler.cpp
        ${CMAKE_SOURCE_DIR}/src/profiler.cpp
        ${CMAKE_SOURCE_DIR}/src/profiling/AdvancedPerformanceProfiler.cpp
    )
    target_include_directories(test_basic_profiler PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src)
    set_target_properties(test_basic_profiler PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests" CXX_STANDARD 20)
    add_test(NAME test_basic_profiler COMMAND test_basic_profiler)
    message(STATUS "  ✓ Added test_basic_profiler")
endif()

if(NOT TARGET test_batch3_profiler_smoke AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/performance/test_batch3_profiler_smoke.cpp")
    add_executable(test_batch3_profiler_smoke
        performance/test_batch3_profiler_smoke.cpp
        ${CMAKE_SOURCE_DIR}/src/profiler.cpp
        ${CMAKE_SOURCE_DIR}/src/profiling/AdvancedPerformanceProfiler.cpp
    )
    target_include_directories(test_batch3_profiler_smoke PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src)
    set_target_properties(test_batch3_profiler_smoke PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests" CXX_STANDARD 20)
    add_test(NAME test_batch3_profiler_smoke COMMAND test_batch3_profiler_smoke)
    message(STATUS "  ✓ Added test_batch3_profiler_smoke")
endif()

# ============================================================
# Test Summary
# ============================================================

# Production Regression Test Suite (Qt-free, no external deps)
if(NOT TARGET test_production_regression AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_production_regression.cpp")
    add_executable(test_production_regression 
        test_production_regression.cpp
        ${CMAKE_SOURCE_DIR}/src/agentic_observability.cpp
        ${CMAKE_SOURCE_DIR}/src/agentic_error_handler.cpp
        ${CMAKE_SOURCE_DIR}/src/agentic_loop_state.cpp
        ${CMAKE_SOURCE_DIR}/src/centralized_exception_handler.cpp
        ${CMAKE_SOURCE_DIR}/src/error_recovery_system.cpp
        ${CMAKE_SOURCE_DIR}/src/production_config_manager.cpp
    )
    target_include_directories(test_production_regression PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/3rdparty
    )
    # Link against the core library when RawrEngine is built as a library target.
    if(TARGET RawrEngine)
        get_target_property(_rawrengine_target_type RawrEngine TYPE)
    endif()
    if(TARGET RawrEngine AND NOT _rawrengine_target_type STREQUAL "EXECUTABLE")
        target_link_libraries(test_production_regression PRIVATE RawrEngine)
    endif()
    set_target_properties(test_production_regression PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
        CXX_STANDARD 20
    )
    add_test(NAME test_production_regression COMMAND test_production_regression)
    message(STATUS "  ✓ Added test_production_regression (Qt-free regression suite)")
endif()

# Instructions Provider Test (getAllContent aggregation, priority sort, hot-reload watcher)
if(NOT TARGET test_instructions_provider AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_instructions_provider.cpp")
    add_executable(test_instructions_provider
        test_instructions_provider.cpp
        ${CMAKE_SOURCE_DIR}/src/core/instructions_provider.cpp
    )
    target_include_directories(test_instructions_provider PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
    )
    set_target_properties(test_instructions_provider PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
        CXX_STANDARD 20
    )
    if(WIN32)
        target_link_libraries(test_instructions_provider PRIVATE shell32 ole32)
    endif()
    add_test(NAME test_instructions_provider COMMAND test_instructions_provider)
    message(STATUS "  ✓ Added test_instructions_provider")
endif()

# =============================================================================
# MEASUREMENT FRAMEWORK - CTest Registration
# These targets are defined in parent CMakeLists.txt, we just register them
# =============================================================================
message(STATUS "========================================")
message(STATUS "Registering Measurement Framework Tests")
message(STATUS "========================================")

# Dispatch Overhead Benchmark
if(TARGET benchmark_dispatch_overhead)
    add_test(NAME benchmark_dispatch_overhead COMMAND benchmark_dispatch_overhead)
    set_tests_properties(benchmark_dispatch_overhead PROPERTIES
        TIMEOUT 60
        LABELS "measurement;performance;dispatch"
    )
    message(STATUS "  [MEASURE] benchmark_dispatch_overhead - RDTSC dispatch latency")
endif()

# Planner Amortization Benchmark
if(TARGET benchmark_planner_amortization)
    add_test(NAME benchmark_planner_amortization COMMAND benchmark_planner_amortization)
    set_tests_properties(benchmark_planner_amortization PROPERTIES
        TIMEOUT 60
        LABELS "measurement;performance;planner"
    )
    message(STATUS "  [MEASURE] benchmark_planner_amortization - Break-even analysis")
endif()

# End-to-End Validation (Four Gates)
if(TARGET validate_end_to_end)
    add_test(NAME validate_end_to_end COMMAND validate_end_to_end)
    set_tests_properties(validate_end_to_end PROPERTIES
        TIMEOUT 120
        LABELS "measurement;validation;gates"
    )
    message(STATUS "  [MEASURE] validate_end_to_end - Four independent gates")
endif()

# NEVM Determinism Validation
if(TARGET nevm_determinism_validation)
    add_test(NAME nevm_determinism_validation COMMAND nevm_determinism_validation)
    set_tests_properties(nevm_determinism_validation PROPERTIES
        TIMEOUT 300
        LABELS "measurement;determinism;stress"
    )
    message(STATUS "  [MEASURE] nevm_determinism_validation - Thread affinity + FNV-1a")
endif()

# NEVM Stress Test
if(TARGET nevm_stress_test)
    add_test(NAME nevm_stress_test COMMAND nevm_stress_test)
    set_tests_properties(nevm_stress_test PROPERTIES
        TIMEOUT 600
        LABELS "measurement;stress;memory"
    )
    message(STATUS "  [MEASURE] nevm_stress_test - 100K token stress + RSS monitoring")
endif()

# PMC Dispatch Benchmark
if(TARGET benchmark_dispatch_pmc)
    add_test(NAME benchmark_dispatch_pmc COMMAND benchmark_dispatch_pmc)
    set_tests_properties(benchmark_dispatch_pmc PROPERTIES
        TIMEOUT 120
        LABELS "measurement;performance;pmc;profiling"
    )
    message(STATUS "  [MEASURE] benchmark_dispatch_pmc - PMC profiling")
endif()

message(STATUS "========================================")
message(STATUS "Test Suite Registration Complete")
message(STATUS "========================================")
message(STATUS "Run all tests:      ctest --output-on-failure -C Release")
message(STATUS "Run measurement:    ctest -L measurement -V -C Release")
message(STATUS "Run specific:       ctest -R <name> -V -C Release")
message(STATUS "========================================")

# Model loader/streamer smoke test (no external model required)
if(NOT TARGET test_model_loader_streamer_smoke AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_model_loader_streamer_smoke.cpp")
    add_executable(test_model_loader_streamer_smoke
        test_model_loader_streamer_smoke.cpp
        gguf_link_stubs.cpp
        ${CMAKE_SOURCE_DIR}/src/gguf_loader.cpp
        ${CMAKE_SOURCE_DIR}/src/gguf_vocab_resolver.cpp
        ${CMAKE_SOURCE_DIR}/src/streaming_gguf_loader.cpp
        ${CMAKE_SOURCE_DIR}/src/utils/Diagnostics.cpp
    )
    target_include_directories(test_model_loader_streamer_smoke PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/3rdparty
    )
    set_target_properties(test_model_loader_streamer_smoke PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
        CXX_STANDARD 20
    )
    add_test(NAME test_model_loader_streamer_smoke COMMAND test_model_loader_streamer_smoke)
    message(STATUS "  ✓ Added test_model_loader_streamer_smoke")
endif()

# Core Smoke Test (minimal, no dependencies)
if(NOT TARGET smoke_core AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/smoke_core.cpp")
    add_executable(smoke_core smoke_core.cpp)
    set_target_properties(smoke_core PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
        CXX_STANDARD 20
    )
    add_test(NAME smoke_core COMMAND smoke_core)
    message(STATUS "  ✓ Added smoke_core (minimal validation)")
endif()

# AVX2 RMSNorm Kernel Test (C-based, no C++ runtime)
if(NOT TARGET test_rmsnorm_avx2 AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/kernels/test_rmsnorm_avx2.c")
    add_executable(test_rmsnorm_avx2
        kernels/test_rmsnorm_avx2.c
        ${CMAKE_SOURCE_DIR}/src/kernels/rmsnorm_avx2_lib.c
    )
    target_include_directories(test_rmsnorm_avx2 PRIVATE ${CMAKE_SOURCE_DIR}/src/kernels)
    set_target_properties(test_rmsnorm_avx2 PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
        C_STANDARD 11
    )
    # Enable AVX2 instruction set
    if(MSVC)
        target_compile_options(test_rmsnorm_avx2 PRIVATE /arch:AVX2)
    else()
        target_compile_options(test_rmsnorm_avx2 PRIVATE -mavx2 -mfma)
    endif()
    add_test(NAME test_rmsnorm_avx2 COMMAND test_rmsnorm_avx2)
    message(STATUS "  ✓ Added test_rmsnorm_avx2 (AVX2 kernel validation)")
endif()

# AVX2 Softmax Kernel Test (C-based, no C++ runtime)
if(NOT TARGET test_softmax_avx2 AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/kernels/test_softmax_avx2.c")
    add_executable(test_softmax_avx2
        kernels/test_softmax_avx2.c
        ${CMAKE_SOURCE_DIR}/src/kernels/softmax_avx2_lib.c
    )
    target_include_directories(test_softmax_avx2 PRIVATE ${CMAKE_SOURCE_DIR}/src/kernels)
    set_target_properties(test_softmax_avx2 PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
        C_STANDARD 11
    )
    # Enable AVX2 instruction set
    if(MSVC)
        target_compile_options(test_softmax_avx2 PRIVATE /arch:AVX2)
    else()
        target_compile_options(test_softmax_avx2 PRIVATE -mavx2 -mfma)
    endif()
    add_test(NAME test_softmax_avx2 COMMAND test_softmax_avx2)
    message(STATUS "  ✓ Added test_softmax_avx2 (AVX2 kernel validation)")
endif()

# Sovereign Integrated Burn-in Test
if(NOT TARGET sovereign_integrated_test AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/sovereign_integrated_test.cpp")
    add_executable(sovereign_integrated_test
        sovereign_integrated_test.cpp
        ${CMAKE_SOURCE_DIR}/src/sovereign/SovereignVCS.cpp
        ${CMAKE_SOURCE_DIR}/src/sovereign/SovereignCheckpoint.cpp
        ${CMAKE_SOURCE_DIR}/src/sovereign/IDE_Lifecycle_Hook.cpp
    )
    target_include_directories(sovereign_integrated_test PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/sovereign
    )
    set_target_properties(sovereign_integrated_test PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
        CXX_STANDARD 20
    )
    # Link RawrXD compression (zero-dependency x64 MASM)
    if(TARGET RawrXD_Compression)
        target_link_libraries(sovereign_integrated_test PRIVATE RawrXD_Compression)
        target_compile_definitions(sovereign_integrated_test PRIVATE HAS_RAWRXD_COMPRESSION=1)
        message(STATUS "  ✓ Using RawrXD_Compression for checkpoint compression")
    else()
        message(WARNING "  RawrXD_Compression not available - checkpoint compression disabled")
    endif()
    add_test(NAME sovereign_integrated_test COMMAND sovereign_integrated_test)
    message(STATUS "  ✓ Added sovereign_integrated_test (Sovereign Burn-in)")
endif()

# Agentic Supervisor Test
if(NOT TARGET test_agentic_supervisor AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_agentic_supervisor.cpp")
    add_executable(test_agentic_supervisor
        test_agentic_supervisor.cpp
        ${CMAKE_SOURCE_DIR}/src/agentic/AgenticSupervisor.cpp
        ${CMAKE_SOURCE_DIR}/src/sovereign/IDE_Lifecycle_Hook.cpp
        ${CMAKE_SOURCE_DIR}/src/sovereign/SovereignVCS.cpp
        ${CMAKE_SOURCE_DIR}/src/sovereign/SovereignCheckpoint.cpp
    )
    target_include_directories(test_agentic_supervisor PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/agentic
        ${CMAKE_SOURCE_DIR}/src/sovereign
    )
    set_target_properties(test_agentic_supervisor PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
        CXX_STANDARD 20
    )
    add_test(NAME test_agentic_supervisor COMMAND test_agentic_supervisor)
    message(STATUS "  ✓ Added test_agentic_supervisor (Agentic Supervisor)")
endif()
=======
<<<<<<< HEAD
# CMakeLists.txt for Unit Tests
# Google Test and Qt Test Framework configuration for RawrXD IDE components

cmake_minimum_required(VERSION 3.16)

# Enable testing
enable_testing()

# Find required packages
    Core 
    Gui 
    Sql 
    Network 
    Multimedia 
    Concurrent
    REQUIRED
)

# Google Test
include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
)

# Prevent installation of gtest
set(INSTALL_GTEST OFF CACHE BOOL "Disable gtest installation" FORCE)

FetchContent_MakeAvailable(googletest)

# ============= Voice Processor Tests =============
add_executable(voice_processor_test
    voice_processor_test.cpp
)

target_link_libraries(voice_processor_test
    PRIVATE
        gtest
        gtest_main
)

target_include_directories(voice_processor_test
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src
)

add_test(
    NAME VoiceProcessorTests
    COMMAND voice_processor_test
)

# ============= AI Merge Resolver Tests =============
add_executable(ai_merge_resolver_test
    ai_merge_resolver_test.cpp
)

target_link_libraries(ai_merge_resolver_test
    PRIVATE
        gtest
        gtest_main
)

target_include_directories(ai_merge_resolver_test
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src
)

add_test(
    NAME AIMergeResolverTests
    COMMAND ai_merge_resolver_test
)

# ============= Semantic Diff Analyzer Tests =============
add_executable(semantic_diff_analyzer_test
    semantic_diff_analyzer_test.cpp
)

target_link_libraries(semantic_diff_analyzer_test
    PRIVATE
        gtest
        gtest_main
)

target_include_directories(semantic_diff_analyzer_test
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src
)

add_test(
    NAME SemanticDiffAnalyzerTests
    COMMAND semantic_diff_analyzer_test
)

# ============= Zero Retention Manager Tests =============
add_executable(zero_retention_manager_test
    zero_retention_manager_test.cpp
)

target_link_libraries(zero_retention_manager_test
    PRIVATE
        gtest
        gtest_main
)

target_include_directories(zero_retention_manager_test
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src
)

add_test(
    NAME ZeroRetentionManagerTests
    COMMAND zero_retention_manager_test
)

# ============= Sandboxed Terminal Tests =============
add_executable(sandboxed_terminal_test
    sandboxed_terminal_test.cpp
)

target_link_libraries(sandboxed_terminal_test
    PRIVATE
        gtest
        gtest_main
)

target_include_directories(sandboxed_terminal_test
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src
)

add_test(
    NAME SandboxedTerminalTests
    COMMAND sandboxed_terminal_test
)

# ============= Model Registry Tests =============
add_executable(model_registry_test
    model_registry_test.cpp
)

target_link_libraries(model_registry_test
    PRIVATE
)

target_include_directories(model_registry_test
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src
)

add_test(
    NAME ModelRegistryTests
    COMMAND model_registry_test
)

# ============= Test Configuration Options =============

# Enable verbose test output
set(CMAKE_CTEST_COMMAND ctest --verbose)

# Set compiler flags for testing
if(MSVC)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /EHsc /W4")
else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -std=c++17")
endif()

# ============= Test Coverage (Optional) =============

# Uncomment to enable code coverage reporting
# include(CodeCoverage)
# append_coverage_compiler_flags()

# ============= Custom Test Targets =============

# Run all tests
add_custom_target(run_all_tests
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    DEPENDS 
        voice_processor_test
        ai_merge_resolver_test
        semantic_diff_analyzer_test
        zero_retention_manager_test
        sandboxed_terminal_test
        model_registry_test
    COMMENT "Running all unit tests"
)

# Run only Google Test tests
add_custom_target(run_gtest_tests
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
            -R "(VoiceProcessor|AIMergeResolver|SemanticDiffAnalyzer|ZeroRetentionManager|SandboxedTerminal)"
    DEPENDS 
        voice_processor_test
        ai_merge_resolver_test
        semantic_diff_analyzer_test
        zero_retention_manager_test
        sandboxed_terminal_test
    COMMENT "Running Google Test suite"
)

# Run only Qt Test tests
add_custom_target(run_qt_tests
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
            -R "ModelRegistry"
    DEPENDS model_registry_test
    COMMENT "Running Qt Test suite"
)

# Run specific test suite with verbose output
add_custom_target(run_voice_processor_tests
    COMMAND voice_processor_test
    DEPENDS voice_processor_test
    COMMENT "Running VoiceProcessor tests"
)

add_custom_target(run_ai_merge_resolver_tests
    COMMAND ai_merge_resolver_test
    DEPENDS ai_merge_resolver_test
    COMMENT "Running AIMergeResolver tests"
)

add_custom_target(run_semantic_diff_analyzer_tests
    COMMAND semantic_diff_analyzer_test
    DEPENDS semantic_diff_analyzer_test
    COMMENT "Running SemanticDiffAnalyzer tests"
)

add_custom_target(run_zero_retention_manager_tests
    COMMAND zero_retention_manager_test
    DEPENDS zero_retention_manager_test
    COMMENT "Running ZeroRetentionManager tests"
)

add_custom_target(run_sandboxed_terminal_tests
    COMMAND sandboxed_terminal_test
    DEPENDS sandboxed_terminal_test
    COMMENT "Running SandboxedTerminal tests"
)

add_custom_target(run_model_registry_tests
    COMMAND model_registry_test
    DEPENDS model_registry_test
    COMMENT "Running ModelRegistry tests"
)

# ============= Test Summary =============

message(STATUS "")
message(STATUS "========== Test Configuration ==========")
message(STATUS "Google Test Framework: Enabled")
message(STATUS "Qt Test Framework: Enabled")
message(STATUS "")
message(STATUS "Test Targets Created:")
message(STATUS "  - voice_processor_test (33 tests)")
message(STATUS "  - ai_merge_resolver_test (40+ tests)")
message(STATUS "  - semantic_diff_analyzer_test (45+ tests)")
message(STATUS "  - zero_retention_manager_test (50+ tests)")
message(STATUS "  - sandboxed_terminal_test (55+ tests)")
message(STATUS "  - model_registry_test (67 tests)")
message(STATUS "")
message(STATUS "Custom Targets:")
message(STATUS "  - run_all_tests (run all test suites)")
message(STATUS "  - run_gtest_tests (run Google Test suite)")
message(STATUS "  - run_qt_tests (run Qt Test suite)")
message(STATUS "  - run_[component]_tests (run individual component tests)")
message(STATUS "")
message(STATUS "Build and run tests with:")
message(STATUS "  cmake --build . --target run_all_tests")
message(STATUS "")
message(STATUS "Total Test Coverage: ~290 individual test cases")
message(STATUS "=========================================")
message(STATUS "")

# ============= CTest Configuration =============

# Set timeout for long-running tests (in seconds)
set_tests_properties(
    VoiceProcessorTests
    AIMergeResolverTests
    SemanticDiffAnalyzerTests
    ZeroRetentionManagerTests
    SandboxedTerminalTests
    ModelRegistryTests
    PROPERTIES TIMEOUT 300
)

# Configure parallel test execution
set(CTEST_PARALLEL_LEVEL 4 CACHE STRING "Number of parallel test processes")

# Enable detailed output on test failure
set(CTEST_OUTPUT_ON_FAILURE ON CACHE BOOL "Output on test failure")
=======
find_library(MATH_LIBRARY m)

# check systems
if (NOT UNAME_S)
    execute_process(COMMAND uname -s OUTPUT_VARIABLE UNAME_S)
endif()
if (NOT UNAME_P)
    execute_process(COMMAND uname -p OUTPUT_VARIABLE UNAME_P)
endif()
if (NOT UNAME_M)
    execute_process(COMMAND uname -m OUTPUT_VARIABLE UNAME_M)
endif()
#message(STATUS "UNAME_S: ${UNAME_S}  UNAME_P: ${UNAME_P}  UNAME_M: ${UNAME_M}")

# Mac OS + Arm can report x86_64
# ref: https://github.com/ggerganov/whisper.cpp/issues/66#issuecomment-1282546789
if (UNAME_S MATCHES "Darwin")
    if (NOT UNAME_P MATCHES "arm")
        execute_process(COMMAND sysctl -n hw.optional.arm64 OUTPUT_VARIABLE SYSCTL_M)
        if (SYSCTL_M MATCHES "1")
            #set(UNAME_P "arm")
            #set(UNAME_M "arm64")
            message(WARNING "Your arch is announced as x86_64, but it seems to actually be ARM64. Not fixing that can lea
d to bad performance. For more info see: https://github.com/ggerganov/whisper.cpp/issues/66\#issuecomment-#1282546789")
        endif()
    endif()
endif()

if (${CMAKE_SYSTEM_PROCESSOR} MATCHES "^(aarch64|arm.*|ARM64)$")
    message(STATUS "ARM detected")
    #set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mcpu=apple-m1")
elseif (${CMAKE_SYSTEM_PROCESSOR} MATCHES "ppc64le" OR ${CMAKE_SYSTEM_PROCESSOR} MATCHES "ppc64")
    message(STATUS "PPC64 detected")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mpower9-vector")
elseif (${CMAKE_SYSTEM_PROCESSOR} MATCHES "loongarch64")
    message(STATUS "loongarch64 detected")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mlsx -mlasx")
else()
    message(STATUS "x86 detected")
    #set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mavx -mavx2 -mfma -mf16c")
    if (UNAME_S MATCHES "Darwin")
        execute_process(COMMAND sysctl machdep.cpu.features OUTPUT_VARIABLE AVX1_M)
        if (AVX1_M MATCHES "AVX1.0")
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mavx")
        endif()
        execute_process(COMMAND sysctl machdep.cpu.leaf7_features OUTPUT_VARIABLE AVX2_M)
        if (AVX2_M MATCHES "AVX2")
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mavx2")
        endif()
        if (AVX1_M MATCHES "FMA")
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mfma")
        endif()
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mf16c")
    elseif (UNAME_S MATCHES "Linux")
        message(STATUS "Linux detected")
        # must have to build on ubuntu22 with gcc11:
        find_package(Threads)
        set(GGML_EXTRA_LIBS  ${GGML_EXTRA_LIBS} Threads::Threads)

        execute_process(COMMAND grep "avx " /proc/cpuinfo OUTPUT_VARIABLE AVX1_M)
        if (AVX1_M MATCHES "avx")
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mavx")
        endif()
        execute_process(COMMAND grep "avx2 " /proc/cpuinfo OUTPUT_VARIABLE AVX2_M)
        if (AVX2_M MATCHES "avx2")
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mavx2")
        endif()
        execute_process(COMMAND grep "fma " /proc/cpuinfo OUTPUT_VARIABLE FMA_M)
        if (FMA_M MATCHES "fma")
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mfma")
        endif()
        execute_process(COMMAND grep "f16c " /proc/cpuinfo OUTPUT_VARIABLE F16C_M)
        if (F16C_M MATCHES "f16c")
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mf16c")
        endif()
        execute_process(COMMAND grep "sse3 " /proc/cpuinfo OUTPUT_VARIABLE SSE3_M)
        if (SSE3_M MATCHES "sse3")
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -msse3")
        endif()
    elseif (UNAME_S MATCHES "Haiku")
        message(STATUS "Haiku detected")
	execute_process(COMMAND sysinfo -cpu COMMAND grep "AVX " OUTPUT_VARIABLE AVX1_M)
        if (AVX1_M MATCHES "avx")
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mavx")
        endif()
	execute_process(COMMAND sysinfo -cpu COMMAND grep "AVX2 " OUTPUT_VARIABLE AVX2_M)
        if (AVX2_M MATCHES "avx2")
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mavx2")
        endif()
	execute_process(COMMAND sysinfo -cpu COMMAND grep "FMA " OUTPUT_VARIABLE FMA_M)
        if (FMA_M MATCHES "fma")
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mfma")
        endif()
	execute_process(COMMAND sysinfo -cpu COMMAND grep "F16C " OUTPUT_VARIABLE F16C_M)
        if (F16C_M MATCHES "f16c")
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mf16c")
        endif()
    elseif (MSVC)
        if (GGML_AVX512)
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /arch:AVX512")
            # MSVC has no compile-time flags enabling specific
            # AVX512 extensions, neither it defines the
            # macros corresponding to the extensions.
            # Do it manually.
            if (GGML_AVX512_VBMI)
                add_compile_definitions(__AVX512VBMI__)
            endif()
            if (GGML_AVX512_VNNI)
                add_compile_definitions(__AVX512VNNI__)
            endif()
        elseif (GGML_AVX2)
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /arch:AVX2")
        elseif (GGML_AVX)
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /arch:AVX")
        endif()
    else()
        set(CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} -mfma -mf16c -mavx -mavx2")
    endif()
endif()

# on APPLE - include Accelerate framework
if (APPLE AND NOT GGML_NO_ACCELERATE)
    find_library(ACCELERATE_FRAMEWORK Accelerate)
    if (ACCELERATE_FRAMEWORK)
        message(STATUS "Accelerate framework found")

        set(GGML_EXTRA_LIBS  ${GGML_EXTRA_LIBS}  ${ACCELERATE_FRAMEWORK})
        set(GGML_EXTRA_FLAGS ${GGML_EXTRA_FLAGS} -DGGML_USE_ACCELERATE)
    else()
        message(WARNING "Accelerate framework not found")
    endif()
endif()

if (GGML_OPENBLAS)
    set(OPENBLAS_INCLUDE_SEARCH_PATHS
        /usr/include
        /usr/include/openblas
        /usr/include/openblas-base
        /usr/local/include
        /usr/local/include/openblas
        /usr/local/include/openblas-base
        /opt/OpenBLAS/include
        $ENV{OpenBLAS_HOME}
        $ENV{OpenBLAS_HOME}/include
        )
    find_path(OPENBLAS_INC NAMES cblas.h PATHS ${OPENBLAS_INCLUDE_SEARCH_PATHS})
    find_library(OPENBLAS_LIB NAMES openblas libopenblas)
    if (OPENBLAS_LIB)
        message(STATUS "OpenBLAS found")

        set(GGML_EXTRA_LIBS  ${GGML_EXTRA_LIBS}  ${OPENBLAS_LIB})
        set(GGML_EXTRA_INCS  ${GGML_EXTRA_INCS}  ${OPENBLAS_INC})
        set(GGML_EXTRA_FLAGS ${GGML_EXTRA_FLAGS} -DGGML_USE_OPENBLAS)
    else()
        message(WARNING "OpenBLAS not found")
    endif()
endif()

# undefine NDEBUG so asserts don't get disabled in tests
add_definitions(-UNDEBUG)

#
# test-backend-ops

set(TEST_TARGET test-backend-ops)
add_executable(${TEST_TARGET} ${TEST_TARGET}.cpp)
target_link_libraries(${TEST_TARGET} PRIVATE ggml Threads::Threads)
add_test(NAME ${TEST_TARGET} COMMAND $<TARGET_FILE:${TEST_TARGET}>)
set_property(TEST ${TEST_TARGET} PROPERTY ENVIRONMENT "LLVM_PROFILE_FILE=${TEST_TARGET}.profraw")


if (NOT GGML_BACKEND_DL)
    #
    # test-opt
    set(TEST_TARGET test-opt)
    add_executable(${TEST_TARGET} ${TEST_TARGET}.cpp)
    target_link_libraries(${TEST_TARGET} PRIVATE ggml)
    add_test(NAME ${TEST_TARGET} COMMAND $<TARGET_FILE:${TEST_TARGET}>)
    set_property(TEST ${TEST_TARGET} PROPERTY ENVIRONMENT "LLVM_PROFILE_FILE=${TEST_TARGET}.profraw")

    #
    # test-quantize-fns

    set(TEST_TARGET test-quantize-fns)
    add_executable(${TEST_TARGET} ${TEST_TARGET}.cpp)
    target_link_libraries(${TEST_TARGET} PRIVATE ggml)
    add_test(NAME ${TEST_TARGET} COMMAND $<TARGET_FILE:${TEST_TARGET}>)
    set_property(TEST ${TEST_TARGET} PROPERTY ENVIRONMENT "LLVM_PROFILE_FILE=${TEST_TARGET}.profraw")

    #
    # test-quantize-perf

    set(TEST_TARGET test-quantize-perf)
    add_executable(${TEST_TARGET} ${TEST_TARGET}.cpp)
    target_link_libraries(${TEST_TARGET} PRIVATE ggml)
    add_test(NAME ${TEST_TARGET} COMMAND $<TARGET_FILE:${TEST_TARGET}>)
    set_property(TEST ${TEST_TARGET} PROPERTY ENVIRONMENT "LLVM_PROFILE_FILE=${TEST_TARGET}.profraw")

    #
    # test-pool

    set(TEST_TARGET test-pool)
    add_executable(${TEST_TARGET} ${TEST_TARGET}.c)
    target_link_libraries(${TEST_TARGET} PRIVATE ggml)
    if (MSVC)
        target_link_options(${TEST_TARGET} PRIVATE "/STACK:8388608") # 8MB
    endif()
    add_test(NAME ${TEST_TARGET} COMMAND $<TARGET_FILE:${TEST_TARGET}>)
    set_property(TEST ${TEST_TARGET} PROPERTY ENVIRONMENT "LLVM_PROFILE_FILE=${TEST_TARGET}.profraw")

    #
    # test-arange

    set(TEST_TARGET test-arange)
    add_executable(${TEST_TARGET} ${TEST_TARGET}.cpp)
    target_link_libraries(${TEST_TARGET} PRIVATE ggml Threads::Threads)
    if (MSVC)
        target_link_options(${TEST_TARGET} PRIVATE "/STACK:8388608") # 8MB
    endif()
    add_test(NAME ${TEST_TARGET} COMMAND $<TARGET_FILE:${TEST_TARGET}>)
    set_property(TEST ${TEST_TARGET} PROPERTY ENVIRONMENT "LLVM_PROFILE_FILE=${TEST_TARGET}.profraw")

    #
    # test-timestep_embedding

    set(TEST_TARGET test-timestep_embedding)
    add_executable(${TEST_TARGET} ${TEST_TARGET}.cpp)
    target_link_libraries(${TEST_TARGET} PRIVATE ggml)
    if (MSVC)
        target_link_options(${TEST_TARGET} PRIVATE "/STACK:8388608") # 8MB
    endif()
    add_test(NAME ${TEST_TARGET} COMMAND $<TARGET_FILE:${TEST_TARGET}>)
    set_property(TEST ${TEST_TARGET} PROPERTY ENVIRONMENT "LLVM_PROFILE_FILE=${TEST_TARGET}.profraw")

    #
    # test-pad-reflect-1d

    set(TEST_TARGET test-pad-reflect-1d)
    add_executable(${TEST_TARGET} ${TEST_TARGET}.cpp)
    target_link_libraries(${TEST_TARGET} PRIVATE ggml)
    add_test(NAME ${TEST_TARGET} COMMAND $<TARGET_FILE:${TEST_TARGET}>)

    #
    # test-roll

    set(TEST_TARGET test-roll)
    add_executable(${TEST_TARGET} ${TEST_TARGET}.cpp)
    target_link_libraries(${TEST_TARGET} PRIVATE ggml)
    add_test(NAME ${TEST_TARGET} COMMAND $<TARGET_FILE:${TEST_TARGET}>)

    #
    # test-conv-transpose

    set(TEST_TARGET test-conv-transpose)
    add_executable(${TEST_TARGET} ${TEST_TARGET}.c)
    target_link_libraries(${TEST_TARGET} PRIVATE ggml)
    add_test(NAME ${TEST_TARGET} COMMAND $<TARGET_FILE:${TEST_TARGET}>)

    # test-conv-transpose-1d

    set(TEST_TARGET test-conv-transpose-1d)
    add_executable(${TEST_TARGET} ${TEST_TARGET}.cpp)
    target_link_libraries(${TEST_TARGET} PRIVATE ggml)
    add_test(NAME ${TEST_TARGET} COMMAND $<TARGET_FILE:${TEST_TARGET}>)

    #
    # test-dup

    set(TEST_TARGET test-dup)
    add_executable(${TEST_TARGET} ${TEST_TARGET}.c)
    target_link_libraries(${TEST_TARGET} PRIVATE ggml)
    add_test(NAME ${TEST_TARGET} COMMAND $<TARGET_FILE:${TEST_TARGET}>)

    #
    # test-rel-pos

    set(TEST_TARGET test-rel-pos)
    add_executable(${TEST_TARGET} ${TEST_TARGET}.c)
    target_link_libraries(${TEST_TARGET} PRIVATE ggml)
    add_test(NAME ${TEST_TARGET} COMMAND $<TARGET_FILE:${TEST_TARGET}>)

    #
    # test-customop

    set(TEST_TARGET test-customop)
    add_executable(${TEST_TARGET} ${TEST_TARGET}.c)
    target_link_libraries(${TEST_TARGET} PRIVATE ggml)
    if (MSVC)
        target_link_options(${TEST_TARGET} PRIVATE "/STACK:8388608") # 8MB
    endif()
    add_test(NAME ${TEST_TARGET} COMMAND $<TARGET_FILE:${TEST_TARGET}>)
    set_property(TEST ${TEST_TARGET} PROPERTY ENVIRONMENT "LLVM_PROFILE_FILE=${TEST_TARGET}.profraw")

    #
    # test-conv1d

    set(TEST_TARGET test-conv1d)
    add_executable(${TEST_TARGET} ${TEST_TARGET}.cpp)
    target_link_libraries(${TEST_TARGET} PRIVATE ggml)
    add_test(NAME ${TEST_TARGET} COMMAND $<TARGET_FILE:${TEST_TARGET}>)
    set_property(TEST ${TEST_TARGET} PROPERTY ENVIRONMENT "LLVM_PROFILE_FILE=${TEST_TARGET}.profraw")

    #
    # test-conv1d-dw-c1

    set(TEST_TARGET test-conv1d-dw-c1)
    add_executable(${TEST_TARGET} ${TEST_TARGET}.cpp)
    target_link_libraries(${TEST_TARGET} PRIVATE ggml)
    add_test(NAME ${TEST_TARGET} COMMAND $<TARGET_FILE:${TEST_TARGET}>)
    set_property(TEST ${TEST_TARGET} PROPERTY ENVIRONMENT "LLVM_PROFILE_FILE=${TEST_TARGET}.profraw")

    #
    # test-conv1d-dw-c2

    set(TEST_TARGET test-conv1d-dw-c2)
    add_executable(${TEST_TARGET} ${TEST_TARGET}.cpp)
    target_link_libraries(${TEST_TARGET} PRIVATE ggml)
    add_test(NAME ${TEST_TARGET} COMMAND $<TARGET_FILE:${TEST_TARGET}>)
    set_property(TEST ${TEST_TARGET} PROPERTY ENVIRONMENT "LLVM_PROFILE_FILE=${TEST_TARGET}.profraw")

    #
    # test-conv2d

    set(TEST_TARGET test-conv2d)
    add_executable(${TEST_TARGET} ${TEST_TARGET}.cpp)
    target_link_libraries(${TEST_TARGET} PRIVATE ggml)
    add_test(NAME ${TEST_TARGET} COMMAND $<TARGET_FILE:${TEST_TARGET}>)
    set_property(TEST ${TEST_TARGET} PROPERTY ENVIRONMENT "LLVM_PROFILE_FILE=${TEST_TARGET}.profraw")

    #
    # test-conv2d-dw

    set(TEST_TARGET test-conv2d-dw)
    add_executable(${TEST_TARGET} ${TEST_TARGET}.cpp)
    target_link_libraries(${TEST_TARGET} PRIVATE ggml)
    add_test(NAME ${TEST_TARGET} COMMAND $<TARGET_FILE:${TEST_TARGET}>)
    set_property(TEST ${TEST_TARGET} PROPERTY ENVIRONMENT "LLVM_PROFILE_FILE=${TEST_TARGET}.profraw")

    #
    # test-cont

    set(TEST_TARGET test-cont)
    add_executable(${TEST_TARGET} ${TEST_TARGET}.c)
    target_link_libraries(${TEST_TARGET} PRIVATE ggml)
    add_test(NAME ${TEST_TARGET} COMMAND $<TARGET_FILE:${TEST_TARGET}>)
    set_property(TEST ${TEST_TARGET} PROPERTY ENVIRONMENT "LLVM_PROFILE_FILE=${TEST_TARGET}.profraw")

    #
    # test-interpolate

    set(TEST_TARGET test-interpolate)
    add_executable(${TEST_TARGET} ${TEST_TARGET}.cpp)
    target_link_libraries(${TEST_TARGET} PRIVATE ggml)
    add_test(NAME ${TEST_TARGET} COMMAND $<TARGET_FILE:${TEST_TARGET}>)
    set_property(TEST ${TEST_TARGET} PROPERTY ENVIRONMENT "LLVM_PROFILE_FILE=${TEST_TARGET}.profraw")
endif()
>>>>>>> upstream/master
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
