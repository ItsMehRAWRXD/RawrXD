# RawrXD Benchmark Suite v2.1 - Phase D.5 Refined
# CMake Build Configuration

cmake_minimum_required(VERSION 3.16)
project(RawrXDBenchmarkSuite VERSION 2.1.0 LANGUAGES CXX)

# C++ Standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build options
option(RAWRXD_BUILD_TESTS "Build benchmark validation tests" ON)
option(RAWRXD_BUILD_OLLAMA_ADAPTER "Build Ollama comparison adapter" ON)
option(RAWRXD_ENABLE_PROFILING "Enable performance profiling" OFF)
option(RAWRXD_BUILD_PHASE_E "Build Phase E statistical validation" ON)

# Find required packages
find_package(Threads REQUIRED)
find_package(CURL REQUIRED)

# Optional packages
find_package(SQLite3)
if(SQLite3_FOUND)
    message(STATUS "SQLite3 found - regression tracking enabled")
else()
    message(WARNING "SQLite3 not found - regression tracking disabled")
endif()

# Platform detection
if(WIN32)
    add_definitions(-D_WIN32_WINNT=0x0A00 -DWIN32_LEAN_AND_MEAN -DNOMINMAX)
    set(PLATFORM_LIBS ws2_32)
elseif(APPLE)
    find_library(COREFOUNDATION_LIBRARY CoreFoundation)
    set(PLATFORM_LIBS ${COREFOUNDATION_LIBRARY})
else()
    set(PLATFORM_LIBS rt)
endif()

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CURL_INCLUDE_DIRS}
)

if(SQLite3_FOUND)
    include_directories(${SQLite3_INCLUDE_DIRS})
endif()

# Core library - statistical metrics and common utilities
add_library(benchmark_core STATIC
    src/statistical_metrics.cpp
    src/workload_loader.cpp
)

target_link_libraries(benchmark_core PUBLIC
    Threads::Threads
    ${CURL_LIBRARIES}
)

if(SQLite3_FOUND)
    target_link_libraries(benchmark_core PUBLIC SQLite::SQLite3)
    target_compile_definitions(benchmark_core PUBLIC HAS_SQLITE3=1)
endif()

# Phase D.5 Refined - 4-Tier Benchmarks
set(REFINED_BENCHMARK_SOURCES
    src/benchmark_tiers.cpp
    src/ci_regression_checker.cpp
)

# Batch 4 Stress & Chaos Benchmarks
set(STRESS_BENCHMARK_SOURCES
    src/stress_overload_benchmark.cpp
    src/swarm_overload_benchmark.cpp
    src/mutation_storm_benchmark.cpp
    src/degradation_curve_benchmark.cpp
    src/resource_pressure_benchmark.cpp
    src/chaos_resilience_benchmark.cpp
    src/chaos_engine.cpp
)

# Main executables

# 1. Phase D.5 Refined benchmark runner
add_executable(benchmark_runner
    src/main.cpp
    ${REFINED_BENCHMARK_SOURCES}
    ${STRESS_BENCHMARK_SOURCES}
)

target_link_libraries(benchmark_runner PRIVATE
    benchmark_core
    ${PLATFORM_LIBS}
)

# 2. Stress test suite (Batch 4 focused)
add_executable(stress_test_suite
    src/stress_test_main.cpp
    ${STRESS_BENCHMARK_SOURCES}
)

target_link_libraries(stress_test_suite PRIVATE
    benchmark_core
    ${PLATFORM_LIBS}
)

# Phase E: Statistical Validation (optional)
if(RAWRXD_BUILD_PHASE_E)
    set(STATISTICAL_SOURCES
        src/statistical_comparison.cpp
    )
    
    add_library(statistical_comparison STATIC ${STATISTICAL_SOURCES})
    
    add_executable(phase_e_benchmark src/phase_e_benchmark.cpp)
    target_link_libraries(phase_e_benchmark statistical_comparison Threads::Threads)
endif()

# Phase 3: Real Backend Integration
set(BACKEND_INTEGRATION_SOURCES
    src/http_client.cpp
    src/sovereign_backend.cpp
    src/ollama_backend.cpp
    src/backend_factory.cpp
    src/result_validator.cpp
    src/baseline_manager.cpp
    src/integrated_runner.cpp
)

add_library(backend_integration STATIC ${BACKEND_INTEGRATION_SOURCES})

target_link_libraries(backend_integration PUBLIC
    benchmark_core
    Threads::Threads
    ${PLATFORM_LIBS}
)

# Integrated benchmark runner with real backends
add_executable(integrated_benchmark_runner
    src/main.cpp
    ${BACKEND_INTEGRATION_SOURCES}
    ${REFINED_BENCHMARK_SOURCES}
    ${STRESS_BENCHMARK_SOURCES}
)

target_link_libraries(integrated_benchmark_runner PRIVATE
    benchmark_core
    backend_integration
    ${PLATFORM_LIBS}
)

# Compiler warnings
if(MSVC)
    target_compile_options(benchmark_core PRIVATE /W4 /WX-)
    target_compile_options(benchmark_runner PRIVATE /W4 /WX-)
    target_compile_options(stress_test_suite PRIVATE /W4 /WX-)
else()
    target_compile_options(benchmark_core PRIVATE -Wall -Wextra -Wno-unused-parameter)
    target_compile_options(benchmark_runner PRIVATE -Wall -Wextra)
    target_compile_options(stress_test_suite PRIVATE -Wall -Wextra)
endif()

# Tests
if(RAWRXD_BUILD_TESTS)
    enable_testing()
    
    # Test infrastructure
    set(TEST_SOURCES
        tests/http_client_tests.cpp
        tests/test_main.cpp
    )
    
    # HTTP Client Unit Tests
    add_executable(http_client_tests ${TEST_SOURCES})
    target_link_libraries(http_client_tests PRIVATE
        benchmark_core
        backend_integration
        ${PLATFORM_LIBS}
    )
    target_include_directories(http_client_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/tests
    )
    
    # Backend Adapter Tests
    add_executable(backend_adapter_tests
        tests/test_main.cpp
    )
    target_link_libraries(backend_adapter_tests PRIVATE
        benchmark_core
        backend_integration
        ${PLATFORM_LIBS}
    )
    target_include_directories(backend_adapter_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/tests
    )
    
    # End-to-End Tests
    add_executable(e2e_tests
        tests/test_main.cpp
    )
    target_link_libraries(e2e_tests PRIVATE
        benchmark_core
        backend_integration
        ${PLATFORM_LIBS}
    )
    target_include_directories(e2e_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/tests
    )
    
    # CTest definitions
    add_test(NAME http_client_unit_tests
        COMMAND http_client_tests --category http
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
    set_tests_properties(http_client_unit_tests PROPERTIES TIMEOUT 120)
    
    add_test(NAME backend_adapter_tests
        COMMAND backend_adapter_tests --category backend
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
    set_tests_properties(backend_adapter_tests PROPERTIES TIMEOUT 120)
    
    add_test(NAME e2e_smoke_tests
        COMMAND e2e_tests --category smoke
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
    set_tests_properties(e2e_smoke_tests PROPERTIES TIMEOUT 300)
    
    add_test(NAME benchmark_quick_validation
        COMMAND benchmark_runner --tier 1 --warmup 1 --runs 5
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
    set_tests_properties(benchmark_quick_validation PROPERTIES TIMEOUT 60)
    
    add_test(NAME benchmark_help
        COMMAND benchmark_runner --help
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
endif()

# Installation
install(TARGETS benchmark_runner stress_test_suite RUNTIME DESTINATION bin)

if(RAWRXD_BUILD_PHASE_E)
    install(TARGETS phase_e_benchmark RUNTIME DESTINATION bin)
endif()

install(FILES
    include/benchmark_common.hpp
    include/benchmark_tiers.hpp
    include/chaos_engine.hpp
    include/workload_profiles.hpp
    include/orchestration_telemetry.hpp
    DESTINATION include/rawrxd/benchmarks
)

# Print configuration summary
message(STATUS "")
message(STATUS "╔══════════════════════════════════════════════════════════════╗")
message(STATUS "║     RawrXD Benchmark Suite v${PROJECT_VERSION} Configuration          ║")
message(STATUS "╠══════════════════════════════════════════════════════════════╣")
message(STATUS "║  Phase D.5 Refined Features:                                 ║")
message(STATUS "║    ✓ 4-Tier Benchmark Structure                              ║")
message(STATUS "║    ✓ Statistical Rigor (95% CI, warmup protocols)           ║")
message(STATUS "║    ✓ Batch 4: Stress & Chaos Benchmarks                    ║")
message(STATUS "║    ✓ CI Regression Gates                                  ║")
message(STATUS "╠══════════════════════════════════════════════════════════════╣")
message(STATUS "║  Phase 3: Real Backend Integration:                          ║")
message(STATUS "║    ✓ HTTP Client with Connection Pooling                    ║")
message(STATUS "║    ✓ Sovereign Backend Adapter (localhost:8080)            ║")
message(STATUS "║    ✓ Ollama Backend Adapter (localhost:11434)              ║")
message(STATUS "║    ✓ Result Validation & Sanity Checking                 ║")
message(STATUS "║    ✓ Baseline Management & Regression Detection            ║")
message(STATUS "║    ✓ Integrated Runner with Real Backends                  ║")
message(STATUS "╠══════════════════════════════════════════════════════════════╣")
message(STATUS "║  Executables:                                                ║")
message(STATUS "║    • benchmark_runner (Phase D.5 Refined)                 ║")
message(STATUS "║    • stress_test_suite (Batch 4 Focused)                  ║")
message(STATUS "║    • integrated_benchmark_runner (Real Backends)          ║")
if(RAWRXD_BUILD_PHASE_E)
    message(STATUS "║    • phase_e_benchmark (Statistical Validation)          ║")
endif()
message(STATUS "╠══════════════════════════════════════════════════════════════╣")
message(STATUS "║  Options:                                                  ║")
message(STATUS "║    Build Tests:        ${RAWRXD_BUILD_TESTS}                                      ║")
message(STATUS "║    Profiling:          ${RAWRXD_ENABLE_PROFILING}                                   ║")
message(STATUS "║    Phase E:           ${RAWRXD_BUILD_PHASE_E}                                   ║")
message(STATUS "║    SQLite3:           ${SQLite3_FOUND}                                   ║")
message(STATUS "╚══════════════════════════════════════════════════════════════╝")
message(STATUS "")
