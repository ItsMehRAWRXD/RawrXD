# RawrXD N-EVM Validation Framework - CMake Build
# Cross-platform build for Windows, Linux, and macOS

cmake_minimum_required(VERSION 3.16)
project(RawrXD_NEVM_Validation VERSION 1.0.0 LANGUAGES CXX)

# C++17 required
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Options
option(BUILD_TESTS "Build unit tests" OFF)
option(BUILD_DOCS "Build documentation" OFF)
option(ENABLE_PARALLEL "Enable parallel gate execution" ON)
option(ENABLE_TREND_TRACKING "Enable historical trend tracking" ON)

# Find packages
find_package(Threads REQUIRED)
find_package(JsonCpp REQUIRED)

# Platform detection
if(WIN32)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    add_definitions(-DNOMINMAX)
elseif(APPLE)
    add_definitions(-DAPPLE)
else()
    add_definitions(-DLINUX)
endif()

# Compiler flags
if(MSVC)
    add_compile_options(/W4 /O2 /EHsc)
    # Enable AVX2/AVX512 if available
    include(CheckCXXCompilerFlag)
    check_cxx_compiler_flag(/arch:AVX2 COMPILER_SUPPORTS_AVX2)
    check_cxx_compiler_flag(/arch:AVX512 COMPILER_SUPPORTS_AVX512)
    if(COMPILER_SUPPORTS_AVX512)
        add_compile_options(/arch:AVX512)
    elseif(COMPILER_SUPPORTS_AVX2)
        add_compile_options(/arch:AVX2)
    endif()
else()
    add_compile_options(-Wall -Wextra -O3)
    # Enable AVX2/AVX512 if available
    include(CheckCXXCompilerFlag)
    check_cxx_compiler_flag(-mavx2 COMPILER_SUPPORTS_AVX2)
    check_cxx_compiler_flag(-mavx512f COMPILER_SUPPORTS_AVX512)
    if(COMPILER_SUPPORTS_AVX512)
        add_compile_options(-mavx512f -mavx512vl)
    elseif(COMPILER_SUPPORTS_AVX2)
        add_compile_options(-mavx2)
    endif()
endif()

# Source files
set(VALIDATION_SOURCES
    src/nevm_math_mode.cpp
    src/nevm_determinism_safeguards.cpp
    src/nevm_kv_integrity.cpp
    src/nevm_execution_plan_version.cpp
    src/nevm_extended_stress_test.cpp
    src/nevm_validation_schema.cpp
    src/nevm_performance_thresholds.cpp
    src/nevm_failure_artifacts.cpp
    src/nevm_kernel_provenance.cpp
    src/nevm_golden_output.cpp
    src/nevm_parallel_executor.cpp
    src/nevm_validate.cpp
)

set(GENERATOR_SOURCES
    src/nevm_math_mode.cpp
    src/nevm_golden_output.cpp
    src/nevm_generate_golden.cpp
)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/src)
include_directories(${JsonCpp_INCLUDE_DIRS})

# Main validator executable
add_executable(nevm_validate ${VALIDATION_SOURCES})
target_link_libraries(nevm_validate
    Threads::Threads
    JsonCpp::JsonCpp
)

# Golden output generator executable
add_executable(nevm_generate_golden ${GENERATOR_SOURCES})
target_link_libraries(nevm_generate_golden
    Threads::Threads
    JsonCpp::JsonCpp
)

# Set output directory
set_target_properties(nevm_validate nevm_generate_golden
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# Install targets
install(TARGETS nevm_validate nevm_generate_golden
    RUNTIME DESTINATION bin
)

install(FILES
    src/nevm_math_mode.hpp
    src/nevm_determinism_safeguards.hpp
    src/nevm_kv_integrity.hpp
    src/nevm_execution_plan_version.hpp
    src/nevm_validation_schema.hpp
    src/nevm_performance_thresholds.hpp
    src/nevm_failure_artifacts.hpp
    src/nevm_kernel_provenance.hpp
    src/nevm_golden_output.hpp
    src/nevm_parallel_executor.hpp
    src/nevm_trend_tracker.hpp
    DESTINATION include/nevm
)

# Tests
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Print configuration summary
message(STATUS "")
message(STATUS "RawrXD N-EVM Validation Framework Configuration")
message(STATUS "================================================")
message(STATUS "Version: ${PROJECT_VERSION}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Parallel execution: ${ENABLE_PARALLEL}")
message(STATUS "Trend tracking: ${ENABLE_TREND_TRACKING}")
message(STATUS "Install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "")
