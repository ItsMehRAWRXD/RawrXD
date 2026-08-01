# RawrXD Validation Harness - CMake Build Configuration
# Supports Visual Studio 2022, MinGW, and Clang

cmake_minimum_required(VERSION 3.20)
project(RawrXDValidation VERSION 1.0.0 LANGUAGES CXX)

# C++ Standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Find dependencies
find_package(Threads REQUIRED)

# nlohmann/json - header only
set(JSON_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../3rdparty/json/include")
if(NOT EXISTS "${JSON_INCLUDE_DIR}/nlohmann/json.hpp")
    message(FATAL_ERROR "nlohmann/json not found at ${JSON_INCLUDE_DIR}")
endif()

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${JSON_INCLUDE_DIR}
)

# Windows-specific libraries
if(WIN32)
    set(PLATFORM_LIBS ws2_32 pdh wbemuuid comsuppw)
else()
    set(PLATFORM_LIBS pthread)
endif()

# Compiler flags
if(MSVC)
    add_compile_options(/W4 /WX- /permissive- /Zc:__cplusplus)
    add_compile_options(/O2)  # Optimize for speed
    add_compile_options(/MP)  # Multi-processor compilation
elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic)
    add_compile_options(-O3)  # Optimize for speed
endif()

# ============================================================================
# Validation Harness Executable
# ============================================================================
add_executable(ValidationHarness
    ValidationHarness.cpp
)

target_link_libraries(ValidationHarness
    PRIVATE
    Threads::Threads
    ${PLATFORM_LIBS}
)

# ============================================================================
# Hardware Validator Executable
# ============================================================================
add_executable(HardwareValidator
    HardwareValidator.cpp
)

target_link_libraries(HardwareValidator
    PRIVATE
    Threads::Threads
    ${PLATFORM_LIBS}
)

# ============================================================================
# Real Inference Benchmark Executable
# ============================================================================
add_executable(RealInferenceBenchmark
    RealInferenceBenchmark.cpp
)

target_link_libraries(RealInferenceBenchmark
    PRIVATE
    Threads::Threads
    ${PLATFORM_LIBS}
)

# ============================================================================
# Telemetry Collector Executable
# ============================================================================
add_executable(TelemetryCollector
    TelemetryCollector.cpp
)

target_link_libraries(TelemetryCollector
    PRIVATE
    Threads::Threads
    ${PLATFORM_LIBS}
)

# ============================================================================
# Installation
# ============================================================================
install(TARGETS
    ValidationHarness
    HardwareValidator
    RealInferenceBenchmark
    TelemetryCollector
    RUNTIME DESTINATION bin
)

# ============================================================================
# Testing
# ============================================================================
enable_testing()

# Add simple smoke tests
add_test(NAME HardwareValidator_Smoke
    COMMAND HardwareValidator
    WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
)

add_test(NAME ValidationHarness_Help
    COMMAND ValidationHarness --help
    WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
)

# ============================================================================
# Packaging
# ============================================================================
set(CPACK_PACKAGE_NAME "RawrXDValidation")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION "RawrXD Production Validation Framework")
set(CPACK_PACKAGE_VENDOR "RawrXD")
set(CPACK_GENERATOR "ZIP")

include(CPack)

# ============================================================================
# Summary
# ============================================================================
message(STATUS "")
message(STATUS "RawrXD Validation Harness Configuration")
message(STATUS "======================================")
message(STATUS "Version: ${PROJECT_VERSION}")
message(STATUS "C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Output Directory: ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")
message(STATUS "JSON Include: ${JSON_INCLUDE_DIR}")
message(STATUS "")
message(STATUS "Targets:")
message(STATUS "  - ValidationHarness")
message(STATUS "  - HardwareValidator")
message(STATUS "  - RealInferenceBenchmark")
message(STATUS "  - TelemetryCollector")
message(STATUS "")
