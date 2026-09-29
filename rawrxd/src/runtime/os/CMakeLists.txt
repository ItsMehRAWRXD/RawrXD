# ============================================================================
# CMakeLists.txt — OS Runtime Registry (universal capability kernel)
# ============================================================================
cmake_minimum_required(VERSION 3.20)

# Build the OS Runtime as a static library
add_library(RawrXD_OSRuntime STATIC)

target_include_directories(RawrXD_OSRuntime
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/generated
)

# Core kernel sources (hand-written)
target_sources(RawrXD_OSRuntime
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/RuntimeKernel.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/WindowsEmitter.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/RuntimeCapabilityRegistration.cpp
)

# Generated capability sources (from capabilities.yaml manifest)
# Run: py tools/generate_runtime_registry.py to regenerate
include(${CMAKE_CURRENT_SOURCE_DIR}/RuntimeCapabilityCMake.cmake)
target_sources(RawrXD_OSRuntime PRIVATE ${RAWRXD_OS_RUNTIME_GENERATED_SOURCES})

# C++20, no exceptions on the hot path
target_compile_features(RawrXD_OSRuntime PUBLIC cxx_std_20)

# Warnings
if(MSVC)
    target_compile_options(RawrXD_OSRuntime PRIVATE /W3 /EHsc)
else()
    target_compile_options(RawrXD_OSRuntime PRIVATE -Wall -Wextra)
endif()