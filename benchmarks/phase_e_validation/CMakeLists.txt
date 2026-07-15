# Phase E Validation Benchmark Suite CMakeLists.txt
# Copyright (c) 2026 RawrXD Team

cmake_minimum_required(VERSION 3.16)
project(PhaseEValidation VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/../../src
    ${CMAKE_SOURCE_DIR}/../../src/autonomy
    ${CMAKE_SOURCE_DIR}/../../src/core
    ${CMAKE_SOURCE_DIR}/../sovereign_vs_ollama
    ${CMAKE_SOURCE_DIR}/../sovereign_vs_ollama/include
)

# Source files
set(PHASEE_SOURCES
    phase_e_runner.cpp
)

# Create executable
add_executable(phase_e_runner ${PHASEE_SOURCES})

# Link libraries
target_link_libraries(phase_e_runner
    Threads::Threads
)

# Platform-specific settings
if(WIN32)
    target_compile_definitions(phase_e_runner PRIVATE
        _WIN32_WINNT=0x0A00
        WIN32_LEAN_AND_MEAN
        NOMINMAX
    )
endif()

# Compiler warnings
if(MSVC)
    target_compile_options(phase_e_runner PRIVATE /W4 /WX-)
else()
    target_compile_options(phase_e_runner PRIVATE -Wall -Wextra -Wno-unused-parameter)
endif()

# Output directory
set_target_properties(phase_e_runner PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)
