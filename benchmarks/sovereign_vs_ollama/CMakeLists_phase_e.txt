# Phase E: Statistical Validation - Standalone CMakeLists.txt
# Copyright (c) 2026 RawrXD Team
# This is a minimal build file for Phase E only

cmake_minimum_required(VERSION 3.16)
project(PhaseEStatisticalValidation VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find only required packages
find_package(Threads REQUIRED)

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Phase E: Statistical Validation
set(STATISTICAL_SOURCES
    src/statistical_comparison.cpp
)

set(PHASE_E_SOURCES
    src/phase_e_benchmark.cpp
)

# Statistical comparison library
add_library(statistical_comparison STATIC ${STATISTICAL_SOURCES})

# Phase E benchmark executable
add_executable(phase_e_benchmark ${PHASE_E_SOURCES})
target_link_libraries(phase_e_benchmark statistical_comparison Threads::Threads)

# Compiler options
if(MSVC)
    target_compile_options(phase_e_benchmark PRIVATE /W4 /O2)
else()
    target_compile_options(phase_e_benchmark PRIVATE -Wall -Wextra -O3 -march=native)
endif()

# Install
install(TARGETS phase_e_benchmark
    RUNTIME DESTINATION bin
)

install(FILES 
    include/benchmark_common.hpp
    include/statistical_comparison.hpp
    DESTINATION include
)
