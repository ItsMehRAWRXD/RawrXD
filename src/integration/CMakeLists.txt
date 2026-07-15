# CMakeLists.txt for Integration Layer
# Wires Scheduler → Router → Executor → Policy

cmake_minimum_required(VERSION 3.20)

project(RawrXD-Runtime VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ═══════════════════════════════════════════════════════════════════════════════
# Integration Library
# ═══════════════════════════════════════════════════════════════════════════════

add_library(RawrXD-Runtime STATIC
    runtime.cpp
    runtime.h
)

target_include_directories(RawrXD-Runtime
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/../core/scheduler
        ${CMAKE_CURRENT_SOURCE_DIR}/../core/router
        ${CMAKE_CURRENT_SOURCE_DIR}/../core/executor
        ${CMAKE_CURRENT_SOURCE_DIR}/../core/policy
)

# Dependencies: All core layers
target_link_libraries(RawrXD-Runtime
    PUBLIC
        RawrXD-Scheduler
        RawrXD-Router
        RawrXD-Executor
        RawrXD-Policy
)

# ═══════════════════════════════════════════════════════════════════════════════
# Compiler Options
# ═══════════════════════════════════════════════════════════════════════════════

if(MSVC)
    target_compile_options(RawrXD-Runtime PRIVATE
        /W4
        /WX-
        /EHsc
        /MP
    )
else()
    target_compile_options(RawrXD-Runtime PRIVATE
        -Wall
        -Wextra
        -Wpedantic
    )
endif()

# ═══════════════════════════════════════════════════════════════════════════════
# Runtime Executable
# ═══════════════════════════════════════════════════════════════════════════════

add_executable(RawrXD-Runtime-Test
    tests/runtime_test.cpp
)

target_link_libraries(RawrXD-Runtime-Test
    PRIVATE
        RawrXD-Runtime
)

# ═══════════════════════════════════════════════════════════════════════════════
# Installation
# ═══════════════════════════════════════════════════════════════════════════════

install(TARGETS RawrXD-Runtime RawrXD-Runtime-Test
    EXPORT RawrXD-Runtime-targets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

install(FILES runtime.h
    DESTINATION include/rawrxd/runtime
)

message(STATUS "RawrXD-Runtime configured:")
message(STATUS "  Version: ${PROJECT_VERSION}")
message(STATUS "  C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Dependencies: Scheduler, Router, Executor, Policy")
