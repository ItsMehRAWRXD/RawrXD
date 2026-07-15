# CMakeLists.txt for Layer 0: Scheduler
# Pure time/credit allocator - no execution semantics

cmake_minimum_required(VERSION 3.20)

project(RawrXD-Scheduler VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ═══════════════════════════════════════════════════════════════════════════════
# Scheduler Library
# ═══════════════════════════════════════════════════════════════════════════════

add_library(RawrXD-Scheduler STATIC
    scheduler.cpp
    scheduler.h
)

target_include_directories(RawrXD-Scheduler
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<INSTALL_INTERFACE:include>
)

# Scheduler has minimal dependencies
target_link_libraries(RawrXD-Scheduler
    PUBLIC
        # No external dependencies - pure C++20
)

# ═══════════════════════════════════════════════════════════════════════════════
# Compiler Options
# ═══════════════════════════════════════════════════════════════════════════════

if(MSVC)
    target_compile_options(RawrXD-Scheduler PRIVATE
        /W4           # High warning level
        /WX-          # Don't treat warnings as errors (for development)
        /EHsc         # Exception handling
        /MP           # Multi-processor compilation
    )
else()
    target_compile_options(RawrXD-Scheduler PRIVATE
        -Wall
        -Wextra
        -Wpedantic
    )
endif()

# ═══════════════════════════════════════════════════════════════════════════════
# Tests
# ═══════════════════════════════════════════════════════════════════════════════

if(BUILD_TESTING)
    enable_testing()
    
    add_executable(scheduler_test
        tests/scheduler_test.cpp
    )
    
    target_link_libraries(scheduler_test
        PRIVATE
            RawrXD-Scheduler
    )
    
    add_test(NAME SchedulerTest COMMAND scheduler_test)
endif()

# ═══════════════════════════════════════════════════════════════════════════════
# Installation
# ═══════════════════════════════════════════════════════════════════════════════

install(TARGETS RawrXD-Scheduler
    EXPORT RawrXD-Scheduler-targets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

install(FILES scheduler.h
    DESTINATION include/rawrxd/scheduler
)

# ═══════════════════════════════════════════════════════════════════════════════
# Export
# ═══════════════════════════════════════════════════════════════════════════════

install(EXPORT RawrXD-Scheduler-targets
    FILE RawrXD-Scheduler-targets.cmake
    NAMESPACE rawrxd::
    DESTINATION lib/cmake/RawrXD-Scheduler
)

# ═══════════════════════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════════════════════

message(STATUS "RawrXD-Scheduler configured:")
message(STATUS "  Version: ${PROJECT_VERSION}")
message(STATUS "  C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  Testing: ${BUILD_TESTING}")
