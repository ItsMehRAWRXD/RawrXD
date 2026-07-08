# CMakeLists.txt for Layer 1: Router
# Pure placement logic - no scheduling or execution internals

cmake_minimum_required(VERSION 3.20)

project(RawrXD-Router VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ═══════════════════════════════════════════════════════════════════════════════
# Router Library
# ═══════════════════════════════════════════════════════════════════════════════

add_library(RawrXD-Router STATIC
    router.cpp
    router.h
)

target_include_directories(RawrXD-Router
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<INSTALL_INTERFACE:include>
)

# Router depends on Scheduler (Layer 0)
target_link_libraries(RawrXD-Router
    PUBLIC
        RawrXD-Scheduler
)

# ═══════════════════════════════════════════════════════════════════════════════
# Compiler Options
# ═══════════════════════════════════════════════════════════════════════════════

if(MSVC)
    target_compile_options(RawrXD-Router PRIVATE
        /W4
        /WX-
        /EHsc
        /MP
    )
else()
    target_compile_options(RawrXD-Router PRIVATE
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
    
    add_executable(router_test
        tests/router_test.cpp
    )
    
    target_link_libraries(router_test
        PRIVATE
            RawrXD-Router
    )
    
    add_test(NAME RouterTest COMMAND router_test)
endif()

# ═══════════════════════════════════════════════════════════════════════════════
# Installation
# ═══════════════════════════════════════════════════════════════════════════════

install(TARGETS RawrXD-Router
    EXPORT RawrXD-Router-targets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

install(FILES router.h
    DESTINATION include/rawrxd/router
)

install(EXPORT RawrXD-Router-targets
    FILE RawrXD-Router-targets.cmake
    NAMESPACE rawrxd::
    DESTINATION lib/cmake/RawrXD-Router
)

message(STATUS "RawrXD-Router configured:")
message(STATUS "  Version: ${PROJECT_VERSION}")
message(STATUS "  C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Dependencies: RawrXD-Scheduler")
