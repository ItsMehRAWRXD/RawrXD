# Sovereign Distributed Runtime - Phase D.3
# Copyright (c) 2026 RawrXD Team

cmake_minimum_required(VERSION 3.16)
project(SovereignDistributedRuntime VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find packages
find_package(Threads REQUIRED)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
)

# Source files
set(DISTRIBUTED_SOURCES
    RawrXD_RPC.cpp
    SovereignNodeDiscovery.cpp
    SovereignConsensusEngine.cpp
    SovereignDistributedRollback.cpp
    SovereignStateReplication.cpp
    SovereignDistributedRuntime.cpp
)

# Create library
add_library(sovereign_distributed STATIC ${DISTRIBUTED_SOURCES})

target_link_libraries(sovereign_distributed
    Threads::Threads
)

# Compiler options - configuration-specific to avoid /RTC1 + /O2 conflict
if(MSVC)
    target_compile_options(sovereign_distributed PRIVATE /W4)
    # Only add /O2 for non-Debug configurations (CMake adds /RTC1 for Debug)
    target_compile_options(sovereign_distributed PRIVATE $<$<NOT:$<CONFIG:Debug>>:/O2>)
else()
    target_compile_options(sovereign_distributed PRIVATE -Wall -Wextra)
    target_compile_options(sovereign_distributed PRIVATE $<$<NOT:$<CONFIG:Debug>>:-O3>)
endif()

# RPC unit tests
add_executable(test_rpc
    test_rpc.cpp
)

target_link_libraries(test_rpc
    sovereign_distributed
    Threads::Threads
)

# Enable CTest
enable_testing()
add_test(NAME RPCUnitTests COMMAND test_rpc)

# Testing executable
add_executable(distributed_tests
    tests/distributed_test_runner.cpp
)

target_link_libraries(distributed_tests
    sovereign_distributed
    Threads::Threads
)

# Install
install(TARGETS sovereign_distributed
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)

install(FILES
    SovereignNodeDiscovery.hpp
    SovereignConsensusEngine.hpp
    SovereignDistributedRollback.hpp
    SovereignStateReplication.hpp
    SovereignDistributedRuntime.hpp
    DESTINATION include/sovereign/distributed
)
