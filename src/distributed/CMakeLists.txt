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

# Compiler options
if(MSVC)
    target_compile_options(sovereign_distributed PRIVATE /W4 /O2)
else()
    target_compile_options(sovereign_distributed PRIVATE -Wall -Wextra -O3)
endif()

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
