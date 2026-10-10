# ============================================================================
# Self-contained build for the agentic resilience subsystems.
#
# Deliberately standalone: it does NOT include the project's root CMakeLists.
# The root build pulls in zlib, ggml, Vulkan detection, NASM, and Qt probes,
# any of which can fail for reasons unrelated to these subsystems. Keeping the
# certification target isolated means CI failure here means something is
# actually wrong with the resilience code itself.
#
# No external dependencies: C++20 standard library only.
# ============================================================================
cmake_minimum_required(VERSION 3.20)
project(agentic_resilience VERSION 1.0.0 LANGUAGES CXX)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(GNUInstallDirs)

# Sources under test.
set(RESILIENCE_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/../../src/agent/adaptive_retry.cpp
    ${CMAKE_CURRENT_LIST_DIR}/../../src/agent/delegated_agents.cpp
    ${CMAKE_CURRENT_LIST_DIR}/../../src/agentic/conflict_resolution.cpp
    ${CMAKE_CURRENT_LIST_DIR}/agentic_resilience_test.cpp
)

# ---------------------------------------------------------------------------
# Production integration test.
#
# Tests/agentic_resilience proves the three subsystems work. This proves the
# real HexMag swarm actually USES them (via hexmag_resilience_bridge.hpp)
# instead of its own parallel implementations, which silently discarded
# concurrent agent edits.
# ---------------------------------------------------------------------------
set(INTEGRATION_SOURCES
    ${RESILIENCE_SOURCES}
    ${CMAKE_CURRENT_LIST_DIR}/hexmag_integration_test.cpp
)
list(REMOVE_ITEM INTEGRATION_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/agentic_resilience_test.cpp)

# The test asserts on live behaviour only; warnings indicate real problems.
if(MSVC)
    add_compile_options(/W4 /permissive- /EHsc /Zc:preprocessor)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

add_executable(agentic-resilience-tests ${RESILIENCE_SOURCES})

target_include_directories(agentic-resilience-tests PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/../../src
    ${CMAKE_CURRENT_LIST_DIR}/../../src/agent
    ${CMAKE_CURRENT_LIST_DIR}/../../src/agentic
)

# std::thread / std::condition_variable require linking a threading library.
find_package(Threads REQUIRED)
target_link_libraries(agentic-resilience-tests PRIVATE Threads::Threads)

# Windows: no extra libs needed. POSIX: also requires -pthread at link time.
if(NOT WIN32)
    target_compile_options(agentic-resilience-tests PRIVATE -pthread)
endif()

enable_testing()
add_test(NAME agentic-resilience COMMAND agentic-resilience-tests)
set_tests_properties(agentic-resilience PROPERTIES
    TIMEOUT 300
    PASS_REGULAR_EXPRESSION "ALL TESTS PASSED"
    FAIL_REGULAR_EXPRESSION "SOME TESTS FAILED"
)

# Production-integration test: the swarm must delegate to the certified engines.
add_executable(hexmag-integration-tests ${INTEGRATION_SOURCES})
target_include_directories(hexmag-integration-tests PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/../../src
    ${CMAKE_CURRENT_LIST_DIR}/../../src/agent
    ${CMAKE_CURRENT_LIST_DIR}/../../src/agentic
)
if(NOT WIN32)
    target_compile_options(hexmag-integration-tests PRIVATE -pthread)
endif()

add_test(NAME hexmag-integration COMMAND hexmag-integration-tests)
set_tests_properties(hexmag-integration PROPERTIES
    TIMEOUT 300
    PASS_REGULAR_EXPRESSION "ALL TESTS PASSED"
    FAIL_REGULAR_EXPRESSION "SOME TESTS FAILED"
)
