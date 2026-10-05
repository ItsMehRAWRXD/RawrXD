# ============================================================================
# CEO Agent Module — CMake Configuration
# The autonomous software engineering layer for RawrXD
# ============================================================================

cmake_minimum_required(VERSION 3.20)

# CEO Agent Library
add_library(rawrxd_ceo STATIC
    CEOAgent.cpp
    CEOAgent.hpp
    AutonomousBuildLoop.cpp
    AutonomousBuildLoop.hpp
    ContextEngine.cpp
    ContextEngine.hpp
    ModelRouter.cpp
    ModelRouter.hpp
    ProjectState.cpp
    ProjectState.hpp
)

target_include_directories(rawrxd_ceo PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include
)

target_link_libraries(rawrxd_ceo PUBLIC
)

# CEO Agent CLI Executable
# Minimal: only CEO library + main + lightweight subsystem API stubs.
add_executable(rawrxd_ceo_cli
    main.cpp
    # Lightweight subsystem API (CEOAgent uses this for mode dispatch)
    ${CMAKE_SOURCE_DIR}/src/core/rawrxd_subsystem_api.cpp
    # Definitions for the 19 *Mode / AD_ProcessGGUF entry points that
    # rawrxd_subsystem_api.cpp declares and dispatches to. Without these the
    # link failed with 19 x LNK2019 unresolved external symbol. They were
    # dropped from the build by commit 7a73ec687 ("GROUP B: remove 16 *Mode
    # stubs from subsystem_api") to clear LNK4006 duplicates, which removed the
    # symbols rather than the duplication.
    #
    # These three files define the mode entry points once and do not overlap
    # with each other. src/core/subsystem_mode_impl.cpp is deliberately NOT
    # added here: it defines the same symbols again plus ~100 asm_* stubs, and
    # it is the file that produced the original duplicate-symbol collisions.
    ${CMAKE_SOURCE_DIR}/src/core/rawrxd_subsys_modes_a.cpp
    ${CMAKE_SOURCE_DIR}/src/core/rawrxd_subsys_modes_b.cpp
    ${CMAKE_SOURCE_DIR}/src/core/rawrxd_subsys_modes_c.cpp
    # Stubs for subsystems not needed by CEO CLI
    ${CMAKE_SOURCE_DIR}/src/ceo/disk_recovery_stubs.cpp
    ${CMAKE_SOURCE_DIR}/src/ceo/ceo_link_stubs.cpp
)

target_link_libraries(rawrxd_ceo_cli PRIVATE
    rawrxd_ceo
)

set_target_properties(rawrxd_ceo_cli PROPERTIES
    OUTPUT_NAME "rawrxd-ceo"
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# Installation
install(TARGETS rawrxd_ceo rawrxd_ceo_cli
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

# Tests (if testing is enabled)
#
# RAWRXD_CEO_PHANTOM_TEST_SOURCE_RETIRED_001
#
# This block declared a test target whose only source has never existed:
#
#     add_executable(test_ceo_agent tests/test_ceo_agent.cpp)
#     add_test(NAME CEOAgentTests COMMAND test_ceo_agent)
#
# `tests/test_ceo_agent.cpp` does not exist anywhere in the tree -- verified by a
# repo-wide search, not by a path guess. The consequence was that ANY configure
# with -DRAWRXD_BUILD_TESTS=ON aborted:
#
#     CMake Error at src/ceo/CMakeLists.txt:74 (add_executable):
#       Cannot find source file: tests/test_ceo_agent.cpp
#
# which made the entire test suite unreachable, not just this one target. A
# declared-but-absent test is worse than no test: `CEOAgentTests` appears in the
# ctest list of every build system that configures successfully, so it reads as
# coverage that does not exist.
#
# RETIRED rather than written. Writing the file would mean inventing assertions
# for an API whose intended contract I have no specification for, which
# manufactures a green test rather than a real one -- the exact substitution the
# empty-source guard above exists to prevent. The honest state is: this component
# has NO automated test, and the graph now says so.
#
# If the coverage is wanted, implement the test first and re-add these three
# lines. Do not re-add them without the source.
if(RAWRXD_BUILD_TESTS AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_ceo_agent.cpp")
    add_executable(test_ceo_agent
        tests/test_ceo_agent.cpp
    )

    target_link_libraries(test_ceo_agent PRIVATE
        rawrxd_ceo
        GTest::gtest_main
    )

    add_test(NAME CEOAgentTests COMMAND test_ceo_agent)
elseif(RAWRXD_BUILD_TESTS)
    # Reported, not silent: a retired test is a coverage gap and should be
    # visible in the configure log rather than quietly absent.
    message(STATUS
        "[RAWRXD_CEO_PHANTOM_TEST_SOURCE_RETIRED_001] test_ceo_agent NOT declared: "
        "tests/test_ceo_agent.cpp does not exist. CEOAgentTests is therefore NOT "
        "in the ctest list. rawrxd_ceo has no automated coverage.")
endif()
