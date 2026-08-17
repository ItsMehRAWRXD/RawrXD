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
if(RAWRXD_BUILD_TESTS)
    add_executable(test_ceo_agent
        tests/test_ceo_agent.cpp
    )
    
    target_link_libraries(test_ceo_agent PRIVATE
        rawrxd_ceo
        GTest::gtest_main
    )
    
    add_test(NAME CEOAgentTests COMMAND test_ceo_agent)
endif()
