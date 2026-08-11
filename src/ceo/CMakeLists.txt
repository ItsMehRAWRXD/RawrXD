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
add_executable(rawrxd_ceo_cli
    main.cpp
    ${CMAKE_SOURCE_DIR}/src/agentic/AgentOrchestrator.cpp
    ${CMAKE_SOURCE_DIR}/src/agentic/AgentToolHandlers.cpp
    ${CMAKE_SOURCE_DIR}/src/agentic/RawrXD_AgentLoop.cpp
    ${CMAKE_SOURCE_DIR}/src/agentic/RawrXD_ToolRegistry.cpp
    ${CMAKE_SOURCE_DIR}/src/agentic/ToolRegistry.cpp
    ${CMAKE_SOURCE_DIR}/src/agentic/AdvancedAgentCoordinator.cpp
    ${CMAKE_SOURCE_DIR}/src/agent/AgentOllamaClient.cpp
    ${CMAKE_SOURCE_DIR}/src/agent/FIMPromptBuilder.cpp
    ${CMAKE_SOURCE_DIR}/src/core/rawrxd_subsystem_api.cpp
    ${CMAKE_SOURCE_DIR}/src/agentic_observability.cpp
    ${CMAKE_SOURCE_DIR}/src/core/unified_hotpatch_manager.cpp
    ${CMAKE_SOURCE_DIR}/src/agentic/DiskRecoveryAgent.cpp
    ${CMAKE_SOURCE_DIR}/src/win32app/agentic_bridge_headless.cpp
        ${CMAKE_SOURCE_DIR}/src/ceo/disk_recovery_stubs.cpp
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
