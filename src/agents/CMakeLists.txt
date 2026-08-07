# ============================================================================
# CEO Agent - Autonomous Engineering Controller
# ============================================================================

set(AGENT_SOURCES
    CEOAgent.cpp
    AgentMemory.cpp
    Planner.cpp
    ToolRegistry.cpp
    ceo_cli.cpp
)

set(AGENT_HEADERS
    CEOAgent.hpp
    AgentMemory.hpp
    Planner.hpp
    ToolRegistry.hpp
)

# CEO Agent Library
add_library(RawrXD_CEOAgent STATIC ${AGENT_SOURCES} ${AGENT_HEADERS})

target_include_directories(RawrXD_CEOAgent PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/src/deep2
    ${CMAKE_SOURCE_DIR}/src/runtime
    ${CMAKE_SOURCE_DIR}/src/tools
    ${CMAKE_SOURCE_DIR}/src/telemetry
)

target_link_libraries(RawrXD_CEOAgent PUBLIC
    nlohmann_json::nlohmann_json
)

# CEO Agent CLI Executable
add_executable(RawrXD-CEO ceo_cli.cpp)

target_link_libraries(RawrXD-CEO PRIVATE
    RawrXD_CEOAgent
)

# Install
install(TARGETS RawrXD-CEO
    RUNTIME DESTINATION bin
)

# Tests
if(RAWRXD_BUILD_TESTS)
    add_subdirectory(tests)
endif()
