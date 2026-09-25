cmake_minimum_required(VERSION 3.20)
project(RawrXDNextMissingBatches002 LANGUAGES CXX)

add_library(rawrxd_next_missing_batches_002 STATIC
    src/deep2/special_graph/FleetSpecialGraph.cpp
    src/deep2/special_graph/FleetSpecialGraphExecutor.cpp
    src/agentic/DualGpuIndependentAgentScheduler.cpp
    src/core/HexMagResidencyAuthority.cpp
    src/screenpilot/ScreenPilotToolAuthorityBridge.cpp
    src/agentic/MultiAgentMergeAuthority.cpp
)
target_compile_features(rawrxd_next_missing_batches_002 PUBLIC cxx_std_20)
target_include_directories(rawrxd_next_missing_batches_002 PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures
)

function(add_rawrxd_selftest name source)
    add_executable(${name} ${source})
    target_compile_features(${name} PRIVATE cxx_std_20)
    target_include_directories(${name} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures
    )
    target_link_libraries(${name} PRIVATE rawrxd_next_missing_batches_002)
endfunction()

add_rawrxd_selftest(rawrxd_special_graph_fleet_selftest tests/FleetSpecialGraphSelfTest.cpp)
add_rawrxd_selftest(rawrxd_special_graph_executor_selftest tests/FleetSpecialGraphExecutorSelfTest.cpp)
add_rawrxd_selftest(rawrxd_dual_gpu_agent_selftest tests/DualGpuIndependentAgentSchedulerSelfTest.cpp)
add_rawrxd_selftest(rawrxd_hexmag_residency_selftest tests/HexMagResidencyAuthoritySelfTest.cpp)
add_rawrxd_selftest(rawrxd_screenpilot_authority_selftest tests/ScreenPilotToolAuthorityBridgeSelfTest.cpp)
add_rawrxd_selftest(rawrxd_multi_agent_merge_selftest tests/MultiAgentMergeAuthoritySelfTest.cpp)

enable_testing()
add_test(NAME special_graph_fleet COMMAND rawrxd_special_graph_fleet_selftest)
add_test(NAME special_graph_executor COMMAND rawrxd_special_graph_executor_selftest)
add_test(NAME dual_gpu_agent COMMAND rawrxd_dual_gpu_agent_selftest)
add_test(NAME hexmag_residency COMMAND rawrxd_hexmag_residency_selftest)
add_test(NAME screenpilot_authority COMMAND rawrxd_screenpilot_authority_selftest)
add_test(NAME multi_agent_merge COMMAND rawrxd_multi_agent_merge_selftest)
