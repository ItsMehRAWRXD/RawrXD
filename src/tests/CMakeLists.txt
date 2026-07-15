# RawrXD Integration Tests
# Phase 19: End-to-End Test Harness

set(TEST_SOURCES
    E2ETestFramework.cpp
    integration_e2e_test.cpp
)

set(TEST_HEADERS
    E2ETestFramework.h
)

# Create test executable
add_executable(rawrxd_e2e_tests ${TEST_SOURCES} ${TEST_HEADERS})

target_include_directories(rawrxd_e2e_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(rawrxd_e2e_tests PRIVATE
    rawrxd_lora
    jsoncpp_lib
    ${CMAKE_THREAD_LIBS_INIT}
)

# Enable testing
enable_testing()

# Add tests
add_test(NAME E2E_BasicTraining COMMAND rawrxd_e2e_tests basic_training_pipeline)
add_test(NAME E2E_Serialization COMMAND rawrxd_e2e_tests serialization_round_trip)
add_test(NAME E2E_Alignment COMMAND rawrxd_e2e_tests memory_alignment_verification)
add_test(NAME E2E_ChainCreation COMMAND rawrxd_e2e_tests beacon_chain_creation)
add_test(NAME E2E_FullPipeline COMMAND rawrxd_e2e_tests full_pipeline_integration)
add_test(NAME E2E_NaNProtection COMMAND rawrxd_e2e_tests nan_inf_protection)
add_test(NAME E2E_ChainTraversal COMMAND rawrxd_e2e_tests chain_traversal_verification)
add_test(NAME E2E_Performance COMMAND rawrxd_e2e_tests performance_budget)

# Add full test suite
add_test(NAME E2E_All COMMAND rawrxd_e2e_tests)

# Set test properties
set_tests_properties(E2E_All PROPERTIES
    TIMEOUT 120
    LABELS "e2e;integration"
)

# Group for IDE
set_target_properties(rawrxd_e2e_tests PROPERTIES 
    FOLDER "Tests"
)

# Install test executable (optional)
install(TARGETS rawrxd_e2e_tests
    RUNTIME DESTINATION bin/tests
)

# Install test data (if any)
# install(DIRECTORY data/ DESTINATION share/rawrxd/tests)
