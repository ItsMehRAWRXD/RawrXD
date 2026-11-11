#============================================================================
# CMakeLists.txt
# RawrXD N-EVM - Test Suite CMake Configuration
#============================================================================

cmake_minimum_required(VERSION 3.14)
project(RawrXD_NEVM_Tests VERSION 1.0.0 LANGUAGES CXX)

# C++ Standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build options
option(BUILD_TESTS "Build test suite" ON)
option(ENABLE_COVERAGE "Enable code coverage" OFF)
option(ENABLE_SANITIZERS "Enable sanitizers" OFF)

# Compiler warnings
if(MSVC)
    add_compile_options(/W4 /WX-)
    add_compile_options(/MP)  # Multi-processor compilation
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
    add_compile_options(-Wno-unused-parameter)
endif()

# Sanitizers
if(ENABLE_SANITIZERS AND NOT MSVC)
    add_compile_options(-fsanitize=address,undefined)
    add_link_options(-fsanitize=address,undefined)
endif()

# Coverage
if(ENABLE_COVERAGE AND NOT MSVC)
    add_compile_options(--coverage)
    add_link_options(--coverage)
endif()

# Directories
set(NEVM_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/..)
set(THIRD_PARTY_ROOT ${NEVM_ROOT}/../../third_party)

# Include directories
include_directories(
    ${NEVM_ROOT}
    ${THIRD_PARTY_ROOT}/jsoncpp/include
)

# Source files
set(TEST_SOURCES
    test_main.cpp
    test_math_mode.cpp
    test_determinism.cpp
    test_kv_integrity.cpp
    test_execution_plan.cpp
    test_performance_thresholds.cpp
    test_golden_output.cpp
    test_validation_schema.cpp
    test_integration.cpp
)

# Create test executable
add_executable(nevm_tests ${TEST_SOURCES})

# Link libraries
if(MSVC)
    target_link_libraries(nevm_tests kernel32 user32)
else()
    target_link_libraries(nevm_tests pthread)
endif()

# Set output directory
set_target_properties(nevm_tests PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# Enable testing
enable_testing()

# Add tests
add_test(NAME AllTests COMMAND nevm_tests)

# Individual test suites
add_test(NAME MathModeTests COMMAND nevm_tests --filter "MathMode_*")
add_test(NAME DeterminismTests COMMAND nevm_tests --filter "Determinism_*")
add_test(NAME KVIntegrityTests COMMAND nevm_tests --filter "KVIntegrity_*")
add_test(NAME ExecutionPlanTests COMMAND nevm_tests --filter "ExecutionPlan_*")
add_test(NAME PerformanceTests COMMAND nevm_tests --filter "Performance*")
add_test(NAME GoldenOutputTests COMMAND nevm_tests --filter "GoldenOutput*")
add_test(NAME ValidationSchemaTests COMMAND nevm_tests --filter "ValidationSchema*")
add_test(NAME IntegrationTests COMMAND nevm_tests --filter "Integration_*")

# Install
install(TARGETS nevm_tests
    RUNTIME DESTINATION bin
)

# Print configuration
message(STATUS "")
message(STATUS "RawrXD N-EVM Test Suite Configuration")
message(STATUS "====================================")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Coverage: ${ENABLE_COVERAGE}")
message(STATUS "Sanitizers: ${ENABLE_SANITIZERS}")
message(STATUS "Tests: ${TEST_SOURCES}")
message(STATUS "")
