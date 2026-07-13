# CMakeLists.txt
# Batch 8: Test Suite Configuration
#
# Builds and configures all unit tests for the benchmark framework

cmake_minimum_required(VERSION 3.20)

# Enable testing
enable_testing()

# Find Google Test
find_package(GTest QUIET)

if(NOT GTest_FOUND)
    # Fetch Google Test if not found
    include(FetchContent)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG v1.14.0
    )
    FetchContent_MakeAvailable(googletest)
endif()

# Test executable
set(TEST_SOURCES
    test_statistical_engine.cpp
    test_backend_adapters.cpp
    test_benchmark_workflow.cpp
    test_regression_detection.cpp
)

add_executable(benchmark_tests ${TEST_SOURCES})

# Link against Google Test
target_link_libraries(benchmark_tests
    GTest::gtest
    GTest::gtest_main
)

# Include directories
target_include_directories(benchmark_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

# Set C++ standard
set_target_properties(benchmark_tests PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

# Compiler warnings for tests
if(MSVC)
    target_compile_options(benchmark_tests PRIVATE /W4 /WX)
else()
    target_compile_options(benchmark_tests PRIVATE -Wall -Wextra -Wpedantic)
endif()

# Add tests to CTest
add_test(NAME StatisticalEngine COMMAND benchmark_tests --gtest_filter="StatisticalEngineTest.*")
add_test(NAME BackendAdapters COMMAND benchmark_tests --gtest_filter="BackendAdapterTest.*")
add_test(NAME BenchmarkWorkflow COMMAND benchmark_tests --gtest_filter="BenchmarkWorkflowTest.*")
add_test(NAME RegressionDetection COMMAND benchmark_tests --gtest_filter="RegressionDetectionTest.*")

# Test labels for categorization
set_tests_properties(
    StatisticalEngine
    PROPERTIES LABELS "unit;statistics"
)

set_tests_properties(
    BackendAdapters
    PROPERTIES LABELS "unit;adapters"
)

set_tests_properties(
    BenchmarkWorkflow
    PROPERTIES LABELS "unit;workflow"
)

set_tests_properties(
    RegressionDetection
    PROPERTIES LABELS "unit;regression"
)

# Custom test targets
add_custom_target(test-statistics
    COMMAND ${CMAKE_CTEST_COMMAND} -R StatisticalEngine --output-on-failure
    DEPENDS benchmark_tests
    COMMENT "Running statistical engine tests"
)

add_custom_target(test-adapters
    COMMAND ${CMAKE_CTEST_COMMAND} -R BackendAdapters --output-on-failure
    DEPENDS benchmark_tests
    COMMENT "Running backend adapter tests"
)

add_custom_target(test-workflow
    COMMAND ${CMAKE_CTEST_COMMAND} -R BenchmarkWorkflow --output-on-failure
    DEPENDS benchmark_tests
    COMMENT "Running benchmark workflow tests"
)

add_custom_target(test-regression
    COMMAND ${CMAKE_CTEST_COMMAND} -R RegressionDetection --output-on-failure
    DEPENDS benchmark_tests
    COMMENT "Running regression detection tests"
)

# Coverage configuration (optional)
if(ENABLE_COVERAGE)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(benchmark_tests PRIVATE --coverage -O0)
        target_link_libraries(benchmark_tests --coverage)
        
        add_custom_target(coverage
            COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
            COMMAND gcovr -r ${CMAKE_SOURCE_DIR} --html --html-details -o coverage.html
            DEPENDS benchmark_tests
            COMMENT "Generating coverage report"
        )
    endif()
endif()

# Valgrind configuration (optional)
if(ENABLE_VALGRIND)
    find_program(VALGRIND_EXECUTABLE valgrind)
    if(VALGRIND_EXECUTABLE)
        add_custom_target(test-valgrind
            COMMAND ${VALGRIND_EXECUTABLE} --leak-check=full --error-exitcode=1 ./benchmark_tests
            DEPENDS benchmark_tests
            COMMENT "Running tests with Valgrind"
        )
    endif()
endif()

# Sanitizer configuration (optional)
if(ENABLE_SANITIZERS)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(benchmark_tests PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(benchmark_tests PRIVATE -fsanitize=address,undefined)
    endif()
endif()

# Print configuration summary
message(STATUS "")
message(STATUS "Test Suite Configuration:")
message(STATUS "  Google Test: ${GTest_FOUND}")
message(STATUS "  Coverage: ${ENABLE_COVERAGE}")
message(STATUS "  Valgrind: ${ENABLE_VALGRIND}")
message(STATUS "  Sanitizers: ${ENABLE_SANITIZERS}")
message(STATUS "")
