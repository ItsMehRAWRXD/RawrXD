# VAL-012: Autonomous Loop Closure
# Vertical Slice Implementation

cmake_minimum_required(VERSION 3.20)
project(VAL012 VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# VAL-012 Controller Library
add_library(val012_controller STATIC
    val012_controller.cpp
    val012_controller.h
    val012_build_executor.cpp
    val012_build_executor.h
    val012_test_executor.cpp
    val012_test_executor.h
    val012_controller_v2.cpp
    val012_controller_v2.h
)

target_include_directories(val012_controller PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# VAL-012 Test Executables
add_executable(val012_test
    ../../tests/val012/val012_test.cpp
)

target_link_libraries(val012_test PRIVATE
    val012_controller
)

target_include_directories(val012_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

add_executable(val012_v2_test
    ../../tests/val012/val012_v2_test.cpp
)

target_link_libraries(val012_v2_test PRIVATE
    val012_controller
)

target_include_directories(val012_v2_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Enable C++20 for VAL-012
target_compile_features(val012_controller PUBLIC cxx_std_20)
target_compile_features(val012_test PRIVATE cxx_std_20)

# Installation
install(TARGETS val012_controller val012_test
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

# Print status message
message(STATUS "VAL-012: Autonomous Loop Closure configured")
message(STATUS "  Target: val012_controller")
message(STATUS "  Test: val012_test")
