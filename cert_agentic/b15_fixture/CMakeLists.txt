cmake_minimum_required(VERSION 3.20)
project(cfix LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

enable_testing()

add_library(cfix_core STATIC
    src/config_loader.cpp
)
target_include_directories(cfix_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_executable(cfix_app
    src/main.cpp
)
target_link_libraries(cfix_app PRIVATE cfix_core)

add_executable(cfix_tests
    tests/test_config_loader.cpp
)
target_link_libraries(cfix_tests PRIVATE cfix_core)

add_test(NAME config_loader_tests COMMAND cfix_tests)
