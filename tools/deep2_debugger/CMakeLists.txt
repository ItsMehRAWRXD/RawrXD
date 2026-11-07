cmake_minimum_required(VERSION 3.20)
project(deep2_flight_recorder LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    add_compile_options(/W4 /permissive- /std:c++20 /EHsc)
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        add_compile_options(/O2 /Ob2)
    endif()
else()
    add_compile_options(-Wall -Wextra -Wpedantic -std=c++20)
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        add_compile_options(-O2)
    endif()
endif()

# Header-only library
add_library(deep2_flight_recorder INTERFACE)
target_include_directories(deep2_flight_recorder INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}
)
target_compile_features(deep2_flight_recorder INTERFACE cxx_std_20)

# Smoke test
add_executable(flight_recorder_smoke flight_recorder_smoke.cpp)
target_link_libraries(flight_recorder_smoke PRIVATE deep2_flight_recorder)

# Enable testing
enable_testing()
add_test(NAME flight_recorder_smoke_test COMMAND $<TARGET_FILE:flight_recorder_smoke>)
