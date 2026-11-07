cmake_minimum_required(VERSION 3.20)
project(snap_process_guard LANGUAGES CXX)

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

# Library with implementation
add_library(snap_process_guard snap_process_guard_cli.cpp)
target_include_directories(snap_process_guard PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
target_compile_features(snap_process_guard PUBLIC cxx_std_20)
target_compile_definitions(snap_process_guard PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)

# Link Windows libraries
if(MSVC)
    target_link_libraries(snap_process_guard PRIVATE Advapi32 Psapi)
endif()

# CLI executable
add_executable(snap_process_guard_cli snap_process_guard_cli.cpp)
target_link_libraries(snap_process_guard_cli PRIVATE snap_process_guard)

# Enable testing
enable_testing()
add_test(NAME snap_process_guard_test COMMAND $<TARGET_FILE:snap_process_guard_cli> --help)

# Install
install(TARGETS snap_process_guard_cli
    RUNTIME DESTINATION bin
)
install(FILES snap_process_guard.hpp
    DESTINATION include/snap/process
)
