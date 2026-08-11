cmake_minimum_required(VERSION 3.20)
project(RawRamXD_v2 VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    add_compile_options(/O2 /Oi /Gy /W4)
else()
    add_compile_options(-O3 -march=native -Wall -Wextra -pthread)
endif()

find_package(Threads REQUIRED)

# v2.2 adversarial validation suite
add_executable(RawrXD_v22_Validate
    RawRamXD_v22_Validation.cpp
    ../RawRamXD.cpp
)

target_include_directories(RawrXD_v22_Validate PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/..
)

target_link_libraries(RawrXD_v22_Validate PRIVATE
    Threads::Threads
)
