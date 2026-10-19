cmake_minimum_required(VERSION 3.16)
project(RawrXDDualStickLocalityEnterprise LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(rawrxd_dualstick_locality STATIC
    src/EnterpriseDualStickLocality.cpp)
target_include_directories(rawrxd_dualstick_locality PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include)

if(MSVC)
    target_compile_options(rawrxd_dualstick_locality PRIVATE /W4 /WX /permissive- /EHsc /sdl)
else()
    target_compile_options(rawrxd_dualstick_locality PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow -Werror)
endif()

add_executable(dualstick_locality_selftest tests/selftest.cpp)
target_link_libraries(dualstick_locality_selftest PRIVATE rawrxd_dualstick_locality)

enable_testing()
add_test(NAME dualstick_locality_selftest COMMAND dualstick_locality_selftest)
