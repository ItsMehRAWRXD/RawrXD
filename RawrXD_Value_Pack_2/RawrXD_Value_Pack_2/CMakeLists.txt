cmake_minimum_required(VERSION 3.20)
project(RawrXDValuePack2 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(RawrXD-ValuePack2 STATIC
    src/lifecycle_bus.cpp
    src/command_center.cpp
)
target_include_directories(RawrXD-ValuePack2 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

if(WIN32)
    target_sources(RawrXD-ValuePack2 PRIVATE src/browser_authority_win32.cpp)
    target_link_libraries(RawrXD-ValuePack2 PUBLIC winhttp)
    target_compile_definitions(RawrXD-ValuePack2 PUBLIC WIN32_LEAN_AND_MEAN NOMINMAX)
endif()

add_executable(rawrxd-value-pack2 src/value_pack_cli.cpp)
target_link_libraries(rawrxd-value-pack2 PRIVATE RawrXD-ValuePack2)

include(CTest)
if(BUILD_TESTING)
    add_executable(rawrxd-value-pack2-test tests/test_core.cpp)
    target_link_libraries(rawrxd-value-pack2-test PRIVATE RawrXD-ValuePack2)
    add_test(NAME rawrxd-value-pack2-core COMMAND rawrxd-value-pack2-test)
endif()
