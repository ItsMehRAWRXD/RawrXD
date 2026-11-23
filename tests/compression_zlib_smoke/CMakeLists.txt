cmake_minimum_required(VERSION 3.20)
project(RawrXDZlibProviderSmoke LANGUAGES CXX)

# Build the same production codec translation unit in a small isolated project.
find_package(ZLIB QUIET)
add_library(rawrxd_compression_core STATIC
    ${CMAKE_CURRENT_LIST_DIR}/../../src/codec/compression_core.cpp)
target_include_directories(rawrxd_compression_core PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/../../include)
target_compile_features(rawrxd_compression_core PUBLIC cxx_std_17)

if(ZLIB_FOUND AND TARGET ZLIB::ZLIB)
    target_link_libraries(rawrxd_compression_core PUBLIC ZLIB::ZLIB)
    target_compile_definitions(rawrxd_compression_core PUBLIC RAWRXD_HAVE_ZLIB=1)
elseif(ZLIB_FOUND AND ZLIB_LIBRARIES AND (ZLIB_INCLUDE_DIRS OR ZLIB_INCLUDE_DIR))
    target_link_libraries(rawrxd_compression_core PUBLIC ${ZLIB_LIBRARIES})
    if(ZLIB_INCLUDE_DIRS)
        target_include_directories(rawrxd_compression_core PUBLIC ${ZLIB_INCLUDE_DIRS})
    else()
        target_include_directories(rawrxd_compression_core PUBLIC ${ZLIB_INCLUDE_DIR})
    endif()
    target_compile_definitions(rawrxd_compression_core PUBLIC RAWRXD_HAVE_ZLIB=1)
elseif(TARGET zlib)
    target_link_libraries(rawrxd_compression_core PUBLIC zlib)
    target_include_directories(rawrxd_compression_core PUBLIC
        ${CMAKE_BINARY_DIR}/_deps/zlib-src
        ${CMAKE_BINARY_DIR}/_deps/zlib-build)
    target_compile_definitions(rawrxd_compression_core PUBLIC RAWRXD_HAVE_ZLIB=1)
else()
    message(FATAL_ERROR "No usable zlib provider found for provider smoke")
endif()

add_executable(compression_zlib_provider_compile_test
    ${CMAKE_CURRENT_LIST_DIR}/../compression_zlib_provider_compile_test.cpp)
target_link_libraries(compression_zlib_provider_compile_test PRIVATE rawrxd_compression_core)
target_compile_features(compression_zlib_provider_compile_test PRIVATE cxx_std_17)
enable_testing()
add_test(NAME compression_zlib_provider_compile_test COMMAND compression_zlib_provider_compile_test)
