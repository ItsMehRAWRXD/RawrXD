cmake_minimum_required(VERSION 3.20)
project(RawrXDCompressedResidencySmoke LANGUAGES CXX)

include(CTest)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(RAWRXD_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../..")
set(RAWRXD_COMPRESSION "${RAWRXD_ROOT}/src/deep2/compression")

add_library(rawrxd_compressed_weight_store STATIC
    "${RAWRXD_COMPRESSION}/CompressedWeightStore.cpp")
target_include_directories(rawrxd_compressed_weight_store PUBLIC
    "${RAWRXD_COMPRESSION}"
    "${RAWRXD_ROOT}/src/deep2"
    "${RAWRXD_ROOT}/include")
if(MSVC)
    target_compile_options(rawrxd_compressed_weight_store PRIVATE /W4 /permissive-)
else()
    target_compile_options(rawrxd_compressed_weight_store PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
endif()

function(rawrxd_add_smoke target source test_name)
    add_executable(${target} "${RAWRXD_ROOT}/${source}")
    target_link_libraries(${target} PRIVATE rawrxd_compressed_weight_store)
    target_compile_features(${target} PRIVATE cxx_std_20)
    add_test(NAME ${test_name} COMMAND ${target})
endfunction()

rawrxd_add_smoke(test_compressed_weight_store
    tests/compressed_weight_store/test_compressed_weight_store.cpp
    compressed_weight_store_roundtrip)

rawrxd_add_smoke(test_stored_tensor_matvec
    tests/compressed_weight_store/test_stored_tensor_matvec.cpp
    compressed_resident_f16_q8_matvec)

rawrxd_add_smoke(test_stored_q4_0_matvec
    tests/compressed_weight_store/test_stored_q4_0_matvec.cpp
    compressed_resident_q4_0_matvec)

rawrxd_add_smoke(test_stored_q4_q5_matvec
    tests/compressed_weight_store/test_stored_q4_q5_matvec.cpp
    compressed_resident_q4_q5_matvec)

rawrxd_add_smoke(test_synthetic_gguf_model_e2e
    tests/compressed_weight_store/test_synthetic_gguf_model_e2e.cpp
    synthetic_gguf_compressed_model_e2e)

rawrxd_add_smoke(test_compressed_norm_vector
    tests/compressed_weight_store/test_compressed_norm_vector.cpp
    compressed_norm_vector_range_residency)

add_executable(test_compressed_gpu_tile_plan
    "${RAWRXD_ROOT}/tests/compressed_weight_store/test_compressed_gpu_tile_plan.cpp")
target_include_directories(test_compressed_gpu_tile_plan PRIVATE
    "${RAWRXD_ROOT}/include"
    "${RAWRXD_COMPRESSION}")
target_compile_features(test_compressed_gpu_tile_plan PRIVATE cxx_std_17)
add_test(NAME compressed_gpu_tile_plan COMMAND test_compressed_gpu_tile_plan)

# Test the actual Qt-independent zlib adapter, with an explicit unsupported
# build when zlib is absent and full roundtrip/corruption/ceiling checks when
# a provider is available.
add_library(rawrxd_compression_core STATIC
    "${RAWRXD_ROOT}/src/codec/compression_core.cpp")
target_include_directories(rawrxd_compression_core PUBLIC
    "${RAWRXD_ROOT}/include")
target_compile_features(rawrxd_compression_core PUBLIC cxx_std_17)
find_package(ZLIB QUIET)
if(ZLIB_FOUND)
    if(TARGET ZLIB::ZLIB)
        target_link_libraries(rawrxd_compression_core PUBLIC ZLIB::ZLIB)
    else()
        target_include_directories(rawrxd_compression_core PUBLIC ${ZLIB_INCLUDE_DIRS})
        target_link_libraries(rawrxd_compression_core PUBLIC ${ZLIB_LIBRARIES})
    endif()
    target_compile_definitions(rawrxd_compression_core PUBLIC RAWRXD_HAVE_ZLIB=1)
endif()
add_executable(rawrxd_compression_core_test
    "${RAWRXD_ROOT}/tests/compression_core_test.cpp")
target_link_libraries(rawrxd_compression_core_test PRIVATE rawrxd_compression_core)
target_compile_features(rawrxd_compression_core_test PRIVATE cxx_std_17)
add_test(NAME rawrxd_zlib_compression_core COMMAND rawrxd_compression_core_test)

if(ZLIB_FOUND)
    add_executable(brutal_gzip_portable_contract_test
        "${RAWRXD_ROOT}/tests/brutal_gzip_portable_contract_test.cpp")
    target_include_directories(brutal_gzip_portable_contract_test PRIVATE
        "${RAWRXD_ROOT}/include")
    target_compile_features(brutal_gzip_portable_contract_test PRIVATE cxx_std_17)
    if(TARGET ZLIB::ZLIB)
        target_link_libraries(brutal_gzip_portable_contract_test PRIVATE ZLIB::ZLIB)
    else()
        target_include_directories(brutal_gzip_portable_contract_test PRIVATE ${ZLIB_INCLUDE_DIRS})
        target_link_libraries(brutal_gzip_portable_contract_test PRIVATE ${ZLIB_LIBRARIES})
    endif()
    add_test(NAME brutal_gzip_portable_contract COMMAND brutal_gzip_portable_contract_test)
endif()

message(STATUS "RawrXD isolated compressed-residency and codec smoke suite configured")

if(MSVC)
    enable_language(ASM_MASM)
    add_library(rawrxd_brutal_gzip STATIC
        "${RAWRXD_ROOT}/kernels/deflate_brutal_masm.asm")
    target_include_directories(rawrxd_brutal_gzip PUBLIC
        "${RAWRXD_ROOT}/include")
    target_compile_definitions(rawrxd_brutal_gzip PUBLIC
        RAWRXD_HAVE_BRUTAL_GZIP_MASM=1)
    if(ZLIB_FOUND)
        add_executable(brutal_masm_gzip_contract_test
            "${RAWRXD_ROOT}/tests/brutal_masm_gzip_contract_test.cpp")
        target_link_libraries(brutal_masm_gzip_contract_test PRIVATE
            rawrxd_brutal_gzip ZLIB::ZLIB)
        target_include_directories(brutal_masm_gzip_contract_test PRIVATE
            "${RAWRXD_ROOT}/include")
        target_compile_features(brutal_masm_gzip_contract_test PRIVATE cxx_std_17)
        add_test(NAME brutal_masm_gzip_contract COMMAND brutal_masm_gzip_contract_test)
    endif()
endif()
