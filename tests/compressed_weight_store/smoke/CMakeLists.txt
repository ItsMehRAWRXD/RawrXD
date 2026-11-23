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

add_executable(test_compressed_gpu_tile_plan
    "${RAWRXD_ROOT}/tests/compressed_weight_store/test_compressed_gpu_tile_plan.cpp")
target_include_directories(test_compressed_gpu_tile_plan PRIVATE
    "${RAWRXD_ROOT}/include"
    "${RAWRXD_COMPRESSION}")
target_compile_features(test_compressed_gpu_tile_plan PRIVATE cxx_std_17)
add_test(NAME compressed_gpu_tile_plan COMMAND test_compressed_gpu_tile_plan)

message(STATUS "RawrXD isolated compressed-residency smoke suite configured")
