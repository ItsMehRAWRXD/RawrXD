#====================================================================
# RAWR Unified LLM Runtime — CMake build
#====================================================================
# Builds the monolithic inference engine with:
#   - rawr_monolith_v2.cpp (main runtime)
#   - rawr_gemm_avx512.h   (AVX-512 GEMM + packed Q6_K/Q8_K/Q4_K kernels)
#   - src/deep2/            (K2 packed kernel branch)
#     - Classify.asm        (x64 MASM weight classifier)
#     - K2LivePathTensorCache.cpp
#     - K2LogitsClimb.cpp   (Q6_K×Q8_K logits projection)
#     - K2VNNIKernel.cpp    (Q4_K VNNI GEMV)
#
# Usage:
#   cmake -B build -G "Visual Studio 17 2022" -A x64
#   cmake --build build --config Release
#====================================================================

cmake_minimum_required(VERSION 3.20)
project(rawr_monolith CXX ASM)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

#--------------------
# AVX-512 flags
#--------------------
if(MSVC)
    add_compile_options(/arch:AVX512 /O2 /fp:fast)
    add_compile_definitions(_WIN32 WIN32_LEAN_AND_MEAN NOMINMAX)
else()
    add_compile_options(-mavx512f -mavx512vl -mavx512bw -mavx512dq -mavx512vnni -mfma -O3)
endif()

#--------------------
# Source files
#--------------------
set(MONOLITH_SOURCES
    rawr_monolith_v2.cpp
)

set(DEEP2_SOURCES
    src/deep2/K2LivePathTensorCache.cpp
    src/deep2/K2LogitsClimb.cpp
    src/deep2/K2VNNIKernel.cpp
)

set(RAWRXD_DEEP2_SOURCES
    rawrxd/src/deep2/Deep2Engine.cpp
    rawrxd/src/deep2/Tokenizer.cpp
    rawrxd/src/deep2/Sampler.cpp
    rawrxd/src/deep2/QuantKernelRegistry.cpp
    rawrxd/src/deep2/Deep2Engine_SsVkDecodeBind.cpp
    rawrxd/src/deep2/d2_engine_ssvk_decode_bind.c
    rawrxd/src/deep2/vulkan_compute.cpp
    rawrxd/src/deep2/Deep2Engine_VulkanRuntime.cpp
    rawrxd/src/deep2/Deep2Engine_GpuForward.cpp
    rawrxd/src/deep2/Deep2MultiGpuLayerPlan.cpp
    rawrxd/src/deep2/Deep2DualGpuRowSplit.cpp
    rawrxd/src/deep2/Deep2Engine_GpuMoEMLA.cpp
)

#--------------------
# MASM assembly (Windows x64 only)
#--------------------
if(WIN32 AND CMAKE_SIZEOF_VOID_P EQUAL 8)
    enable_language(ASM_MASM)
    set(DEEP2_ASM
        src/deep2/Classify.asm
    )
    set_source_files_properties(src/deep2/Classify.asm PROPERTIES LANGUAGE ASM_MASM)
else()
    set(DEEP2_ASM "")
    message(STATUS "Classify.asm skipped — MASM requires Windows x64")
endif()

#--------------------
# Main executable
#--------------------
add_executable(rawr_monolith
    ${MONOLITH_SOURCES}
    ${DEEP2_SOURCES}
    ${DEEP2_ASM}
)

target_include_directories(rawr_monolith PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/deep2
)

#--------------------
# Parity harness (certification)
#--------------------
add_executable(k2_parity_harness
    tests/k2_parity_harness.cpp
)
target_include_directories(k2_parity_harness PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/deep2
)

#--------------------
# Smoke test (certification)
#--------------------
add_executable(k2_smoke_test
    tests/k2_smoke_test.cpp
)
target_include_directories(k2_smoke_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/deep2
)

#--------------------
# Deep2 Engine + Decode Bind (certification)
#--------------------
add_executable(deep2_engine_ssvk_decode_bind_cert
    rawrxd/src/deep2/deep2_engine_ssvk_decode_bind_cert.cpp
    ${RAWRXD_DEEP2_SOURCES}
)
target_include_directories(deep2_engine_ssvk_decode_bind_cert PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/deep2
)

#--------------------
# Deep2 standalone engine test
#--------------------
add_executable(deep2_standalone
    rawrxd/src/deep2/Deep2Engine.cpp
    rawrxd/src/deep2/Tokenizer.cpp
    rawrxd/src/deep2/Sampler.cpp
    rawrxd/src/deep2/QuantKernelRegistry.cpp
    rawrxd/src/deep2/Deep2Engine_SsVkDecodeBind.cpp
    rawrxd/src/deep2/d2_engine_ssvk_decode_bind.c
    rawrxd/src/deep2/vulkan_compute.cpp
    rawrxd/src/deep2/Deep2Engine_VulkanRuntime.cpp
    rawrxd/src/deep2/Deep2Engine_GpuForward.cpp
    rawrxd/src/deep2/Deep2MultiGpuLayerPlan.cpp
    rawrxd/src/deep2/Deep2DualGpuRowSplit.cpp
    rawrxd/src/deep2/Deep2Engine_GpuMoEMLA.cpp
    tests/deep2_standalone.cpp
)
target_include_directories(deep2_standalone PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/deep2
)

# Batch 9: Vulkan runtime for deep2_standalone.
find_package(Vulkan QUIET)
if(Vulkan_FOUND)
    target_link_libraries(deep2_standalone PRIVATE Vulkan::Vulkan)
else()
    message(STATUS "[deep2_standalone] Vulkan SDK not found - Batch 9 runtime will fail closed at device init")
endif()

# Batch 9 hardware cert: physical enumeration + dual-device probe.
add_executable(batch9_vulkan_multigpu_cert
    rawrxd/src/deep2/Batch9_VulkanMultiGpuCert.cpp
    rawrxd/src/deep2/vulkan_compute.cpp
)
target_include_directories(batch9_vulkan_multigpu_cert PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src
)
if(Vulkan_FOUND)
    target_link_libraries(batch9_vulkan_multigpu_cert PRIVATE Vulkan::Vulkan)
endif()

# Batch 10 hardware cert: peer group probe + dual row-split GEMV.
add_executable(batch10_peer_rowsplit_cert
    rawrxd/src/deep2/Batch10_PeerRowSplitCert.cpp
    rawrxd/src/deep2/vulkan_compute.cpp
    rawrxd/src/deep2/Deep2DualGpuRowSplit.cpp
)
target_include_directories(batch10_peer_rowsplit_cert PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src
)
if(Vulkan_FOUND)
    target_link_libraries(batch10_peer_rowsplit_cert PRIVATE Vulkan::Vulkan)
endif()

# Batch 10 row-split plan self-test (host-only, no Vulkan).
add_executable(batch10_rowsplit_plan_selftest
    rawrxd/src/deep2/Batch10_RowSplitPlan_SELFTEST.cpp
)
target_include_directories(batch10_rowsplit_plan_selftest PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)