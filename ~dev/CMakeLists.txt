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
    rawrxd/src/deep2/Deep2Engine_Speculative.cpp
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
    # MASM does not accept C++ compiler flags; override them.
    set_source_files_properties(src/deep2/Classify.asm PROPERTIES COMPILE_FLAGS "")
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
target_compile_definitions(rawr_monolith PRIVATE RAWR_MONOLITH_STANDALONE)

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
find_package(Vulkan QUIET)
if(Vulkan_FOUND)
    add_executable(deep2_engine_ssvk_decode_bind_cert
        rawrxd/src/deep2/deep2_engine_ssvk_decode_bind_cert.cpp
        ${RAWRXD_DEEP2_SOURCES}
    )
    target_include_directories(deep2_engine_ssvk_decode_bind_cert PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src
        ${CMAKE_CURRENT_SOURCE_DIR}/src/deep2
    )
    target_link_libraries(deep2_engine_ssvk_decode_bind_cert PRIVATE Vulkan::Vulkan)
else()
    message(STATUS "[deep2_engine_ssvk_decode_bind_cert] Vulkan SDK not found - target skipped")
endif()

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
    rawrxd/src/deep2/Deep2Engine_Speculative.cpp
    tests/deep2_standalone.cpp
)
target_include_directories(deep2_standalone PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/deep2
)

# Qwen2.5-Coder-32B real measured >=40 TPS authority gate.
# Safe if Vulkan was already discovered; idempotent otherwise.
find_package(Vulkan QUIET)
add_executable(qwen32_40tps_gate
    tests/qwen32_40tps_gate.cpp
    ${RAWRXD_DEEP2_SOURCES}
)
target_include_directories(qwen32_40tps_gate PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src/deep2
    ${CMAKE_CURRENT_SOURCE_DIR}/src/deep2
)
if(Vulkan_FOUND)
    target_link_libraries(qwen32_40tps_gate PRIVATE Vulkan::Vulkan)
endif()

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

# Batch 11-15 roofline self-test (host-only, no Vulkan).
add_executable(batch11_roofline_selftest
    tests/roofline_selftest.cpp
    rawrxd/src/deep2/Deep2PersistentDecode.cpp
    rawrxd/src/deep2/Deep2ExpertResidency.cpp
    rawrxd/src/deep2/Deep2PredictiveRouter.cpp
    rawrxd/src/deep2/Deep2DualGpuBalancer.cpp
    rawrxd/src/deep2/Deep2CommandBatch.cpp
    rawrxd/src/deep2/Deep2RooflineGovernor.cpp
    rawrxd/src/deep2/Deep2RooflineCert.cpp
    rawrxd/src/deep2/Deep2RooflineRuntime.cpp
)
target_include_directories(batch11_roofline_selftest PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src/deep2
)

# Batch 16-20 roofline self-test (host-only, no Vulkan).
add_executable(batch16_roofline_selftest
    tests/roofline_batches_selftest.cpp
    rawrxd/src/deep2/Deep2QuantGemvRoofline.cpp
    rawrxd/src/deep2/Deep2WaveOccupancy.cpp
    rawrxd/src/deep2/Deep2KvMlaTraffic.cpp
    rawrxd/src/deep2/Deep2MoEMathPlan.cpp
    rawrxd/src/deep2/Deep2LaunchAmortizer.cpp
    rawrxd/src/deep2/Deep2RooflineRatchet.cpp
)
target_include_directories(batch16_roofline_selftest PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src/deep2
)

# Batch 21-25 roofline self-test (host-only, no Vulkan).
add_executable(batch21_25_roofline_selftest
    tests/batch21_25_selftest.cpp
    rawrxd/src/deep2/Deep2B21QuantPack.cpp
    rawrxd/src/deep2/Deep2B22LdsReuse.cpp
    rawrxd/src/deep2/Deep2B23PersistentQueue.cpp
    rawrxd/src/deep2/Deep2B24SpecDecode.cpp
    rawrxd/src/deep2/Deep2B25Autotune.cpp
)
target_include_directories(batch21_25_roofline_selftest PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src/deep2
)

# Batch 26-30 roofline self-test (host-only, no Vulkan).
add_executable(batch26_30_roofline_selftest
    tests/batch26_30_selftest.cpp
    rawrxd/src/deep2/Deep2B26AttentionSuperkernel.cpp
    rawrxd/src/deep2/Deep2B27MoESuperkernel.cpp
    rawrxd/src/deep2/Deep2B28DeviceLogits.cpp
    rawrxd/src/deep2/Deep2B29LayerChain.cpp
    rawrxd/src/deep2/Deep2B30RooflineSeal.cpp
)
target_include_directories(batch26_30_roofline_selftest PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src/deep2
)

# Batch 31-35 roofline self-test (host-only, no Vulkan).
add_executable(batch31_35_roofline_selftest
    tests/batch31_35_selftest.cpp
    rawrxd/src/deep2/Deep2B31QuantSuperkernel.cpp
    rawrxd/src/deep2/Deep2B32FlashMLA.cpp
    rawrxd/src/deep2/Deep2B33ExpertStriping.cpp
    rawrxd/src/deep2/Deep2B34FusedKvAttention.cpp
    rawrxd/src/deep2/Deep2B35DeviceTokenHandoff.cpp
)
target_include_directories(batch31_35_roofline_selftest PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src/deep2
)

# Batch 36-40 roofline self-test (host-only, no Vulkan).
add_executable(batch36_40_roofline_selftest
    tests/batch36_40_selftest.cpp
    rawrxd/src/deep2/Deep2B36WaveDot.cpp
    rawrxd/src/deep2/Deep2B37RegisterTune.cpp
    rawrxd/src/deep2/Deep2B38CoopGemv.cpp
    rawrxd/src/deep2/Deep2B39FamilySpecializer.cpp
    rawrxd/src/deep2/Deep2B40PhysicalSeal.cpp
)
target_include_directories(batch36_40_roofline_selftest PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src/deep2
)

# Batch 41-45 roofline self-test (host-only, no Vulkan).
add_executable(batch41_45_roofline_selftest
    tests/batch41_45_selftest.cpp
    rawrxd/src/deep2/Deep2B41PackedDot.cpp
    rawrxd/src/deep2/Deep2B42AsyncLds.cpp
    rawrxd/src/deep2/Deep2B43MoEWave.cpp
    rawrxd/src/deep2/Deep2B44MlaComputeBalance.cpp
    rawrxd/src/deep2/Deep2B45KernelPlan.cpp
)
target_include_directories(batch41_45_roofline_selftest PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src/deep2
)

# Batch 46-50 roofline self-test (host-only, no Vulkan).
add_executable(batch46_50_roofline_selftest
    tests/batch46_50_selftest.cpp
    rawrxd/src/deep2/Deep2B46NativeQuant.cpp
    rawrxd/src/deep2/Deep2B47RegisterExpert.cpp
    rawrxd/src/deep2/Deep2B48CrossLayerFusion.cpp
    rawrxd/src/deep2/Deep2B49ShaderSpecializer.cpp
    rawrxd/src/deep2/Deep2B50ChallengeSeal.cpp
)
target_include_directories(batch46_50_roofline_selftest PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src/deep2
)

# Batch 51-55 roofline self-test (host-only, no Vulkan).
add_executable(batch51_55_roofline_selftest
    tests/batch51_55_selftest.cpp
    rawrxd/src/deep2/Deep2B51OwnerDirector.cpp
    rawrxd/src/deep2/Deep2B52MemoryTail.cpp
    rawrxd/src/deep2/Deep2B53ComputeTail.cpp
    rawrxd/src/deep2/Deep2B54DeviceGraph.cpp
    rawrxd/src/deep2/Deep2B55AsymptoticSeal.cpp
)
target_include_directories(batch51_55_roofline_selftest PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src/deep2
)

# Batch 56-60 roofline self-test (host-only, no Vulkan).
add_executable(batch56_60_roofline_selftest
    tests/batch56_60_selftest.cpp
    rawrxd/src/deep2/Deep2B56LayerPhasePlanner.cpp
    rawrxd/src/deep2/Deep2B57ContextKernel.cpp
    rawrxd/src/deep2/Deep2B58RouteSpecializer.cpp
    rawrxd/src/deep2/Deep2B59StabilityGovernor.cpp
    rawrxd/src/deep2/Deep2B60ModelContract.cpp
)
target_include_directories(batch56_60_roofline_selftest PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src/deep2
)

# Batch 61-65 showcase fleet self-test (host-only, no Vulkan).
add_executable(batch61_65_showcase_selftest
    tests/batch61_65_selftest.cpp
    rawrxd/src/deep2/Deep2B61QwenNext.cpp
    rawrxd/src/deep2/Deep2B62Nemotron.cpp
    rawrxd/src/deep2/Deep2B63GptOss.cpp
    rawrxd/src/deep2/Deep2B64Laguna.cpp
    rawrxd/src/deep2/Deep2B65DeepSeekFlash.cpp
    rawrxd/src/deep2/Deep2FleetContract.cpp
)
target_include_directories(batch61_65_showcase_selftest PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src/deep2
)

# Batch 66-70 live contract self-test (host-only, no Vulkan).
add_executable(batch66_70_livecontract_selftest
    tests/batch66_70_selftest.cpp
    rawrxd/src/deep2/Deep2B66RuntimeMeta.cpp
    rawrxd/src/deep2/Deep2B67LiveTelemetry.cpp
    rawrxd/src/deep2/Deep2B68TargetCalibrator.cpp
    rawrxd/src/deep2/Deep2B69ContractRunner.cpp
    rawrxd/src/deep2/Deep2B70Receipt.cpp
)
target_include_directories(batch66_70_livecontract_selftest PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src/deep2
)

# Batch 71-75 product authority self-test (host-only, no Vulkan).
add_executable(batch71_75_authority_selftest
    tests/batch71_75_selftest.cpp
    rawrxd/src/deep2/Deep2B71GpuCounterAdapter.cpp
    rawrxd/src/deep2/Deep2B72RawrBenchCli.cpp
    rawrxd/src/deep2/Deep2B73EvidenceStore.cpp
    rawrxd/src/deep2/Deep2B74ReceiptReplay.cpp
    rawrxd/src/deep2/Deep2B75FleetPromotion.cpp
)
target_include_directories(batch71_75_authority_selftest PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src/deep2
)

# Batch 76-80 independent real-model E2E audit self-test (host-only, no Vulkan).
add_executable(batch76_80_e2e_selftest
    tests/batch76_80_e2e_selftest.cpp
)
target_include_directories(batch76_80_e2e_selftest PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src/deep2
)

# Batch 76-80 independent E2E audit tool (host-only, no Vulkan).
add_executable(deep2_e2e_audit
    rawrxd/src/deep2/deep2_e2e_audit.cpp
)
target_include_directories(deep2_e2e_audit PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src/deep2
)
add_executable(qwen32_85tps_prereq
    tests/qwen32_85tps_prereq.cpp
)
target_include_directories(qwen32_85tps_prereq PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src/deep2
)
add_executable(qwen32_85tps_gate
    tests/qwen32_85tps_gate.cpp
    ${RAWRXD_DEEP2_SOURCES}
)
target_include_directories(qwen32_85tps_gate PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src/deep2
    ${CMAKE_CURRENT_SOURCE_DIR}/src/deep2
)
find_package(Vulkan QUIET)
if(Vulkan_FOUND)
    target_link_libraries(qwen32_85tps_gate PRIVATE Vulkan::Vulkan)
endif()
