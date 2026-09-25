cmake_minimum_required(VERSION 3.20)
project(rawr_monolith LANGUAGES C CXX ASM_MASM)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Vulkan REQUIRED)

add_executable(rawr_monolith
    rawr_monolith_v2.cpp
    src/rawr_run_stream.cpp
    src/rawr_agent.cpp
    src/rawr_audit_state.cpp
    src/rawr_agent_dispatch.cpp
    src/rawr_stub_scan.cpp
    src/rawr_agent_audit_driver.cpp
    rawrxd/src/deep2/AgentToolAuthority.cpp
    rawrxd/src/deep2/Deep2Engine.cpp
    rawrxd/src/deep2/Deep2Engine_Speculative.cpp
    rawrxd/src/deep2/Tokenizer.cpp
    rawrxd/src/deep2/Sampler.cpp
    rawrxd/src/deep2/QuantKernelRegistry.cpp
    rawrxd/src/deep2/Deep2Engine_SsVkDecodeBind.cpp
    rawrxd/src/deep2/vulkan_compute.cpp
    rawrxd/src/deep2/Deep2Engine_VulkanRuntime.cpp
    rawrxd/src/deep2/Deep2Engine_GpuForward.cpp
    rawrxd/src/deep2/Deep2MultiGpuLayerPlan.cpp
    rawrxd/src/deep2/Deep2DualGpuRowSplit.cpp
    rawrxd/src/deep2/Deep2Engine_GpuMoEMLA.cpp
    rawrxd/src/deep2/Deep2Engine_GpuToken.cpp
    rawrxd/src/deep2/Deep2DeviceManager.cpp
    rawrxd/src/deep2/VramStreamingController.cpp
    rawrxd/src/deep2/StreamEngine.cpp
    rawrxd/src/deep2/StreamRouter.cpp
    rawrxd/src/deep2/BP16Streamer.cpp
    rawrxd/src/deep2/CompressedKVCache.cpp
    rawrxd/src/deep2/NVMeStream.cpp
    rawrxd/src/deep2/ElasticResidencyManager.cpp
    rawrxd/src/deep2/CycloneScheduler.cpp
    rawrxd/src/deep2/ProductionProfiler.cpp
    rawrxd/src/deep2/Chamber.cpp
    rawrxd/src/deep2/ToroidalKVCache.cpp
    rawrxd/src/deep2/PlasmaGovernor.cpp
    rawrxd/src/deep2/SovereignOutOfCoreRuntime.cpp
    rawrxd/src/deep2/expert_cache/ExpertCache.cpp
    rawrxd/src/deep2/expert_cache/VulkanExpertTransport.cpp
    rawrxd/src/deep2/expert_cache/HostStagingRing.cpp
    rawrxd/src/deep2/mars/MARSController.cpp
    rawrxd/src/deep2/streaming/ContinuousExecution.cpp
    rawrxd/src/deep2/streaming/Win32ContinuousBridge.cpp
    src/deep2/Classify.asm
    rawrxd/src/rawr_classifier_scalar.asm
    rawrxd/src/rawr_classifier_avx2.asm
)

target_include_directories(rawr_monolith PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/deep2
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src/deep2
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src/deep2/streaming
    ${Vulkan_INCLUDE_DIRS}
)

target_compile_definitions(rawr_monolith PRIVATE
    RAWR_MONOLITH_STANDALONE
    RAWR_HAS_SOVEREIGN_ENGINES=1
    RAWR_HAS_RAWR_INFERENCE=1
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

target_compile_options(rawr_monolith PRIVATE
    /arch:AVX512
    /fp:fast
)

if(MSVC)
    target_compile_options(rawr_monolith PRIVATE /W4 /permissive- /EHsc)
endif()

target_link_libraries(rawr_monolith PRIVATE Vulkan::Vulkan)

# ---- V2 static library target ----
add_library(rawrxd_screenpilot_e2e STATIC
    rawrxd/src/screenpilot/rawrxd_screenpilot_agent_v2.cpp
)

target_include_directories(rawrxd_screenpilot_e2e PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/include/screenpilot
)

target_compile_features(rawrxd_screenpilot_e2e PUBLIC cxx_std_20)
target_compile_definitions(rawrxd_screenpilot_e2e PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(rawrxd_screenpilot_e2e PUBLIC bcrypt)

if(MSVC)
    target_compile_options(rawrxd_screenpilot_e2e PRIVATE /W4 /permissive- /EHsc)
endif()

target_link_libraries(rawr_monolith PRIVATE rawrxd_screenpilot_e2e)

# ---- Deep2 benchmark target ----
add_executable(deep2_benchmark
    rawrxd/src/deep2/deep2_benchmark_main.cpp
    rawrxd/src/deep2/AgentToolAuthority.cpp
    rawrxd/src/deep2/Deep2Engine.cpp
    rawrxd/src/deep2/Deep2Engine_Speculative.cpp
    rawrxd/src/deep2/Tokenizer.cpp
    rawrxd/src/deep2/Sampler.cpp
    rawrxd/src/deep2/QuantKernelRegistry.cpp
    rawrxd/src/deep2/Deep2Engine_SsVkDecodeBind.cpp
    rawrxd/src/deep2/vulkan_compute.cpp
    rawrxd/src/deep2/Deep2Engine_VulkanRuntime.cpp
    rawrxd/src/deep2/Deep2Engine_GpuForward.cpp
    rawrxd/src/deep2/Deep2MultiGpuLayerPlan.cpp
    rawrxd/src/deep2/Deep2DualGpuRowSplit.cpp
    rawrxd/src/deep2/Deep2Engine_GpuMoEMLA.cpp
    rawrxd/src/deep2/Deep2Engine_GpuToken.cpp
    rawrxd/src/deep2/Deep2DeviceManager.cpp
    rawrxd/src/deep2/VramStreamingController.cpp
    rawrxd/src/deep2/StreamEngine.cpp
    rawrxd/src/deep2/StreamRouter.cpp
    rawrxd/src/deep2/BP16Streamer.cpp
    rawrxd/src/deep2/CompressedKVCache.cpp
    rawrxd/src/deep2/NVMeStream.cpp
    rawrxd/src/deep2/ElasticResidencyManager.cpp
    rawrxd/src/deep2/CycloneScheduler.cpp
    rawrxd/src/deep2/ProductionProfiler.cpp
    rawrxd/src/deep2/Chamber.cpp
    rawrxd/src/deep2/ToroidalKVCache.cpp
    rawrxd/src/deep2/PlasmaGovernor.cpp
    rawrxd/src/deep2/SovereignOutOfCoreRuntime.cpp
    rawrxd/src/deep2/expert_cache/ExpertCache.cpp
    rawrxd/src/deep2/expert_cache/VulkanExpertTransport.cpp
    rawrxd/src/deep2/expert_cache/HostStagingRing.cpp
    rawrxd/src/deep2/mars/MARSController.cpp
    rawrxd/src/deep2/strict_gpu_violations.cpp
    rawrxd/src/deep2/Beaconism.cpp
    rawrxd/src/deep2/GpuScheduler.cpp
    rawrxd/src/deep2/TimeReverseDigest.cpp
    rawrxd/src/deep2/RealGGUFParity.cpp
    rawrxd/src/deep2/streaming/ContinuousExecution.cpp
    rawrxd/src/deep2/streaming/Win32ContinuousBridge.cpp
    rawrxd/src/deep2/streaming/ContinuousEventLedger.cpp
    src/deep2/Classify.asm
    rawrxd/src/rawr_classifier_scalar.asm
    rawrxd/src/rawr_classifier_avx2.asm
)

target_include_directories(deep2_benchmark PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/deep2
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src/deep2
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src/deep2/streaming
    ${Vulkan_INCLUDE_DIRS}
)

target_compile_definitions(deep2_benchmark PRIVATE
    RAWR_HAS_SOVEREIGN_ENGINES=1
    RAWR_HAS_RAWR_INFERENCE=1
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

target_compile_options(deep2_benchmark PRIVATE
    /arch:AVX512
    /fp:fast
)

if(MSVC)
    target_compile_options(deep2_benchmark PRIVATE /W4 /permissive- /EHsc)
endif()

target_link_libraries(deep2_benchmark PRIVATE Vulkan::Vulkan)
