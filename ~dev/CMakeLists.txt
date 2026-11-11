cmake_minimum_required(VERSION 3.20)
project(rawr_monolith LANGUAGES C CXX ASM_MASM)

enable_testing()

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
    src/rawr_model_resolver.cpp
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
    rawrxd/src/deep2/RawrExpertPager.cpp
    rawrxd/src/deep2/RawrNativeCompiler.cpp
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
    ${Vulkan_INCLUDE_DIRS}
)

target_compile_definitions(rawr_monolith PRIVATE
    RAWR_MONOLITH_STANDALONE
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

add_executable(rawr_deep2_native_primitives_test
    tools/deep2_native_primitives_test.cpp
    rawrxd/src/deep2/RawrExpertPager.cpp
    rawrxd/src/deep2/RawrNativeCompiler.cpp
)
target_include_directories(rawr_deep2_native_primitives_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src
)
target_compile_definitions(rawr_deep2_native_primitives_test PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
if(MSVC)
    target_compile_options(rawr_deep2_native_primitives_test PRIVATE /W4 /permissive- /EHsc)
endif()
add_test(NAME rawr_deep2_native_primitives COMMAND rawr_deep2_native_primitives_test)

# Standalone deterministic trace producer.  It deliberately does not share
# the product CLI so parity captures cannot be confused with self-comparison
# or agent output.  The external reference trace must come from an independent
# implementation before the comparison utility can report PASS.
add_executable(deep2_parity_oracle
    tests/deep2_parity_oracle.cpp
    tests/deep2_parity_symbols.cpp
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
)
target_include_directories(deep2_parity_oracle PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/deep2
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src/deep2
    ${Vulkan_INCLUDE_DIRS}
)
target_compile_definitions(deep2_parity_oracle PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)
target_compile_options(deep2_parity_oracle PRIVATE /arch:AVX512 /fp:fast)
if(MSVC)
    target_compile_options(deep2_parity_oracle PRIVATE /W4 /permissive- /EHsc)
endif()
target_link_libraries(deep2_parity_oracle PRIVATE Vulkan::Vulkan)

# Product-facing command name. Keep the historical monolith artifact for
# existing scripts, while also emitting the documented `rawr run ...` binary.
if(WIN32)
    add_custom_command(TARGET rawr_monolith POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "$<TARGET_FILE:rawr_monolith>"
            "$<TARGET_FILE_DIR:rawr_monolith>/rawr.exe"
        COMMENT "Publishing rawr.exe product entry point")
endif()
