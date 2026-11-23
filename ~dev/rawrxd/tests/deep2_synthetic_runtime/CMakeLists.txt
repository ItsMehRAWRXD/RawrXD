cmake_minimum_required(VERSION 3.20)
project(RawrXD_Deep2_Synthetic_GGUF_E2E LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Threads REQUIRED)
find_package(Vulkan REQUIRED)

set(DEEP2_DIR "${CMAKE_CURRENT_LIST_DIR}/../../src/deep2")
add_executable(rawrxd-native-deep2-gguf-model-e2e-test
    "${CMAKE_CURRENT_LIST_DIR}/../native_deep2_gguf_model_e2e_test.cpp"
    "${DEEP2_DIR}/Deep2Engine.cpp"
    "${DEEP2_DIR}/Deep2Engine_GpuForward.cpp"
    "${DEEP2_DIR}/Deep2Engine_GpuMoEMLA.cpp"
    "${DEEP2_DIR}/Deep2Engine_Speculative.cpp"
    "${DEEP2_DIR}/Deep2Engine_SsVkDecodeBind.cpp"
    "${DEEP2_DIR}/Deep2Engine_VulkanRuntime.cpp"
    "${DEEP2_DIR}/Deep2DualGpuRowSplit.cpp"
    "${DEEP2_DIR}/Deep2DualGpuBalancer.cpp"
    "${DEEP2_DIR}/Deep2MultiGpuLayerPlan.cpp"
    "${DEEP2_DIR}/vulkan_compute.cpp"
    "${DEEP2_DIR}/QuantKernelRegistry.cpp"
    "${DEEP2_DIR}/Tokenizer.cpp"
    "${DEEP2_DIR}/Sampler.cpp"
)
target_include_directories(rawrxd-native-deep2-gguf-model-e2e-test PRIVATE
    "${DEEP2_DIR}"
    "${CMAKE_CURRENT_LIST_DIR}/../../src"
    "${CMAKE_CURRENT_LIST_DIR}/../../src/core"
    "${CMAKE_CURRENT_LIST_DIR}/../../include"
)
target_link_libraries(rawrxd-native-deep2-gguf-model-e2e-test PRIVATE
    Threads::Threads Vulkan::Vulkan
)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(rawrxd-native-deep2-gguf-model-e2e-test PRIVATE
        -O2 -ffunction-sections -fdata-sections -fno-omit-frame-pointer)
    target_link_options(rawrxd-native-deep2-gguf-model-e2e-test PRIVATE
        -Wl,--gc-sections)
endif()
