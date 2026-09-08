# VWA consumer gates after B3 (IOCP). Additive fragment.
# VWA does not grow residency/GPU authority here.

if(NOT WIN32 OR NOT MSVC)
    return()
endif()

set(_VWA_ELASTIC_SRCS
    ${CMAKE_SOURCE_DIR}/src/deep2/ElasticResidencyManager.cpp
    ${CMAKE_SOURCE_DIR}/src/deep2/GhostCache.cpp
    ${CMAKE_SOURCE_DIR}/src/deep2/VwaCertTraceStub.cpp)

set(_VWA_GPU_DMA_SRCS
    ${CMAKE_SOURCE_DIR}/src/deep2/VwaGpuDma_Session.cpp
    ${CMAKE_SOURCE_DIR}/src/deep2/VwaGpuDma.cpp)

function(rawrxd_link_vwa_gpu_dma name)
    target_sources(${name} PRIVATE ${_VWA_GPU_DMA_SRCS})
    if(RAWR_VULKAN_INCLUDE)
        target_include_directories(${name} PRIVATE ${RAWR_VULKAN_INCLUDE})
    endif()
    if(RAWR_VULKAN_LIB)
        target_link_libraries(${name} PRIVATE ${RAWR_VULKAN_LIB})
    endif()
    target_compile_definitions(${name} PRIVATE RAWR_HAS_VULKAN=1)
endfunction()

function(rawrxd_add_vwa_elastic_cert name src)
    option(BUILD_${name} "Build ${name}" ON)
    if(NOT BUILD_${name})
        return()
    endif()
    add_executable(${name} ${src} ${_VWA_ELASTIC_SRCS})
    target_include_directories(${name} PRIVATE ${CMAKE_SOURCE_DIR}/src/deep2)
    target_compile_options(${name} PRIVATE
        $<$<NOT:$<CONFIG:Debug>>:/O2> /EHsc /W4 /std:c++20 /Gy)
    target_link_libraries(${name} PRIVATE kernel32)
    set_target_properties(${name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
        OUTPUT_NAME ${name}
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    message(STATUS "[Deep2] VWA consumer: ${name}")
endfunction()

function(rawrxd_add_vwa_header_cert name src)
    option(BUILD_${name} "Build ${name}" ON)
    if(NOT BUILD_${name})
        return()
    endif()
    add_executable(${name} ${src})
    target_include_directories(${name} PRIVATE ${CMAKE_SOURCE_DIR}/src/deep2)
    target_compile_options(${name} PRIVATE
        $<$<NOT:$<CONFIG:Debug>>:/O2> /EHsc /W4 /std:c++20)
    set_target_properties(${name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
        OUTPUT_NAME ${name}
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    message(STATUS "[Deep2] VWA consumer: ${name}")
endfunction()

function(rawrxd_add_c1c9_cert name src)
    option(BUILD_${name} "Build ${name}" ON)
    if(NOT BUILD_${name})
        return()
    endif()
    add_executable(${name} ${src})
    target_include_directories(${name} PRIVATE ${CMAKE_SOURCE_DIR}/src/deep2)
    target_compile_options(${name} PRIVATE
        $<$<NOT:$<CONFIG:Debug>>:/O2> /EHsc /W4 /std:c++20)
    if(TARGET deep2_c1_c9)
        target_link_libraries(${name} PRIVATE deep2_c1_c9)
    endif()
    if(TARGET deep2_vwa_range_core)
        target_link_libraries(${name} PRIVATE deep2_vwa_range_core)
    endif()
    target_link_libraries(${name} PRIVATE kernel32)
    set_target_properties(${name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
        OUTPUT_NAME ${name}
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    message(STATUS "[Deep2] C-ladder consumer: ${name}")
endfunction()

rawrxd_add_vwa_elastic_cert(deep2_vwa_elastic_range_001
    ${CMAKE_SOURCE_DIR}/src/deep2/deep2_vwa_elastic_range_001.cpp)
if(TARGET deep2_vwa_elastic_range_001 AND TARGET deep2_vwa_range_core)
    target_link_libraries(deep2_vwa_elastic_range_001 PRIVATE deep2_vwa_range_core)
endif()

rawrxd_add_vwa_elastic_cert(deep2_vwa_elastic_lease_001
    ${CMAKE_SOURCE_DIR}/src/deep2/deep2_vwa_elastic_lease_001.cpp)
if(TARGET deep2_vwa_elastic_lease_001 AND TARGET deep2_vwa_range_core)
    target_link_libraries(deep2_vwa_elastic_lease_001 PRIVATE deep2_vwa_range_core)
endif()

rawrxd_add_vwa_elastic_cert(deep2_vwa_gpu_stage_001
    ${CMAKE_SOURCE_DIR}/src/deep2/deep2_vwa_gpu_stage_001.cpp)
if(TARGET deep2_vwa_gpu_stage_001 AND TARGET deep2_vwa_range_core)
    target_link_libraries(deep2_vwa_gpu_stage_001 PRIVATE deep2_vwa_range_core)
endif()
if(TARGET deep2_vwa_gpu_stage_001)
    rawrxd_link_vwa_gpu_dma(deep2_vwa_gpu_stage_001)
endif()

rawrxd_add_vwa_header_cert(deep2_vwa_gpu_transfer_parity_001
    ${CMAKE_SOURCE_DIR}/src/deep2/deep2_vwa_gpu_transfer_parity_001.cpp)
if(TARGET deep2_vwa_gpu_transfer_parity_001)
    rawrxd_link_vwa_gpu_dma(deep2_vwa_gpu_transfer_parity_001)
endif()

rawrxd_add_vwa_header_cert(deep2_vwa_expert_slice_001
    ${CMAKE_SOURCE_DIR}/src/deep2/deep2_vwa_expert_slice_001.cpp)

rawrxd_add_c1c9_cert(deep2_vwa_moe_prefetch_001
    ${CMAKE_SOURCE_DIR}/src/deep2/deep2_vwa_moe_prefetch_001.cpp)
rawrxd_add_c1c9_cert(deep2_vwa_bounded_k2_001
    ${CMAKE_SOURCE_DIR}/src/deep2/deep2_vwa_bounded_k2_001.cpp)
if(TARGET deep2_vwa_bounded_k2_001 AND TARGET InferenceEngine)
    target_link_libraries(deep2_vwa_bounded_k2_001 PRIVATE InferenceEngine dxgi)
    target_include_directories(deep2_vwa_bounded_k2_001 PRIVATE
        ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/include)
endif()
rawrxd_add_c1c9_cert(deep2_k2_logits_range_sweep_001
    ${CMAKE_SOURCE_DIR}/src/deep2/deep2_k2_logits_range_sweep_001.cpp)
rawrxd_add_c1c9_cert(deep2_k2_logits_range_freeze_001
    ${CMAKE_SOURCE_DIR}/src/deep2/deep2_k2_logits_range_freeze_001.cpp)
rawrxd_add_c1c9_cert(deep2_vwa_async_file_range_001
    ${CMAKE_SOURCE_DIR}/src/deep2/deep2_vwa_async_file_range_001.cpp)
rawrxd_add_c1c9_cert(deep2_vwa_gpu_transfer_001
    ${CMAKE_SOURCE_DIR}/src/deep2/deep2_vwa_gpu_transfer_001.cpp)
if(TARGET deep2_vwa_gpu_transfer_001)
    rawrxd_link_vwa_gpu_dma(deep2_vwa_gpu_transfer_001)
endif()
rawrxd_add_c1c9_cert(deep2_vwa_k2_expert_selective_001
    ${CMAKE_SOURCE_DIR}/src/deep2/deep2_vwa_k2_expert_selective_001.cpp)
rawrxd_add_c1c9_cert(deep2_vwa_k2_prefetch_overlap_001
    ${CMAKE_SOURCE_DIR}/src/deep2/deep2_vwa_k2_prefetch_overlap_001.cpp)
rawrxd_add_c1c9_cert(deep2_vwa_k2_full_e2e_001
    ${CMAKE_SOURCE_DIR}/src/deep2/deep2_vwa_k2_full_e2e_001.cpp)
