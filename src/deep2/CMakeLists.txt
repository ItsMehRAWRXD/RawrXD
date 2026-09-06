cmake_minimum_required(VERSION 3.20)
project(Deep2EngineOptimization LANGUAGES CXX ASM_MASM)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(MASM_PATH "f:/~dev/RawrXD-production-lazy-init/src/masm/final-ide")

set(MASM_SOURCES
    "${MASM_PATH}/masm_core_transform_aes_ni.asm"
    "${MASM_PATH}/masm_transform_ring_buffer.asm"
    "${MASM_PATH}/masm_core_gemv_avx512.asm"
    "${MASM_PATH}/masm_7800x3d_unmethoded.asm"
    "${MASM_PATH}/masm_core_profiler.asm"
    "${MASM_PATH}/engineering_unreverse_core_extension.asm"
    "${MASM_PATH}/masm_host_zero_engineer.asm"
    "${MASM_PATH}/masm_dual_gpu_mirror.asm"
    "${MASM_PATH}/masm_nugenperf_hotpatch.asm"
    "${MASM_PATH}/masm_large_content_zero_overhead.asm"
    "${MASM_PATH}/masm_1m_context_core.asm"
    "${MASM_PATH}/avx512_tensor_quant.asm"
    "${MASM_PATH}/avx512_negative_scale.asm"
    "${MASM_PATH}/masm_kv_cache_multiplier.asm"
    "${MASM_PATH}/masm_smt_prefetch_kernel.asm"
    "f:/~dev/rawrxd/src/asm/StreamRingBufferToVramAperture_x64.asm"
)

set(CPP_LIB_SOURCES
    "f:/~dev/rawrxd/src/deep2/Deep2EngineExtensions.cpp"
)

# Check all MASM sources exist
foreach(src IN LISTS MASM_SOURCES)
    if(NOT EXISTS "${src}")
        message(FATAL_ERROR "Required MASM source missing: ${src}")
    endif()
endforeach()

add_library(Deep2EngineOpt STATIC ${MASM_SOURCES} ${CPP_LIB_SOURCES})
set_target_properties(Deep2EngineOpt PROPERTIES LINKER_LANGUAGE CXX)

target_compile_options(Deep2EngineOpt PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:$<$<CONFIG:Release>:/O2 /arch:AVX512 /LTCG /GL /DNDEBUG>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<CONFIG:Debug>:/Od /Zi /RTC1>>
    $<$<COMPILE_LANGUAGE:CXX>:/W4>
)

target_compile_options(Deep2EngineOpt PRIVATE
    $<$<COMPILE_LANGUAGE:ASM_MASM>:/nologo /Zi /W3>
)

target_compile_definitions(Deep2EngineOpt PRIVATE
    RAWRXD_BUILD_WIN32IDE=ON
    LOCAL_ONLY_001=1
    NOMINMAX
    WIN32_LEAN_AND_MEAN
)
target_include_directories(Deep2EngineOpt PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} "f:/~dev/rawrxd/src/deep2")

# Link Deep2EngineOpt against relevant Windows libraries for UI contamination
target_link_libraries(Deep2EngineOpt PRIVATE uxtheme.lib dwmapi.lib)

add_executable(master_test_suite "f:/~dev/rawrxd/src/deep2/main.cpp")
target_compile_definitions(master_test_suite PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
target_link_libraries(master_test_suite PRIVATE Deep2EngineOpt kernel32.lib user32.lib gdi32.lib dwmapi.lib d2d1.lib dwrite.lib pdh.lib advapi32.lib)

target_compile_options(master_test_suite PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:$<$<CONFIG:Release>:/O2 /arch:AVX512 /LTCG /GL /DNDEBUG>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<CONFIG:Debug>:/Od /Zi /RTC1>>
    $<$<COMPILE_LANGUAGE:CXX>:/W4>
)
target_link_options(master_test_suite PRIVATE
    $<$<CONFIG:Release>:/LTCG /OPT:REF /OPT:ICF>
)
