cmake_minimum_required(VERSION 3.16)
project(Deep2Engine LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build configuration
set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build")
set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "RelWithDebInfo" "MinSizeRel")

# Vulkan support option
option(ENABLE_VULKAN "Enable Vulkan support" ON)

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Engine sources shared by every executable that links the inference core.
set(DEEP2_ENGINE_CORE_SOURCES
    src/Deep2Engine.cpp
    src/Deep2Engine_MultiGPU.cpp
    src/GGUFLoader.cpp
    src/TensorROM.cpp
    src/ShardPager.cpp
    src/quant_kernels.cpp
    src/MasmCoreKernels.cpp
    src/VulkanDevice.cpp
    src/VulkanDeviceAllocator.cpp
    src/VulkanStagingPipeline.cpp
    src/core/VulkanComputeEngine.cpp
    src/core/Tokenizer.cpp
    src/core/GgufTokenizer.cpp
    src/core/KVCache.cpp
    src/core/Sampling.cpp
    src/core/GenerationLoop.cpp
    src/core/InferenceEngine.cpp
)

add_executable(Deep2Engine_Benchmark
    src/main.cpp
    ${DEEP2_ENGINE_CORE_SOURCES}
)

# Multi-shard GGUF -> TensorROM converter.
add_executable(gguf2rom
    src/gguf2rom.cpp
)

# Multi-shard GGUF -> sharded TensorROM converter. It consumes the same ROM
# container layout as gguf2rom and the zero-copy loader, so it is built here
# to keep that layout from drifting again.
add_executable(gguf2rom_ms
    src/tools/gguf2rom_ms.cpp
)

# Real-token autoregressive oracle. Runs the paged ROM path end-to-end so a
# wrong quantized dequant surfaces immediately as garbage tokens.
add_executable(rom_audit
    src/inference_oracle.cpp
    ${DEEP2_ENGINE_CORE_SOURCES}
)

add_executable(test_metadata_parity
    src/test_metadata_parity.cpp
    src/GGUFLoader.cpp
)

# Standalone tokenizer check: encode/decode round-trip plus a golden token-id
# vector captured from the reference HuggingFace tokenizer.
add_executable(tokenizer_test
    src/tools/tokenizer_test.cpp
    src/core/GgufTokenizer.cpp
)

add_executable(production_smoke_test
    src/tools/production_smoke_test.cpp
    src/core/VulkanStagingPipeline.cpp
    src/core/VulkanComputeEngine.cpp
    src/core/VulkanGEMV.cpp
    src/core/MultiShardFlickerManager.cpp
    src/core/PrefetchQueue.cpp
    src/core/PerformanceProfiler.cpp
    src/core/HereticWeightModifier.cpp
    src/core/UniversalRunner.cpp
    src/GGUFLoader.cpp
    src/core/Tokenizer.cpp
    src/core/KVCache.cpp
    src/core/Sampling.cpp
    src/core/GenerationLoop.cpp
    src/core/InferenceEngine.cpp
)

target_include_directories(Deep2Engine_Benchmark PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR}/src/core)
target_include_directories(rom_audit PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR}/src/core)
target_include_directories(tokenizer_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR}/src/core)
target_include_directories(test_metadata_parity PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_include_directories(production_smoke_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR}/src/core)

# ggml's canonical type enum. QuantBlockTraits.hpp keys the block-layout
# traits on ggml_type so that the several differently-numbered GGMLType
# enums in this tree cannot be mixed up silently.
target_include_directories(Deep2Engine_Benchmark PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/ggml/include)
target_include_directories(rom_audit PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/ggml/include)
target_include_directories(production_smoke_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/ggml/include)

# Deploy GLSL compute shaders (SPIR-V) next to the executable for the Vulkan path.
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/shaders)
    file(GLOB SHADER_FILES "${CMAKE_CURRENT_SOURCE_DIR}/shaders/*")
    foreach(shader ${SHADER_FILES})
        get_filename_component(shaderName "${shader}" NAME)
        add_custom_command(TARGET Deep2Engine_Benchmark POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy "${shader}"
                     $<TARGET_FILE_DIR:Deep2Engine_Benchmark>/shaders/${shaderName}
            COMMENT "Deploying shader ${shaderName}")
        add_custom_command(TARGET rom_audit POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy "${shader}"
                     $<TARGET_FILE_DIR:rom_audit>/shaders/${shaderName}
            COMMENT "Deploying shader ${shaderName}")
    endforeach()
endif()

# Enable deep hardware optimization flags dynamically based on active toolchain mappings
if(MSVC)
    # Check if the host compiler version explicitly supports 512-bit vector processing arguments
    if(MSVC_VERSION GREATER_EQUAL 1910)
        target_compile_options(Deep2Engine_Benchmark PRIVATE
            $<$<CXX_COMPILER_ID:MSVC>:/O2 /Oi /Ot /EHsc /W4 /permissive- /arch:AVX2>
        )
        message(STATUS "[BUILD] MSVC compiler target assigned to native AVX2 (256-bit YMM) for Zen 4 / 7800X3D.")
    else()
        target_compile_options(Deep2Engine_Benchmark PRIVATE
            $<$<CXX_COMPILER_ID:MSVC>:/O2 /Oi /Ot /EHsc /W4 /arch:AVX2>
        )
        message(STATUS "[BUILD] Standard AVX2 micro-architectural fallbacks configured.")
    endif()
else()
    target_compile_options(Deep2Engine_Benchmark PRIVATE
        $<$<CXX_COMPILER_ID:GNU>:-O3 -Wall -Wextra -ffast-math -pthread>
    )
    # Check for native AVX-512 hardware compliance strings automatically under GCC/Clang
    include(CheckCXXCompilerFlag)
    CHECK_CXX_COMPILER_FLAG("-mavx512f" HAS_AVX512F)
    CHECK_CXX_COMPILER_FLAG("-mavx512bw" HAS_AVX512BW)
    CHECK_CXX_COMPILER_FLAG("-mavx512dq" HAS_AVX512DQ)
    CHECK_CXX_COMPILER_FLAG("-mavx512vnni" HAS_AVX512VNNI)
    if(HAS_AVX512F AND HAS_AVX512BW AND HAS_AVX512DQ)
        target_compile_options(Deep2Engine_Benchmark PRIVATE $<$<CXX_COMPILER_ID:GNU>:-mavx512f -mavx512bw -mavx512dq>)
        if(HAS_AVX512VNNI)
            target_compile_options(Deep2Engine_Benchmark PRIVATE $<$<CXX_COMPILER_ID:GNU>:-mavx512vnni>)
        endif()
        message(STATUS "[BUILD] GCC/Clang: AVX-512 vectorization enabled (F, BW, DQ, VNNI)")
    else()
        target_compile_options(Deep2Engine_Benchmark PRIVATE $<$<CXX_COMPILER_ID:GNU>:-mavx2 -mfma>)
        message(STATUS "[BUILD] GCC/Clang: AVX-512 not fully supported, using AVX2 fallback")
    endif()
endif()

# Vulkan linkage for multi-GPU support
if(ENABLE_VULKAN)
    find_package(Vulkan REQUIRED)
    if(Vulkan_FOUND)
        target_include_directories(Deep2Engine_Benchmark PRIVATE ${Vulkan_INCLUDE_DIRS})
        target_include_directories(rom_audit PRIVATE ${Vulkan_INCLUDE_DIRS})
        message(STATUS "[BUILD] Bound hardware graphics layers to Vulkan libraries natively.")
    endif()
endif()

# Link libraries
if(MSVC)
    target_link_libraries(Deep2Engine_Benchmark
        PRIVATE Vulkan::Vulkan
        kernel32 user32 advapi32
    )
    target_link_libraries(rom_audit
        PRIVATE Vulkan::Vulkan
        kernel32 user32 advapi32
    )
    target_link_libraries(production_smoke_test
        PRIVATE Vulkan::Vulkan
        kernel32 user32 advapi32
    )
elseif(UNIX AND NOT APPLE)
    target_link_libraries(Deep2Engine_Benchmark pthread dl Vulkan::Vulkan)
    target_link_libraries(rom_audit pthread dl Vulkan::Vulkan)
    target_link_libraries(production_smoke_test pthread dl Vulkan::Vulkan)
elseif(APPLE)
    target_link_libraries(Deep2Engine_Benchmark pthread dl Vulkan::Vulkan)
    target_link_libraries(rom_audit pthread dl Vulkan::Vulkan)
    target_link_libraries(production_smoke_test pthread dl Vulkan::Vulkan)
endif()

# Install target
install(TARGETS Deep2Engine_Benchmark DESTINATION bin)

# Enable testing
enable_testing()
add_test(NAME Deep2Engine_SmokeTest
    COMMAND Deep2Engine_Benchmark --help
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)

add_test(NAME MetadataParity_Phi3
    COMMAND test_metadata_parity "G:/~dev/rawrxd/models/phi3-mini-Q2_K.gguf"
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)

# Converts a GGUF to a ROM and runs the production validation suite against
# the result. The model path is machine specific; the test skips itself when
# the model is not present.
add_test(NAME ProductionSmokeTest
    COMMAND ${CMAKE_COMMAND}
        -DGGUF=G:/~dev/rawrxd/models/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf
        -DROM=${CMAKE_BINARY_DIR}/test-model.rom
        -DCONVERTER=$<TARGET_FILE:gguf2rom>
        -DSMOKE=$<TARGET_FILE:production_smoke_test>
        -DARCH=llama
        -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/run_production_smoke.cmake
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)

# The tokenizer must agree with the reference HuggingFace tokenizers.
add_test(NAME TokenizerRoundTrip_Phi3
    COMMAND tokenizer_test "G:/~dev/rawrxd/models/phi3-mini-Q2_K.gguf"
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
