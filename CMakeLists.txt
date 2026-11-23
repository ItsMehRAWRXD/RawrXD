cmake_minimum_required(VERSION 3.15)
project(Deep2Engine LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build configuration
set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build")
set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "RelWithDebInfo" "MinSizeRel")

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

add_executable(Deep2Engine_Benchmark
    src/main.cpp
    src/Deep2Engine.cpp
    src/GGUFLoader.cpp
    src/TensorROM.cpp
    src/ShardPager.cpp
    src/quant_kernels.cpp
    src/MasmCoreKernels.cpp
    src/VulkanDevice.cpp
    src/VulkanDeviceAllocator.cpp
    src/VulkanStagingPipeline.cpp
)

add_executable(gguf2rom
    src/gguf2rom.cpp
)

add_executable(gguf2rom_ms
    src/gguf2rom_ms.cpp
)

add_executable(test_metadata_parity
    src/test_metadata_parity.cpp
    src/GGUFLoader.cpp
)

# Dependency-free GGUF metadata and loader regression.
add_executable(gguf_parser_regression
    tools/gguf_parser_regression.cpp
    src/GGUFLoader.cpp
)
target_include_directories(gguf_parser_regression PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

add_executable(reap_planner_regression tools/reap_planner_regression.cpp)
target_include_directories(reap_planner_regression PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

add_executable(rawrxd_reap_repack tools/reap_repack_cli.cpp)
target_include_directories(rawrxd_reap_repack PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

add_executable(reap_repacker_regression tools/reap_repacker_regression.cpp)
target_include_directories(reap_repacker_regression PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

add_executable(rawrxd_reap_blob tools/reap_blob_cli.cpp)
add_executable(rawrxd_reap_f16_audit tools/reap_f16_audit_cli.cpp)
add_executable(reap_f16_accuracy_regression tools/reap_f16_accuracy_regression.cpp)
add_executable(reap_f16_gguf_regression tools/reap_f16_gguf_regression.cpp)
add_executable(reap_float16_regression tools/reap_float16_regression.cpp)
add_executable(reap_blob_regression tools/reap_blob_regression.cpp)
add_executable(reap_sha256_regression tools/reap_sha256_regression.cpp)
target_include_directories(rawrxd_reap_blob PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_include_directories(rawrxd_reap_f16_audit PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_include_directories(reap_f16_accuracy_regression PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_include_directories(reap_f16_gguf_regression PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_include_directories(reap_float16_regression PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_include_directories(reap_blob_regression PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_include_directories(reap_sha256_regression PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
add_executable(reap_publisher_regression tools/reap_publisher_regression.cpp)
target_include_directories(reap_publisher_regression PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
find_package(Threads REQUIRED)
target_link_libraries(reap_publisher_regression PRIVATE Threads::Threads)

add_executable(reap_q8_0_regression tools/reap_q8_0_regression.cpp)
target_include_directories(reap_q8_0_regression PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
add_executable(reap_q4_0_regression tools/reap_q4_0_regression.cpp)
target_include_directories(reap_q4_0_regression PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
add_executable(reap_q5_to_q4_regression tools/reap_q5_to_q4_regression.cpp)
target_include_directories(reap_q5_to_q4_regression PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
add_executable(reap_q8_1_to_q4_regression tools/reap_q8_1_to_q4_regression.cpp)
target_include_directories(reap_q8_1_to_q4_regression PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
add_executable(reap_affine_q4_regression tools/reap_affine_q4_regression.cpp)
target_include_directories(reap_affine_q4_regression PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
add_executable(reap_float_to_q4_regression tools/reap_float_to_q4_regression.cpp)
target_include_directories(reap_float_to_q4_regression PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
add_executable(reap_string_array_regression tools/reap_string_array_regression.cpp)
target_include_directories(reap_string_array_regression PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
add_executable(reap_auto_singleton_regression tools/reap_auto_singleton_regression.cpp)
target_include_directories(reap_auto_singleton_regression PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
add_executable(reap_auto_regression tools/reap_auto_regression.cpp)
target_include_directories(reap_auto_regression PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
add_executable(reap_row_alignment_regression tools/reap_row_alignment_regression.cpp)
target_include_directories(reap_row_alignment_regression PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

add_executable(production_smoke_test
    src/tools/production_smoke_test.cpp
)

target_include_directories(Deep2Engine_Benchmark PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR}/src/core)
target_include_directories(gguf2rom_ms PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR}/src/core)
target_include_directories(test_metadata_parity PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_include_directories(production_smoke_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR}/src/core)

# Deploy GLSL compute shaders (SPIR-V) next to the executable for the Vulkan path.
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/shaders)
    file(GLOB SHADER_FILES "${CMAKE_CURRENT_SOURCE_DIR}/shaders/*")
    foreach(shader ${SHADER_FILES})
        get_filename_component(shaderName "${shader}" NAME)
        add_custom_command(TARGET Deep2Engine_Benchmark POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy "${shader}"
                     $<TARGET_FILE_DIR:Deep2Engine_Benchmark>/shaders/${shaderName}
            COMMENT "Deploying shader ${shaderName}")
    endforeach()
endif()

# Enable deep hardware optimization flags dynamically based on active toolchain mappings
if(MSVC)
    if(MSVC_VERSION GREATER_EQUAL 1910)
        target_compile_options(Deep2Engine_Benchmark PRIVATE 
            $<$<COMPILE_LANGUAGE:CXX>:/O2 /Oi /Ot /EHsc /W4 /permissive- /arch:AVX2>
        )
        message(STATUS "[BUILD] MSVC compiler target assigned to native AVX2 (256-bit YMM) for Zen 4 / 7800X3D.")
    else()
        target_compile_options(Deep2Engine_Benchmark PRIVATE 
            $<$<COMPILE_LANGUAGE:CXX>:/O2 /Oi /Ot /EHsc /W4 /arch:AVX2>
        )
        message(STATUS "[BUILD] Standard AVX2 micro-architectural fallbacks configured.")
    endif()
else()
    target_compile_options(Deep2Engine_Benchmark PRIVATE 
        $<$<COMPILE_LANGUAGE:CXX>:-O3 -Wall -Wextra -ffast-math -pthread>
    )
    include(CheckCXXCompilerFlag)
    CHECK_CXX_COMPILER_FLAG("-mavx512f" HAS_AVX512F)
    CHECK_CXX_COMPILER_FLAG("-mavx512bw" HAS_AVX512BW)
    CHECK_CXX_COMPILER_FLAG("-mavx512dq" HAS_AVX512DQ)
    if(HAS_AVX512F AND HAS_AVX512BW AND HAS_AVX512DQ)
        target_compile_options(Deep2Engine_Benchmark PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-mavx512f -mavx512bw -mavx512dq>)
        if(HAS_AVX512VNNI)
            target_compile_options(Deep2Engine_Benchmark PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-mavx512vnni>)
        endif()
        message(STATUS "[BUILD] GCC/Clang: AVX-512 vectorization enabled (F, BW, DQ, VNNI)")
    else()
        message(STATUS "[BUILD] GCC/Clang: AVX-512 not fully supported, using AVX2 fallback")
        target_compile_options(Deep2Engine_Benchmark PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-mavx2 -mfma>)
    endif()
endif()

# Vulkan linkage for multi-GPU support
find_package(Vulkan REQUIRED)
if(Vulkan_FOUND)
    target_include_directories(Deep2Engine_Benchmark PRIVATE ${Vulkan_INCLUDE_DIRS})
    message(STATUS "[BUILD] Bound hardware graphics layers to Vulkan libraries natively.")
endif()

# Link libraries
if(MSVC)
    target_link_libraries(Deep2Engine_Benchmark 
        PRIVATE Vulkan::Vulkan
        kernel32.lib user32.lib advapi32.lib
    )
    target_link_libraries(production_smoke_test
        PRIVATE Vulkan::Vulkan
        kernel32.lib user32.lib advapi32.lib
    )
elseif(UNIX AND NOT APPLE)
    target_link_libraries(Deep2Engine_Benchmark pthread dl Vulkan::Vulkan)
    target_link_libraries(production_smoke_test pthread dl Vulkan::Vulkan)
elseif(APPLE)
    target_link_libraries(Deep2Engine_Benchmark pthread dl Vulkan::Vulkan)
    target_link_libraries(production_smoke_test pthread dl Vulkan::Vulkan)
endif()

# Install target
install(TARGETS Deep2Engine_Benchmark DESTINATION bin)

# Enable testing
enable_testing()
add_test(NAME GGUF_Parser_Regression COMMAND gguf_parser_regression)
add_test(NAME REAP_Planner_Regression COMMAND reap_planner_regression)
add_test(NAME REAP_Repacker_Regression COMMAND reap_repacker_regression)
add_test(NAME REAP_Publisher_Regression COMMAND reap_publisher_regression)
add_test(NAME REAP_SHA256_Regression COMMAND reap_sha256_regression)
add_test(NAME REAP_Blob_Regression COMMAND reap_blob_regression)
add_test(NAME REAP_Float16_Regression COMMAND reap_float16_regression)
add_test(NAME REAP_F16_GGUF_Regression COMMAND reap_f16_gguf_regression)
add_test(NAME REAP_F16_Accuracy_Regression COMMAND reap_f16_accuracy_regression)
add_test(NAME REAP_Q8_0_Regression COMMAND reap_q8_0_regression)
add_test(NAME REAP_Q4_0_Regression COMMAND reap_q4_0_regression)
add_test(NAME REAP_Q5_0_To_Q4_0_Regression COMMAND reap_q5_to_q4_regression)
add_test(NAME REAP_Q8_1_To_Q4_0_Regression COMMAND reap_q8_1_to_q4_regression)
add_test(NAME REAP_Affine_Q4_Regression COMMAND reap_affine_q4_regression)
add_test(NAME REAP_Float_To_Q4_Regression COMMAND reap_float_to_q4_regression)
add_test(NAME REAP_String_Array_Regression COMMAND reap_string_array_regression)
add_test(NAME REAP_Auto_Singleton_Regression COMMAND reap_auto_singleton_regression)
add_test(NAME REAP_Auto_Regression COMMAND reap_auto_regression)
add_test(NAME REAP_Row_Alignment_Regression COMMAND reap_row_alignment_regression)
add_test(NAME Deep2Engine_SmokeTest
    COMMAND Deep2Engine_Benchmark --help
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)

add_test(NAME MetadataParity_Phi3
    COMMAND test_metadata_parity "G:/~dev/rawrxd/models/phi3-mini-Q2_K.gguf"
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
