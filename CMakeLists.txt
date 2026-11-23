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

add_executable(gguf2rom src/gguf2rom.cpp)
add_executable(gguf2rom_ms src/gguf2rom_ms.cpp)
add_executable(test_metadata_parity src/test_metadata_parity.cpp src/GGUFLoader.cpp)
add_executable(production_smoke_test src/tools/production_smoke_test.cpp)

target_include_directories(Deep2Engine_Benchmark PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR}/src/core)
target_include_directories(gguf2rom_ms PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR}/src/core)
target_include_directories(test_metadata_parity PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_include_directories(production_smoke_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR}/src/core)

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

if(MSVC)
    if(MSVC_VERSION GREATER_EQUAL 1910)
        target_compile_options(Deep2Engine_Benchmark PRIVATE
            $<$<COMPILE_LANGUAGE:CXX>:/O2 /Oi /Ot /EHsc /W4 /permissive- /arch:AVX2>)
        message(STATUS "[BUILD] MSVC compiler target assigned to native AVX2.")
    else()
        target_compile_options(Deep2Engine_Benchmark PRIVATE
            $<$<COMPILE_LANGUAGE:CXX>:/O2 /Oi /Ot /EHsc /W4 /arch:AVX2>)
        message(STATUS "[BUILD] Standard MSVC AVX2 fallbacks configured.")
    endif()
else()
    target_compile_options(Deep2Engine_Benchmark PRIVATE
        $<$<COMPILE_LANGUAGE:CXX>:-O3 -Wall -Wextra -ffast-math -pthread>)
    include(CheckCXXCompilerFlag)
    CHECK_CXX_COMPILER_FLAG("-mavx512f" HAS_AVX512F)
    CHECK_CXX_COMPILER_FLAG("-mavx512bw" HAS_AVX512BW)
    CHECK_CXX_COMPILER_FLAG("-mavx512dq" HAS_AVX512DQ)
    if(HAS_AVX512F AND HAS_AVX512BW AND HAS_AVX512DQ)
        target_compile_options(Deep2Engine_Benchmark PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-mavx512f -mavx512bw -mavx512dq>)
        if(HAS_AVX512VNNI)
            target_compile_options(Deep2Engine_Benchmark PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-mavx512vnni>)
        endif()
        message(STATUS "[BUILD] GCC/Clang: AVX-512 vectorization enabled.")
    else()
        message(STATUS "[BUILD] GCC/Clang: AVX2 fallback.")
        target_compile_options(Deep2Engine_Benchmark PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-mavx2 -mfma>)
    endif()
endif()

find_package(Vulkan REQUIRED)
if(Vulkan_FOUND)
    target_include_directories(Deep2Engine_Benchmark PRIVATE ${Vulkan_INCLUDE_DIRS})
    message(STATUS "[BUILD] Vulkan libraries enabled.")
endif()

if(MSVC)
    target_link_libraries(Deep2Engine_Benchmark PRIVATE Vulkan::Vulkan kernel32.lib user32.lib advapi32.lib)
    target_link_libraries(production_smoke_test PRIVATE Vulkan::Vulkan kernel32.lib user32.lib advapi32.lib)
elseif(UNIX AND NOT APPLE)
    target_link_libraries(Deep2Engine_Benchmark pthread dl Vulkan::Vulkan)
    target_link_libraries(production_smoke_test pthread dl Vulkan::Vulkan)
elseif(APPLE)
    target_link_libraries(Deep2Engine_Benchmark pthread dl Vulkan::Vulkan)
    target_link_libraries(production_smoke_test pthread dl Vulkan::Vulkan)
endif()

install(TARGETS Deep2Engine_Benchmark DESTINATION bin)

enable_testing()
add_test(NAME Deep2Engine_SmokeTest COMMAND Deep2Engine_Benchmark --help WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
add_test(NAME MetadataParity_Phi3 COMMAND test_metadata_parity "G:/~dev/rawrxd/models/phi3-mini-Q2_K.gguf" WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

# Optional Qt6/zlib adapter smoke test. The core engine does not depend on
# either library; compile the production adapter whenever both are detected.
find_package(ZLIB QUIET)
find_package(Qt6 COMPONENTS Core QUIET)
if(ZLIB_FOUND AND Qt6_FOUND)
    add_library(rawrxd_qt_zlib_codec STATIC src/codec/compression.cpp)
    target_include_directories(rawrxd_qt_zlib_codec PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_compile_features(rawrxd_qt_zlib_codec PUBLIC cxx_std_17)
    target_link_libraries(rawrxd_qt_zlib_codec PUBLIC Qt6::Core ZLIB::ZLIB)

    add_executable(qt_zlib_codec_test tests/qt_zlib_codec_test.cpp)
    target_link_libraries(qt_zlib_codec_test PRIVATE rawrxd_qt_zlib_codec)
    add_test(NAME qt_zlib_codec_test COMMAND qt_zlib_codec_test)
    message(STATUS "[CODEC] Qt6 Core and ZLIB detected; zlib adapter test enabled")
else()
    message(STATUS "[CODEC] Qt6 Core or ZLIB missing; optional adapter test skipped")
endif()
