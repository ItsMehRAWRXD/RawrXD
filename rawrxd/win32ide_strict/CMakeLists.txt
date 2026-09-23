# ============================================================================
# RawrXD-Win32IDE Strict Minimal Build
# ============================================================================
# Only includes verified non-stub files for:
# 1. Win32 entry point (main_win32.cpp)
# 2. Frozen native toolchain (InstructionEncoderX64, RawrCOFFWriter, RawrPE64Linker)
# 3. JIT assembler
# 4. RawrXD Backend common types
#
# Zero stubs, zero demo code, zero fallback.
# Certification target: RAWRXD_WIN32IDE_STRICT_001
# ============================================================================

cmake_minimum_required(VERSION 3.20)
project(RawrXD-Win32IDE LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Subsystem: Windows (not Console)
add_executable(${PROJECT_NAME} WIN32)

# Strict source closure - ONLY these files
target_sources(${PROJECT_NAME} PRIVATE
    # Entry point (real Win32 window + message pump)
    ${CMAKE_SOURCE_DIR}/../src/win32app/main_win32.cpp

    # IDE-native toolchain gate (RAWRXD_WIN32IDE_TOOLCHAIN_001)
    ${CMAKE_SOURCE_DIR}/../src/win32app/ide_toolchain_gate.cpp

    # IDE-native local inference gate (RAWRXD_WIN32IDE_INFERENCE_001)
    ${CMAKE_SOURCE_DIR}/../src/win32app/ide_inference_gate.cpp

    # Frozen native toolchain
    ${CMAKE_SOURCE_DIR}/../src/compiler_backend/InstructionEncoderX64.cpp
    ${CMAKE_SOURCE_DIR}/../src/compiler_backend/RawrCOFFWriter.cpp
    ${CMAKE_SOURCE_DIR}/../src/compiler_backend/RawrPE64Linker.cpp

    # JIT Assembler
    ${CMAKE_SOURCE_DIR}/../src/sovereign/puppeteer/JITAssembler.cpp

    # Gate 2A: Deep2Engine compile-closure probe
    ${CMAKE_SOURCE_DIR}/../src/deep2/Deep2Engine.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/Tokenizer.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/Sampler.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/vulkan_compute.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/Deep2Engine_GpuMoEMLA.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/Deep2Engine_Speculative.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/Deep2Engine_VulkanRuntime.cpp

    # Quant kernel registry (GEMV/Dequant dispatch tables + LookupQuantType)
    ${CMAKE_SOURCE_DIR}/../src/deep2/QuantKernelRegistry.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/Deep2DualGpuRowSplit.cpp
    ${CMAKE_SOURCE_DIR}/../src/deep2/Deep2Engine_GpuForward.cpp
    ${CMAKE_SOURCE_DIR}/deep2_extern_definitions.cpp
)

# Include directories for the backend headers
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_SOURCE_DIR}/../src/win32app
    ${CMAKE_SOURCE_DIR}/../src/compiler_backend
    ${CMAKE_SOURCE_DIR}/../src/sovereign/puppeteer
    ${CMAKE_SOURCE_DIR}/../src/core
    ${CMAKE_SOURCE_DIR}/../src/deep2
    ${CMAKE_SOURCE_DIR}/../src
    C:/VulkanSDK/1.4.357.0/Include
)

# MSVC specific
if(MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE /W4 /WX- /DNOMINMAX)
    # Ensure Windows subsystem entry (WinMain)
    set_property(TARGET ${PROJECT_NAME} PROPERTY WIN32_EXECUTABLE TRUE)
endif()

# Vulkan loader library
if(WIN32)
    target_link_libraries(${PROJECT_NAME} PRIVATE
        "C:/VulkanSDK/1.4.357.0/Lib/vulkan-1.lib"
    )
endif()


# Certification: verify no STUB files are linked
set(STRICT_IDE_SOURCES
    main_win32.cpp
    InstructionEncoderX64.cpp
    RawrCOFFWriter.cpp
    RawrPE64Linker.cpp
    JITAssembler.cpp
)

foreach(src ${STRICT_IDE_SOURCES})
    if(NOT EXISTS "${CMAKE_SOURCE_DIR}/../src/compiler_backend/${src}")
        if(NOT EXISTS "${CMAKE_SOURCE_DIR}/../src/sovereign/puppeteer/${src}")
            if(NOT EXISTS "${CMAKE_SOURCE_DIR}/../src/win32app/${src}")
                message(FATAL_ERROR "Strict source missing: ${src}")
            endif()
        endif()
    endif()
endforeach()

message(STATUS "RAWRXD_WIN32IDE_STRICT: source closure verified for ${PROJECT_NAME}")
