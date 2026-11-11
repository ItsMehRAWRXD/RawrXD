# Minimal CMakeLists for VS Compatibility Validation - Dynamic Runtime (/MD /MDd)
# Only builds RawrXDCore DLL and VS Compat Tests

cmake_minimum_required(VERSION 3.20)

project(RawrXD_VSValidation_Dynamic VERSION 14.7.3 LANGUAGES C CXX ASM_MASM RC)

# Real source directory - use absolute path directly
set(RAWRXD_SOURCE_DIR "F:/rawrxd")

# Multi-config generator setup
if(NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_CONFIGURATION_TYPES "Debug;Release;RelWithDebInfo;MinSizeRel" CACHE STRING "Configs" FORCE)
endif()
set(CMAKE_VS_PLATFORM_NAME "x64" CACHE STRING "VS Platform" FORCE)
set(CMAKE_VS_PLATFORM_TOOLSET "v143" CACHE STRING "VS Toolset" FORCE)
set(CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION "10.0.26100.0" CACHE STRING "Windows SDK" FORCE)

# CMake policy CMP0091: Disable auto-generation of MSVC_RUNTIME_LIBRARY per-config values
# CMake 4.4 auto-generates invalid "MultiThreadedDLLDebug" from global "MultiThreadedDLL"
# Setting to OLD preserves manual per-config control
if(POLICY CMP0091)
    cmake_policy(SET CMP0091 OLD)
endif()

# Explicitly unset global to prevent CMake 4.4 auto-generation
set(CMAKE_MSVC_RUNTIME_LIBRARY "" CACHE STRING "MSVC Runtime (global - unset)" FORCE)

# MSVC Runtime Library Configuration - Explicitly set correct per-config values ONLY
# Do NOT set global CMAKE_MSVC_RUNTIME_LIBRARY to avoid CMake 4.4 auto-generation
# of invalid "MultiThreadedDLLDebug" (correct is "MultiThreadedDebugDLL")
# Correct values: MultiThreaded, MultiThreadedDebug, MultiThreadedDLL, MultiThreadedDebugDLL
set(CMAKE_MSVC_RUNTIME_LIBRARY_DEBUG "MultiThreadedDebugDLL" CACHE STRING "MSVC Runtime Debug" FORCE)
set(CMAKE_MSVC_RUNTIME_LIBRARY_RELEASE "MultiThreadedDLL" CACHE STRING "MSVC Runtime Release" FORCE)
set(CMAKE_MSVC_RUNTIME_LIBRARY_RELWITHDEBINFO "MultiThreadedDLL" CACHE STRING "MSVC Runtime RelWithDebInfo" FORCE)
set(CMAKE_MSVC_RUNTIME_LIBRARY_MINSIZEREL "MultiThreadedDLL" CACHE STRING "MSVC Runtime MinSizeRel" FORCE)

# Per-config output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin/Debug")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin/Release")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}/bin/RelWithDebInfo")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL "${CMAKE_BINARY_DIR}/bin/MinSizeRel")

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/lib/Debug")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/lib/Release")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}/lib/RelWithDebInfo")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_MINSIZEREL "${CMAKE_BINARY_DIR}/lib/MinSizeRel")

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/lib/Debug")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/lib/Release")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}/lib/RelWithDebInfo")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_MINSIZEREL "${CMAKE_BINARY_DIR}/lib/MinSizeRel")

# Compile options per configuration - use dynamic runtime /MDd for Debug, /MD for Release
set(CMAKE_CXX_FLAGS_DEBUG "/Od /Zi /RTC1 /MDd /DDEBUG /D_DEBUG" CACHE STRING "CXX Debug Flags" FORCE)
set(CMAKE_C_FLAGS_DEBUG "/Od /Zi /RTC1 /MDd /DDEBUG /D_DEBUG" CACHE STRING "C Debug Flags" FORCE)
set(CMAKE_ASM_MASM_FLAGS_DEBUG "/Zi /Zd" CACHE STRING "MASM Debug Flags" FORCE)

set(CMAKE_CXX_FLAGS_RELEASE "/O2 /Ob2 /Oi /Ot /GL /MD /DNDEBUG" CACHE STRING "CXX Release Flags" FORCE)
set(CMAKE_C_FLAGS_RELEASE "/O2 /Ob2 /Oi /Ot /GL /MD /DNDEBUG" CACHE STRING "C Release Flags" FORCE)
set(CMAKE_ASM_MASM_FLAGS_RELEASE "" CACHE STRING "MASM Release Flags" FORCE)

set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "/O2 /Ob2 /Oi /Ot /GL /MD /Zi /DNDEBUG" CACHE STRING "CXX RelWithDebInfo Flags" FORCE)
set(CMAKE_C_FLAGS_RELWITHDEBINFO "/O2 /Ob2 /Oi /Ot /GL /MD /Zi /DNDEBUG" CACHE STRING "C RelWithDebInfo Flags" FORCE)
set(CMAKE_ASM_MASM_FLAGS_RELWITHDEBINFO "/Zi /Zd" CACHE STRING "MASM RelWithDebInfo Flags" FORCE)

set(CMAKE_CXX_FLAGS_MINSIZEREL "/O1 /Ob1 /Oi /Os /GL /MD /DNDEBUG" CACHE STRING "CXX MinSizeRel Flags" FORCE)
set(CMAKE_C_FLAGS_MINSIZEREL "/O1 /Ob1 /Oi /Os /GL /MD /DNDEBUG" CACHE STRING "C MinSizeRel Flags" FORCE)
set(CMAKE_ASM_MASM_FLAGS_MINSIZEREL "" CACHE STRING "MASM MinSizeRel Flags" FORCE)

# Common compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /std:c++20 /EHsc /nologo /W3 /permissive- /FS" CACHE STRING "CXX Flags" FORCE)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /std:c17 /nologo /W3 /FS" CACHE STRING "C Flags" FORCE)

# Common preprocessor definitions
add_compile_definitions(
    _CRT_SECURE_NO_WARNINGS
    NOMINMAX
    WIN32_LEAN_AND_MEAN
    UNICODE
    _UNICODE
    RAWXD_BUILD
)

# Export compile commands
set(CMAKE_EXPORT_COMPILE_COMMANDS ON CACHE BOOL "Export compile_commands.json" FORCE)

# MASM64
if(RAWRXD_ENABLE_MASM AND MSVC)
    enable_language(ASM_MASM)
endif()

# RC
if(WIN32)
    enable_language(RC)
endif()

# nlohmann/json via FetchContent
include(FetchContent)
FetchContent_Declare(
    nlohmann_json
    URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(nlohmann_json)

# Vulkan
if(RAWRXD_ENABLE_VULKAN)
    find_package(Vulkan QUIET)
endif()

# Build RawrXDCore DLL - specify binary dir for out-of-tree source
add_subdirectory(${RAWRXD_SOURCE_DIR}/src/core/dll ${CMAKE_BINARY_DIR}/src/core/dll)

# Build Tests - specify binary dir for out-of-tree source
add_subdirectory(${RAWRXD_SOURCE_DIR}/tests ${CMAKE_BINARY_DIR}/tests)

# Summary
message(STATUS "")
message(STATUS "========================================")
message(STATUS "RawrXD VS Validation Configured (Dynamic CRT)")
message(STATUS "========================================")
message(STATUS "RawrXDCore DLL: ON")
message(STATUS "VS Compat Tests: ON")
message(STATUS "Vulkan: ${RAWRXD_ENABLE_VULKAN}")
message(STATUS "MASM64: ${RAWRXD_ENABLE_MASM}")
message(STATUS "Dynamic Libs: ${BUILD_SHARED_LIBS}")
message(STATUS "========================================")