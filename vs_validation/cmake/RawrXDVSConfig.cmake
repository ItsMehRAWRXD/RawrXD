# RawrXDVSConfig.cmake
# CMake configuration for generating Visual Studio solutions with full compatibility
# Supports: multi-config (Debug/Release/RelWithDebInfo/MinSizeRel), DLLs, static libs, 
# executables, MASM64, proper debugging, project dependencies

cmake_minimum_required(VERSION 3.20)

# =============================================================================
# VS Solution Generation Configuration
# =============================================================================

# Force multi-config generator for VS (enables Debug/Release/RelWithDebInfo/MinSizeRel)
if(NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_CONFIGURATION_TYPES "Debug;Release;RelWithDebInfo;MinSizeRel" CACHE STRING "Configs" FORCE)
endif()

# Default configuration order for VS
set(CMAKE_CONFIGURATION_TYPES "${CMAKE_CONFIGURATION_TYPES}" CACHE STRING "" FORCE)

# =============================================================================
# Platform and Toolset Configuration
# =============================================================================

# Set default platform to x64
if(NOT CMAKE_VS_PLATFORM_NAME)
    set(CMAKE_VS_PLATFORM_NAME "x64" CACHE STRING "VS Platform" FORCE)
endif()

# VS Toolset version (v143 = VS 2022)
if(NOT CMAKE_VS_PLATFORM_TOOLSET)
    set(CMAKE_VS_PLATFORM_TOOLSET "v143" CACHE STRING "VS Toolset" FORCE)
endif()

# Windows SDK version
if(NOT CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION)
    set(CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION "10.0.26100.0" CACHE STRING "Windows SDK" FORCE)
endif()

# =============================================================================
# Multi-config Build Type Handling
# =============================================================================

# For multi-config generators, CMAKE_BUILD_TYPE is ignored at configure time
# but we can set a default for single-config generators
if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
endif()

# Per-configuration output directories
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

# Per-configuration PDB names
set(CMAKE_PDB_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin/Debug")
set(CMAKE_PDB_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin/Release")

# =============================================================================
# MSVC Runtime Library Configuration (Critical for DLL/EXE compatibility)
# =============================================================================

# Use MultiThreadedDLL (/MD) for shared libraries and executables that link to DLLs
# Use MultiThreaded (/MT) for static libraries and standalone executables
# This is the KEY setting for VS compatibility

# Default for shared libraries and executables - set per-target instead of globally
# to avoid issues with test compiles (FindThreads, etc.)
# set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDLL" CACHE STRING "MSVC Runtime" FORCE)

# For static libraries, use static runtime
# (Individual targets can override with set_target_properties)

# =============================================================================
# Compile Options per Configuration
# =============================================================================

# Debug configuration
set(CMAKE_CXX_FLAGS_DEBUG "/Od /Zi /RTC1 /MDd /DDEBUG /D_DEBUG" CACHE STRING "CXX Debug Flags" FORCE)
set(CMAKE_C_FLAGS_DEBUG "/Od /Zi /RTC1 /MDd /DDEBUG /D_DEBUG" CACHE STRING "C Debug Flags" FORCE)
set(CMAKE_ASM_MASM_FLAGS_DEBUG "/Zi /Zd" CACHE STRING "MASM Debug Flags" FORCE)

# Release configuration
set(CMAKE_CXX_FLAGS_RELEASE "/O2 /Ob2 /Oi /Ot /GL /MD /DNDEBUG" CACHE STRING "CXX Release Flags" FORCE)
set(CMAKE_C_FLAGS_RELEASE "/O2 /Ob2 /Oi /Ot /GL /MD /DNDEBUG" CACHE STRING "C Release Flags" FORCE)
set(CMAKE_ASM_MASM_FLAGS_RELEASE "" CACHE STRING "MASM Release Flags" FORCE)

# RelWithDebInfo configuration
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "/O2 /Ob2 /Oi /Ot /GL /MD /Zi /DNDEBUG" CACHE STRING "CXX RelWithDebInfo Flags" FORCE)
set(CMAKE_C_FLAGS_RELWITHDEBINFO "/O2 /Ob2 /Oi /Ot /GL /MD /Zi /DNDEBUG" CACHE STRING "C RelWithDebInfo Flags" FORCE)
set(CMAKE_ASM_MASM_FLAGS_RELWITHDEBINFO "/Zi /Zd" CACHE STRING "MASM RelWithDebInfo Flags" FORCE)

# MinSizeRel configuration
set(CMAKE_CXX_FLAGS_MINSIZEREL "/O1 /Ob1 /Oi /Os /GL /MD /DNDEBUG" CACHE STRING "CXX MinSizeRel Flags" FORCE)
set(CMAKE_C_FLAGS_MINSIZEREL "/O1 /Ob1 /Oi /Os /GL /MD /DNDEBUG" CACHE STRING "C MinSizeRel Flags" FORCE)
set(CMAKE_ASM_MASM_FLAGS_MINSIZEREL "" CACHE STRING "MASM MinSizeRel Flags" FORCE)

# =============================================================================
# Linker Options per Configuration
# =============================================================================

# Debug linker flags
set(CMAKE_EXE_LINKER_FLAGS_DEBUG "/DEBUG /INCREMENTAL" CACHE STRING "Exe Debug Link Flags" FORCE)
set(CMAKE_SHARED_LINKER_FLAGS_DEBUG "/DEBUG /INCREMENTAL" CACHE STRING "Shared Debug Link Flags" FORCE)
set(CMAKE_MODULE_LINKER_FLAGS_DEBUG "/DEBUG /INCREMENTAL" CACHE STRING "Module Debug Link Flags" FORCE)

# Release linker flags
set(CMAKE_EXE_LINKER_FLAGS_RELEASE "/OPT:REF /OPT:ICF /LTCG" CACHE STRING "Exe Release Link Flags" FORCE)
set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "/OPT:REF /OPT:ICF /LTCG" CACHE STRING "Shared Release Link Flags" FORCE)
set(CMAKE_MODULE_LINKER_FLAGS_RELEASE "/OPT:REF /OPT:ICF /LTCG" CACHE STRING "Module Release Link Flags" FORCE)

# RelWithDebInfo linker flags
set(CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO "/OPT:REF /OPT:ICF /LTCG /DEBUG" CACHE STRING "Exe RelWithDebInfo Link Flags" FORCE)
set(CMAKE_SHARED_LINKER_FLAGS_RELWITHDEBINFO "/OPT:REF /OPT:ICF /LTCG /DEBUG" CACHE STRING "Shared RelWithDebInfo Link Flags" FORCE)
set(CMAKE_MODULE_LINKER_FLAGS_RELWITHDEBINFO "/OPT:REF /OPT:ICF /LTCG /DEBUG" CACHE STRING "Module RelWithDebInfo Link Flags" FORCE)

# MinSizeRel linker flags
set(CMAKE_EXE_LINKER_FLAGS_MINSIZEREL "/OPT:REF /OPT:ICF /LTCG" CACHE STRING "Exe MinSizeRel Link Flags" FORCE)
set(CMAKE_SHARED_LINKER_FLAGS_MINSIZEREL "/OPT:REF /OPT:ICF /LTCG" CACHE STRING "Shared MinSizeRel Link Flags" FORCE)
set(CMAKE_MODULE_LINKER_FLAGS_MINSIZEREL "/OPT:REF /OPT:ICF /LTCG" CACHE STRING "Module MinSizeRel Link Flags" FORCE)

# =============================================================================
# Common Compiler Flags (All Configurations)
# =============================================================================

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /std:c++20 /EHsc /nologo /W3 /permissive- /FS" CACHE STRING "CXX Flags" FORCE)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /std:c17 /nologo /W3 /FS" CACHE STRING "C Flags" FORCE)

# Common preprocessor definitions
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_compile_definitions(
    _CRT_SECURE_NO_WARNINGS
    NOMINMAX
    WIN32_LEAN_AND_MEAN
    UNICODE
    _UNICODE
    RAWXD_BUILD
)

# =============================================================================
# Export Compile Commands for clangd/IntelliSense
# =============================================================================

set(CMAKE_EXPORT_COMPILE_COMMANDS ON CACHE BOOL "Export compile_commands.json" FORCE)

# =============================================================================
# VS Solution/Project Generation Enhancements
# =============================================================================

# Enable folder organization in VS Solution Explorer
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

# Set default startup project (can be overridden per project)
# set(CMAKE_VS_STARTUP_PROJECT "RawrXD-Win32IDE")

# Solution-level settings
set(CMAKE_VS_SOLUTION_VERSION "17.0")

# =============================================================================
# MASM64 Support
# =============================================================================

if(MSVC)
    enable_language(ASM_MASM)
    set(CMAKE_ASM_MASM_COMPILER "ml64.exe")
    set(CMAKE_ASM_MASM_FLAGS "/c /nologo /W3 /I${CMAKE_SOURCE_DIR}/src/asm /I${CMAKE_SOURCE_DIR}/include")
    set(CMAKE_ASM_MASM_OBJECT_FORMAT "coff")
endif()

# =============================================================================
# RC (Resource Compiler) Support
# =============================================================================

if(WIN32)
    enable_language(RC)
    set(CMAKE_RC_COMPILER "rc.exe")
    set(CMAKE_RC_FLAGS "/nologo /I${CMAKE_SOURCE_DIR}/include /I${CMAKE_SOURCE_DIR}/src")
endif()

# =============================================================================
# Debugging Support
# =============================================================================

# Generate .pdb files for all configurations
set(CMAKE_DEBUG_POSTFIX "d")

# Ensure PDB files are generated for all build types
set(CMAKE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

# =============================================================================
# IntelliSense / clangd Support
# =============================================================================

# Generate compile_commands.json for each configuration
# For multi-config generators, this creates a merged file
# Individual config files can be generated with:
# cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -G "Visual Studio 17 2022" -A x64 ..

# =============================================================================
# Installation Configuration
# =============================================================================

set(CMAKE_INSTALL_PREFIX "${CMAKE_BINARY_DIR}/install" CACHE PATH "Install prefix")
set(CMAKE_INSTALL_BINDIR "bin")
set(CMAKE_INSTALL_LIBDIR "lib")
set(CMAKE_INSTALL_INCLUDEDIR "include")

# =============================================================================
# Testing Configuration
# =============================================================================

enable_testing()
include(CTest)

# =============================================================================
# CPack Configuration (Optional)
# =============================================================================

# set(CPACK_GENERATOR "ZIP")
# set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
# include(CPack)

# =============================================================================
# Helper Macros for VS Project Customization
# =============================================================================

# Macro to set VS-specific properties on a target
macro(rawrxd_vs_target_properties TARGET)
    # Organize in Solution Explorer folders
    set_target_properties(${TARGET} PROPERTIES
        FOLDER "RawrXD/${CMAKE_PROJECT_NAME}"
        VS_DEBUGGER_WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        VS_DEBUGGER_COMMAND_ARGUMENTS ""
        VS_DEBUGGER_ENVIRONMENT ""
    )
    
    # Per-configuration properties
    set_target_properties(${TARGET} PROPERTIES
        DEBUG_POSTFIX "d"
        VS_GLOBAL_ProjectIsGenerated "true"
    )
    
    # Apply property sheets if they exist
    if(EXISTS "${CMAKE_SOURCE_DIR}/cmake/RawrXD.Common.props")
        set_target_properties(${TARGET} PROPERTIES
            VS_GLOBAL_ImportProps "${CMAKE_SOURCE_DIR}/cmake/RawrXD.Common.props"
        )
    endif()
endmacro()

# Macro to configure a target as a DLL
macro(rawrxd_configure_dll TARGET)
    set_target_properties(${TARGET} PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        WINDOWS_EXPORT_ALL_SYMBOLS ON
        MSVC_RUNTIME_LIBRARY "MultiThreadedDLL\$<\$<CONFIG:Debug>:Debug>"
    )
    target_compile_definitions(${TARGET} PRIVATE ${TARGET}_EXPORTS)
    rawrxd_vs_target_properties(${TARGET})
endmacro()

# Macro to configure a target as a Static Library
macro(rawrxd_configure_static_lib TARGET)
    set_target_properties(${TARGET} PROPERTIES
        MSVC_RUNTIME_LIBRARY "MultiThreaded\$<\$<CONFIG:Debug>:Debug>"
    )
    rawrxd_vs_target_properties(${TARGET})
endmacro()

# Macro to configure a target as an Executable
macro(rawrxd_configure_executable TARGET)
    set_target_properties(${TARGET} PROPERTIES
        MSVC_RUNTIME_LIBRARY "MultiThreadedDLL\$<\$<CONFIG:Debug>:Debug>"
        RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin/Debug"
        RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin/Release"
        RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}/bin/RelWithDebInfo"
        RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL "${CMAKE_BINARY_DIR}/bin/MinSizeRel"
    )
    rawrxd_vs_target_properties(${TARGET})
endmacro()

# =============================================================================
# Project Dependency Management
# =============================================================================

# Function to add project dependencies with proper build order
function(rawrxd_add_dependencies TARGET)
    foreach(dep ${ARGN})
        if(TARGET ${dep})
            add_dependencies(${TARGET} ${dep})
            # Also ensure link dependency
            target_link_libraries(${TARGET} PUBLIC ${dep})
        else()
            message(WARNING "Dependency target '${dep}' not found for '${TARGET}'")
        endif()
    endforeach()
endfunction()

# =============================================================================
# Include Shared Library Support
# =============================================================================

include(${CMAKE_CURRENT_LIST_DIR}/RawrXDSharedLibrary.cmake)

message(STATUS "[RawrXD VS Config] Visual Studio multi-config setup complete")
message(STATUS "  Configurations: ${CMAKE_CONFIGURATION_TYPES}")
message(STATUS "  Platform: ${CMAKE_VS_PLATFORM_NAME}")
message(STATUS "  Toolset: ${CMAKE_VS_PLATFORM_TOOLSET}")
message(STATUS "  Windows SDK: ${CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION}")
message(STATUS "  Runtime: ${CMAKE_MSVC_RUNTIME_LIBRARY}")