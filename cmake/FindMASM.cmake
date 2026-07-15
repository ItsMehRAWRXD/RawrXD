# FindMASM.cmake
# Phase 21: CMake Build System Integration
# 
# This module provides robust detection of the Microsoft Macro Assembler (MASM)
# for x64 assembly compilation. It searches standard Visual Studio installation
# paths and allows user overrides.
#
# Variables defined:
#   MASM_FOUND          - TRUE if ml64.exe was found
#   MASM_EXECUTABLE     - Full path to ml64.exe
#   MASM_VERSION        - Version string of ml64.exe (if detectable)
#
# Usage:
#   find_package(MASM REQUIRED)
#   enable_language(ASM_MASM)
#
# =============================================================================

include(FindPackageHandleStandardArgs)

# =============================================================================
# User-configurable paths (can be set via -DMASM_ROOT=...)
# =============================================================================
set(MASM_SEARCH_PATHS
    # Visual Studio 2022 (v17.x) - Enterprise, Professional, Community, BuildTools
    "C:/Program Files/Microsoft Visual Studio/2022/Enterprise/VC/Tools/MSVC"
    "C:/Program Files/Microsoft Visual Studio/2022/Professional/VC/Tools/MSVC"
    "C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC"
    "C:/Program Files/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC"
    
    # Visual Studio 2019 (v16.x)
    "C:/Program Files (x86)/Microsoft Visual Studio/2019/Enterprise/VC/Tools/MSVC"
    "C:/Program Files (x86)/Microsoft Visual Studio/2019/Professional/VC/Tools/MSVC"
    "C:/Program Files (x86)/Microsoft Visual Studio/2019/Community/VC/Tools/MSVC"
    "C:/Program Files (x86)/Microsoft Visual Studio/2019/BuildTools/VC/Tools/MSVC"
    
    # Visual Studio 2017 (v15.x)
    "C:/Program Files (x86)/Microsoft Visual Studio/2017/Enterprise/VC/Tools/MSVC"
    "C:/Program Files (x86)/Microsoft Visual Studio/2017/Professional/VC/Tools/MSVC"
    "C:/Program Files (x86)/Microsoft Visual Studio/2017/Community/VC/Tools/MSVC"
    "C:/Program Files (x86)/Microsoft Visual Studio/2017/BuildTools/VC/Tools/MSVC"
    
    # Standalone Build Tools
    "C:/BuildTools/VC/Tools/MSVC"
    "C:/VS/VC/Tools/MSVC"
    
    # User override
    "${MASM_ROOT}"
    "$ENV{MASM_ROOT}"
    "$ENV{VSINSTALLDIR}/VC/Tools/MSVC"
)

# =============================================================================
# Helper function to find ml64.exe in versioned subdirectories
# =============================================================================
function(_find_ml64_in_msvc_root msvc_root out_path)
    file(GLOB version_dirs "${msvc_root}/*" )
    list(SORT version_dirs)
    list(REVERSE version_dirs)  # Prefer newest version
    
    foreach(version_dir ${version_dirs})
        if(IS_DIRECTORY ${version_dir})
            set(ml64_path "${version_dir}/bin/Hostx64/x64/ml64.exe")
            if(EXISTS ${ml64_path})
                set(${out_path} ${ml64_path} PARENT_SCOPE)
                return()
            endif()
        endif()
    endforeach()
    
    set(${out_path} "" PARENT_SCOPE)
endfunction()

# =============================================================================
# Search for ml64.exe
# =============================================================================
set(MASM_EXECUTABLE "")

# First, check if user provided a direct path
if(DEFINED MASM_EXECUTABLE AND EXISTS "${MASM_EXECUTABLE}")
    # User override - use as-is
    message(STATUS "[FindMASM] Using user-provided MASM: ${MASM_EXECUTABLE}")
else()
    # Search in standard paths
    foreach(search_path ${MASM_SEARCH_PATHS})
        if(EXISTS ${search_path})
            _find_ml64_in_msvc_root(${search_path} found_ml64)
            if(found_ml64)
                set(MASM_EXECUTABLE ${found_ml64})
                message(STATUS "[FindMASM] Found MASM: ${MASM_EXECUTABLE}")
                break()
            endif()
        endif()
    endforeach()
endif()

# =============================================================================
# Try to detect version
# =============================================================================
if(MASM_EXECUTABLE)
    execute_process(
        COMMAND ${MASM_EXECUTABLE}
        ERROR_VARIABLE masm_output
        OUTPUT_QUIET
        ERROR_STRIP_TRAILING_WHITESPACE
    )
    
    # Parse version from output (e.g., "Microsoft (R) Macro Assembler (x64) Version 14.35.32215.1")
    if(masm_output MATCHES "Version ([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)")
        set(MASM_VERSION ${CMAKE_MATCH_1})
        message(STATUS "[FindMASM] MASM Version: ${MASM_VERSION}")
    else()
        set(MASM_VERSION "unknown")
    endif()
endif()

# =============================================================================
# Handle standard arguments
# =============================================================================
find_package_handle_standard_args(MASM
    REQUIRED_VARS MASM_EXECUTABLE
    VERSION_VAR MASM_VERSION
    FAIL_MESSAGE "MASM (ml64.exe) not found. Install Visual Studio Build Tools or set MASM_ROOT."
)

# =============================================================================
# Mark variables as advanced
# =============================================================================
mark_as_advanced(MASM_EXECUTABLE MASM_VERSION)

# =============================================================================
# Set up ASM_MASM compiler if found
# =============================================================================
if(MASM_FOUND)
    # Set the ASM_MASM compiler
    set(CMAKE_ASM_MASM_COMPILER ${MASM_EXECUTABLE} CACHE FILEPATH "MASM compiler" FORCE)
    
    # Set default flags
    set(CMAKE_ASM_MASM_FLAGS "/c /Zi /Zd" CACHE STRING "Default MASM flags" FORCE)
    
    message(STATUS "[FindMASM] ASM_MASM compiler configured: ${CMAKE_ASM_MASM_COMPILER}")
    message(STATUS "[FindMASM] ASM_MASM flags: ${CMAKE_ASM_MASM_FLAGS}")
endif()
