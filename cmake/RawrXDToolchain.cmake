# RawrXDToolchain.cmake
# Toolchain file for Visual Studio Developer Command Prompt parity
# 
# Usage:
#   cmake -DCMAKE_TOOLCHAIN_FILE=cmake/RawrXDToolchain.cmake -G "Visual Studio 17 2022" -A x64 ..
#   cmake --build . --config Release
#
# This replicates the environment setup that vcvars64.bat provides, allowing
# CMake to find the correct compiler, SDK, and libraries without requiring
# the developer to run from a VS Developer Command Prompt.

cmake_minimum_required(VERSION 3.20)

# =============================================================================
# Visual Studio Installation Detection
# =============================================================================

# Use vswhere to find VS installation
if(WIN32 AND NOT DEFINED ENV{VCToolsInstallDir})
    # Try to find vswhere - use common paths
    set(VSWHERE_PATH "$ENV{ProgramFiles}/Microsoft Visual Studio/Installer/vswhere.exe")
    if(NOT EXISTS "${VSWHERE_PATH}")
        # ProgramFiles(x86) on 64-bit systems
        set(VSWHERE_PATH "C:/Program Files (x86)/Microsoft Visual Studio/Installer/vswhere.exe")
    endif()
    message(STATUS "[Toolchain] VSWHERE_PATH: ${VSWHERE_PATH}")
    if(EXISTS "${VSWHERE_PATH}")
        execute_process(
            COMMAND "${VSWHERE_PATH}" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
            OUTPUT_VARIABLE VS_INSTALL_PATH
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET
        )
        if(VS_INSTALL_PATH)
            message(STATUS "[Toolchain] Found VS at: ${VS_INSTALL_PATH}")
        else()
            message(WARNING "[Toolchain] vswhere returned empty path")
        endif()
    else()
        message(WARNING "[Toolchain] vswhere.exe not found at ${VSWHERE_PATH}")
    endif()
    
    # Fallback paths
    if(NOT VS_INSTALL_PATH)
        set(VS_INSTALL_PATH "C:/Program Files (x86)/Microsoft Visual Studio/2022/Enterprise")
        if(NOT EXISTS "${VS_INSTALL_PATH}")
            set(VS_INSTALL_PATH "C:/Program Files (x86)/Microsoft Visual Studio/2022/Community")
        endif()
        if(NOT EXISTS "${VS_INSTALL_PATH}")
            set(VS_INSTALL_PATH "C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools")
        endif()
        if(NOT EXISTS "${VS_INSTALL_PATH}")
            set(VS_INSTALL_PATH "C:/Program Files/Microsoft Visual Studio/2022/BuildTools")
        endif()
        message(STATUS "[Toolchain] Using fallback VS path: ${VS_INSTALL_PATH}")
    endif()
endif()

# =============================================================================
# MSVC Toolchain Path Detection
# =============================================================================

if(WIN32)
    # Find MSVC toolchain version
    set(MSVC_TOOLS_BASE "${VS_INSTALL_PATH}/VC/Tools/MSVC")
    if(EXISTS "${MSVC_TOOLS_BASE}")
        file(GLOB MSVC_VERSIONS "${MSVC_TOOLS_BASE}/*")
        if(MSVC_VERSIONS)
            list(SORT MSVC_VERSIONS)
            list(GET MSVC_VERSIONS -1 MSVC_LATEST_VERSION)
            set(VC_TOOLS_INSTALL_DIR "${MSVC_LATEST_VERSION}")
            message(STATUS "[Toolchain] MSVC Tools: ${VC_TOOLS_INSTALL_DIR}")
        endif()
    endif()
    
    # Fallback to known version
    if(NOT VC_TOOLS_INSTALL_DIR)
        set(VC_TOOLS_INSTALL_DIR "C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC/14.44.35207")
    endif()
    
    # Verify cl.exe exists
    if(NOT EXISTS "${VC_TOOLS_INSTALL_DIR}/bin/Hostx64/x64/cl.exe")
        message(FATAL_ERROR "[Toolchain] cl.exe not found at ${VC_TOOLS_INSTALL_DIR}/bin/Hostx64/x64/cl.exe")
    endif()
    
    # Set compiler paths
    set(CMAKE_C_COMPILER "${VC_TOOLS_INSTALL_DIR}/bin/Hostx64/x64/cl.exe" CACHE FILEPATH "C Compiler" FORCE)
    set(CMAKE_CXX_COMPILER "${VC_TOOLS_INSTALL_DIR}/bin/Hostx64/x64/cl.exe" CACHE FILEPATH "C++ Compiler" FORCE)
    set(CMAKE_LINKER "${VC_TOOLS_INSTALL_DIR}/bin/Hostx64/x64/link.exe" CACHE FILEPATH "Linker" FORCE)
    set(CMAKE_ASM_MASM_COMPILER "${VC_TOOLS_INSTALL_DIR}/bin/Hostx64/x64/ml64.exe" CACHE FILEPATH "MASM64" FORCE)
    set(CMAKE_RC_COMPILER "rc.exe" CACHE FILEPATH "Resource Compiler" FORCE)
    
    # Set environment variables for the build
    set(ENV{VCToolsInstallDir} "${VC_TOOLS_INSTALL_DIR}")
    set(ENV{VCToolsVersion} "14.44")
    set(ENV{VCINSTALLDIR} "${VS_INSTALL_PATH}/VC/")
    set(ENV{VisualStudioVersion} "17.0")
    set(ENV{VSINSTALLDIR} "${VS_INSTALL_PATH}/")
    
    # Windows SDK Detection
    set(WIN10_SDK_BASE "C:/Program Files (x86)/Windows Kits/10")
    if(EXISTS "D:/Program Files (x86)/Windows Kits/10")
        set(WIN10_SDK_BASE "D:/Program Files (x86)/Windows Kits/10")
    endif()
    
    # Find latest SDK with ucrt
    file(GLOB SDK_VERSIONS "${WIN10_SDK_BASE}/Include/*")
    set(SELECTED_SDK_VER "")
    foreach(sdk_ver ${SDK_VERSIONS})
        get_filename_component(sdk_name ${sdk_ver} NAME)
        if(sdk_name MATCHES "^10\\.0\\.\\d+\\.\\d+$")
            if(EXISTS "${WIN10_SDK_BASE}/Include/${sdk_name}/ucrt")
                set(SELECTED_SDK_VER ${sdk_name})
            endif()
        endif()
    endforeach()
    
    if(NOT SELECTED_SDK_VER)
        # Fallback to known good versions
        if(EXISTS "${WIN10_SDK_BASE}/Include/10.0.26100.0/ucrt")
            set(SELECTED_SDK_VER "10.0.26100.0")
        elseif(EXISTS "${WIN10_SDK_BASE}/Include/10.0.22621.0/ucrt")
            set(SELECTED_SDK_VER "10.0.22621.0")
        else()
            list(SORT SDK_VERSIONS)
            list(GET SDK_VERSIONS -1 SELECTED_SDK_VER)
            get_filename_component(SELECTED_SDK_VER ${SELECTED_SDK_VER} NAME)
        endif()
    endif()
    
    set(ENV{WindowsSdkDir} "${WIN10_SDK_BASE}/")
    set(ENV{WindowsSDKVersion} "${SELECTED_SDK_VER}\\")
    set(ENV{UCRTVersion} "${SELECTED_SDK_VER}")
    
    message(STATUS "[Toolchain] Windows SDK: ${SELECTED_SDK_VER}")
    message(STATUS "[Toolchain] SDK Root: ${WIN10_SDK_BASE}")
    
    # Build INCLUDE path
    set(MSVC_INCLUDE "${VC_TOOLS_INSTALL_DIR}/include")
    set(UCRT_INCLUDE "${WIN10_SDK_BASE}/Include/${SELECTED_SDK_VER}/ucrt")
    set(SHARED_INCLUDE "${WIN10_SDK_BASE}/Include/${SELECTED_SDK_VER}/shared")
    set(UM_INCLUDE "${WIN10_SDK_BASE}/Include/${SELECTED_SDK_VER}/um")
    set(WINRT_INCLUDE "${WIN10_SDK_BASE}/Include/${SELECTED_SDK_VER}/winrt")
    
    set(ENV{INCLUDE} "${MSVC_INCLUDE};${UCRT_INCLUDE};${SHARED_INCLUDE};${UM_INCLUDE};${WINRT_INCLUDE}")
    
    # Build LIB path
    set(MSVC_LIB_X64 "${VC_TOOLS_INSTALL_DIR}/lib/x64")
    set(MSVC_LIB_ONECORE_X64 "${VC_TOOLS_INSTALL_DIR}/lib/onecore/x64")
    set(UCRT_LIB_X64 "${WIN10_SDK_BASE}/Lib/${SELECTED_SDK_VER}/ucrt/x64")
    set(UM_LIB_X64 "${WIN10_SDK_BASE}/Lib/${SELECTED_SDK_VER}/um/x64")
    
    set(ENV{LIB} "${MSVC_LIB_X64};${MSVC_LIB_ONECORE_X64};${UCRT_LIB_X64};${UM_LIB_X64}")
    
    # SDK bin tools (rc.exe, mt.exe)
    set(SDK_BIN_X64 "${WIN10_SDK_BASE}/bin/${SELECTED_SDK_VER}/x64")
    if(EXISTS "${SDK_BIN_X64}/rc.exe")
        set(CMAKE_RC_COMPILER "${SDK_BIN_X64}/rc.exe" CACHE FILEPATH "Resource Compiler" FORCE)
    endif()
    if(EXISTS "${SDK_BIN_X64}/mt.exe")
        set(CMAKE_MT "${SDK_BIN_X64}/mt.exe" CACHE FILEPATH "Manifest Tool" FORCE)
    endif()
    
    # Add to PATH
    set(ENV{PATH} "${VC_TOOLS_INSTALL_DIR}/bin/Hostx64/x64;${SDK_BIN_X64};$ENV{PATH}")
    
    # NMake support - only set if using NMake generator
    if(CMAKE_GENERATOR STREQUAL "NMake Makefiles" AND EXISTS "${VC_TOOLS_INSTALL_DIR}/bin/Hostx64/x64/nmake.exe")
        set(CMAKE_MAKE_PROGRAM "${VC_TOOLS_INSTALL_DIR}/bin/Hostx64/x64/nmake.exe" CACHE FILEPATH "NMake" FORCE)
    endif()
    
    message(STATUS "[Toolchain] INCLUDE = $ENV{INCLUDE}")
    message(STATUS "[Toolchain] LIB = $ENV{LIB}")
    message(STATUS "[Toolchain] PATH includes: ${VC_TOOLS_INSTALL_DIR}/bin/Hostx64/x64")
    message(STATUS "[Toolchain] PATH includes: ${SDK_BIN_X64}")
endif()

# =============================================================================
# Cross-compilation settings (if targeting ARM64, etc.)
# =============================================================================

# For ARM64 targets, uncomment and adjust:
# set(CMAKE_VS_PLATFORM_NAME "ARM64")
# set(CMAKE_C_COMPILER "${VC_TOOLS_INSTALL_DIR}/bin/Hostx64/arm64/cl.exe")
# set(CMAKE_CXX_COMPILER "${VC_TOOLS_INSTALL_DIR}/bin/Hostx64/arm64/cl.exe")
# set(CMAKE_LINKER "${VC_TOOLS_INSTALL_DIR}/bin/Hostx64/arm64/link.exe")
# set(CMAKE_ASM_MASM_COMPILER "${VC_TOOLS_INSTALL_DIR}/bin/Hostx64/arm64/ml64.exe")

# =============================================================================
# Force CMake to use our detected paths
# =============================================================================

# These must be set before project() call in the main CMakeLists.txt
# But since this is a toolchain file, they're set early enough

# Store for use in main CMakeLists.txt
set(RAWRXD_VC_TOOLS_INSTALL_DIR "${VC_TOOLS_INSTALL_DIR}" CACHE INTERNAL "")
set(RAWRXD_WIN10_SDK_BASE "${WIN10_SDK_BASE}" CACHE INTERNAL "")
set(RAWRXD_SELECTED_SDK_VER "${SELECTED_SDK_VER}" CACHE INTERNAL "")
set(RAWRXD_VS_INSTALL_PATH "${VS_INSTALL_PATH}" CACHE INTERNAL "")

message(STATUS "[Toolchain] RawrXD VS Developer Command Prompt parity configured")