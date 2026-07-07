# Model Stack Integration Validation CMakeLists.txt
cmake_minimum_required(VERSION 3.20)

# Force Ninja generator to avoid Visual Studio SDK auto-detection
if(NOT CMAKE_GENERATOR)
    set(CMAKE_GENERATOR "Ninja" CACHE STRING "CMake generator" FORCE)
endif()

# Force Windows SDK version BEFORE project()
# This MUST run before project() because CMake's compiler test needs these paths.
# The environment on this machine has partial SDK installs:
#   10.0.22621.0 — has ucrt, shared, um includes BUT um/x64 libs are separate
#   10.0.26100.0 — has um/shared includes and um/x64 libs BUT no ucrt
# We combine them to form a complete toolchain.
if(WIN32 AND NOT DEFINED ENV{VSCMD_ARG_TGT_ARCH})
    # Not running inside a VS Developer Prompt — inject paths manually
    # Auto-detect Windows SDK: try D: first, fall back to C:
    if(EXISTS "D:/Program Files (x86)/Windows Kits/10")
        set(_WIN10_SDK_ROOT "D:/Program Files (x86)/Windows Kits/10")
    else()
        set(_WIN10_SDK_ROOT "C:/Program Files (x86)/Windows Kits/10")
    endif()
    set(_SDK_UCRT_VER "10.0.22621.0")    # Has ucrt
    
    # Force use of 22621.0 since 26100.0 is not registered properly for MSBuild
    set(_SDK_UM_VER "10.0.22621.0")
    
    # Fallback: if 10.0.26100.0 doesn't exist for um, try 10.0.22621.0 for everything
    if(NOT EXISTS "${_WIN10_SDK_ROOT}/Include/${_SDK_UM_VER}/um/windows.h")
        set(_SDK_UM_VER "${_SDK_UCRT_VER}")
    endif()
    if(NOT EXISTS "${_WIN10_SDK_ROOT}/Include/${_SDK_UCRT_VER}/ucrt")
        set(_SDK_UCRT_VER "${_SDK_UM_VER}")
    endif()

    # Auto-detect MSVC toolchain: try D: first, fall back to C:
    # Verify that cl.exe exists in the detected path before using it
    set(_MSVC_ROOT "")
    foreach(_MSVC_CANDIDATE_ROOT
        "C:/Program Files/Microsoft Visual Studio/18/Enterprise/VC/Tools/MSVC"
        "D:/VS2022Enterprise/VC/Tools/MSVC"
        "C:/VS2022Enterprise/VC/Tools/MSVC"
        "C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC"
        "C:/Program Files/Microsoft Visual Studio/2022/Enterprise/VC/Tools/MSVC"
        "C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC"
        "C:/Program Files (x86)/Microsoft Visual Studio/2022/Enterprise/VC/Tools/MSVC"
        "C:/Program Files (x86)/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC"
    )
        if(EXISTS "${_MSVC_CANDIDATE_ROOT}")
            file(GLOB _MSVC_VERSIONS RELATIVE "${_MSVC_CANDIDATE_ROOT}" "${_MSVC_CANDIDATE_ROOT}/*")
            list(SORT _MSVC_VERSIONS)
            list(REVERSE _MSVC_VERSIONS)
            foreach(_VER ${_MSVC_VERSIONS})
                if(EXISTS "${_MSVC_CANDIDATE_ROOT}/${_VER}/bin/Hostx64/x64/cl.exe")
                    set(_MSVC_ROOT "${_MSVC_CANDIDATE_ROOT}/${_VER}")
                    break()
                endif()
            endforeach()
            if(_MSVC_ROOT)
                break()
            endif()
        endif()
    endforeach()

    if(_MSVC_ROOT AND EXISTS "${_WIN10_SDK_ROOT}/Include/${_SDK_UCRT_VER}/ucrt")
        # SDK bin tools (rc.exe, mt.exe)
        set(_SDK_BIN "${_WIN10_SDK_ROOT}/bin/${_SDK_UCRT_VER}/x64")
        
        # Set environment variables for compiler/linker
        set(ENV{INCLUDE} "${_MSVC_ROOT}/include;${_WIN10_SDK_ROOT}/Include/${_SDK_UCRT_VER}/ucrt;${_WIN10_SDK_ROOT}/Include/${_SDK_UM_VER}/shared;${_WIN10_SDK_ROOT}/Include/${_SDK_UM_VER}/um")
        set(ENV{LIB} "${_MSVC_ROOT}/lib/x64;${_WIN10_SDK_ROOT}/Lib/${_SDK_UCRT_VER}/ucrt/x64;${_WIN10_SDK_ROOT}/Lib/${_SDK_UM_VER}/um/x64")
        set(ENV{PATH} "${_MSVC_ROOT}/bin/Hostx64/x64;${_SDK_BIN};$ENV{PATH}")
        
        set(CMAKE_C_COMPILER "${_MSVC_ROOT}/bin/Hostx64/x64/cl.exe" CACHE FILEPATH "C compiler" FORCE)
        set(CMAKE_CXX_COMPILER "${_MSVC_ROOT}/bin/Hostx64/x64/cl.exe" CACHE FILEPATH "C++ compiler" FORCE)
        set(CMAKE_LINKER "${_MSVC_ROOT}/bin/Hostx64/x64/link.exe" CACHE FILEPATH "Linker" FORCE)
        set(CMAKE_RC_COMPILER "${_SDK_BIN}/rc.exe" CACHE FILEPATH "Resource Compiler" FORCE)
        set(CMAKE_MT "${_SDK_BIN}/mt.exe" CACHE FILEPATH "Manifest Tool" FORCE)
        
        set(CMAKE_C_FLAGS "/DWIN32 /D_WINDOWS /W3 /utf-8" CACHE STRING "C flags" FORCE)
        set(CMAKE_CXX_FLAGS "/DWIN32 /D_WINDOWS /W3 /utf-8 /EHsc" CACHE STRING "C++ flags" FORCE)
        
        message(STATUS "[SDK Fix] Found MSVC with cl.exe at: ${_MSVC_ROOT}")
        message(STATUS "[SDK Fix] RC = ${_SDK_BIN}/rc.exe")
        message(STATUS "[SDK Fix] MT = ${_SDK_BIN}/mt.exe")
        message(STATUS "[SDK Fix] INCLUDE = $ENV{INCLUDE}")
        message(STATUS "[SDK Fix] LIB     = $ENV{LIB}")
    endif()
endif()

project(RawrXD_Validation)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# AVX-512 support
option(ENABLE_AVX512 "Enable AVX-512 instructions" ON)
if(ENABLE_AVX512)
    if(MSVC)
        add_compile_options(/arch:AVX512)
    else()
        add_compile_options(-mavx512f -mavx512dq -mavx512vl -mavx512bw)
    endif()
    add_compile_definitions(HAS_AVX512=1)
endif()

# Include directories - use target_include_directories with SYSTEM for standard headers
# Validation executables
# 1. Minimal validation (standalone - no RawrXD dependencies)
add_executable(model_stack_validation
    minimal_validation.cpp
)

# 2. Telemetry-enhanced validation (with profiling layer)
add_executable(telemetry_validation
    telemetry_validation.cpp
)

# Explicitly add MSVC and Windows SDK include directories
foreach(target model_stack_validation telemetry_validation)
    target_include_directories(${target} SYSTEM PRIVATE
        "${_MSVC_ROOT}/include"
        "${_WIN10_SDK_ROOT}/Include/${_SDK_UCRT_VER}/ucrt"
        "${_WIN10_SDK_ROOT}/Include/${_SDK_UM_VER}/shared"
        "${_WIN10_SDK_ROOT}/Include/${_SDK_UM_VER}/um"
    )
    
    # Explicitly add library directories
    target_link_directories(${target} PRIVATE
        "${_MSVC_ROOT}/lib/x64"
        "${_WIN10_SDK_ROOT}/Lib/${_SDK_UCRT_VER}/ucrt/x64"
        "${_WIN10_SDK_ROOT}/Lib/${_SDK_UM_VER}/um/x64"
    )
    
    # Link only Windows libraries (no RawrXD libraries)
    target_link_libraries(${target} PRIVATE
        kernel32
        user32
    )
    
    # Use static runtime to avoid DLL dependencies
    if(MSVC)
        set_property(TARGET ${target} PROPERTY
            MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
        )
    endif()
endforeach()

# Link telemetry_validation against MASM kernels
target_link_libraries(telemetry_validation PRIVATE telemetry_masm_kernels)
target_include_directories(telemetry_validation PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/kernels
)

# ============================================================================
# REAL MODEL VALIDATION - Link against pre-built RawrXD libraries
# ============================================================================

# Define the path to pre-compiled libraries
set(RAWRXD_BUILD_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../build-ninja")

# Check if libraries exist
if(EXISTS "${RAWRXD_BUILD_DIR}/RawrXD_Gold.lib")
    message(STATUS "Found RawrXD libraries at: ${RAWRXD_BUILD_DIR}")
    
    # Create factory exports library (provides C-compatible factory functions)
    add_library(engine_factory STATIC
        engine_factory_exports.cpp
    )
    
    target_include_directories(engine_factory PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/..
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
    )
    
    # Link factory against RawrXD libraries
    target_link_directories(engine_factory PRIVATE
        "${RAWRXD_BUILD_DIR}"
    )
    
    # Note: RawrXD_Gold is an executable, not a library, so we cannot link against it
    # We can only link against library targets
    # target_link_libraries(engine_factory PRIVATE
    #     RawrXD_Gold
    #     RawrXD-ModelAnalysisLib
    # )
    
    # Create real model validation executable
    add_executable(model_stack_validation_real
        model_validation_real.cpp
    )
    
    # Add include directories for RawrXD headers
    target_include_directories(model_stack_validation_real PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/..
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
        ${CMAKE_CURRENT_SOURCE_DIR}/kernels
    )
    
    # Add system includes
    target_include_directories(model_stack_validation_real SYSTEM PRIVATE
        "${_MSVC_ROOT}/include"
        "${_WIN10_SDK_ROOT}/Include/${_SDK_UCRT_VER}/ucrt"
        "${_WIN10_SDK_ROOT}/Include/${_SDK_UM_VER}/shared"
        "${_WIN10_SDK_ROOT}/Include/${_SDK_UM_VER}/um"
    )
    
    # Add library directories
    target_link_directories(model_stack_validation_real PRIVATE
        "${_MSVC_ROOT}/lib/x64"
        "${_WIN10_SDK_ROOT}/Lib/${_SDK_UCRT_VER}/ucrt/x64"
        "${_WIN10_SDK_ROOT}/Lib/${_SDK_UM_VER}/um/x64"
        "${RAWRXD_BUILD_DIR}"
    )
    
    # Link against RawrXD libraries and system libs
    target_link_libraries(model_stack_validation_real PRIVATE
        engine_factory
        # Note: RawrXD_Gold is an executable, not a library, so we cannot link against it
        # RawrXD_Gold
        # RawrXD-ModelAnalysisLib
        kernel32
        user32
        gdi32
        winspool
        comdlg32
        advapi32
        shell32
        ole32
        oleaut32
        uuid
        odbc32
        odbccp32
    )
    
    # Use static runtime
    if(MSVC)
        set_property(TARGET model_stack_validation_real PROPERTY
            MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
        )
    endif()
    
    # AVX-512 support
    if(ENABLE_AVX512)
        if(MSVC)
            target_compile_options(model_stack_validation_real PRIVATE /arch:AVX512)
        endif()
    endif()
    
    message(STATUS "Real model validation target: model_stack_validation_real")
else()
    message(WARNING "RawrXD libraries not found at ${RAWRXD_BUILD_DIR}")
    message(WARNING "Building only minimal validation (simulation mode)")
endif()

# ============================================================================
# A/B DIFFERENTIAL TEST RUNNER - Standalone kernel validation
# ============================================================================

add_executable(ab_test_runner
    ab_test_runner.cpp
)

# Add include directories
target_include_directories(ab_test_runner PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/kernels
)

# Add system includes
target_include_directories(ab_test_runner SYSTEM PRIVATE
    "${_MSVC_ROOT}/include"
    "${_WIN10_SDK_ROOT}/Include/${_SDK_UCRT_VER}/ucrt"
    "${_WIN10_SDK_ROOT}/Include/${_SDK_UM_VER}/shared"
    "${_WIN10_SDK_ROOT}/Include/${_SDK_UM_VER}/um"
)

# Add library directories
target_link_directories(ab_test_runner PRIVATE
    "${_MSVC_ROOT}/lib/x64"
    "${_WIN10_SDK_ROOT}/Lib/${_SDK_UCRT_VER}/ucrt/x64"
    "${_WIN10_SDK_ROOT}/Lib/${_SDK_UM_VER}/um/x64"
)

# Link MASM kernels and system libraries
target_link_libraries(ab_test_runner PRIVATE
    telemetry_masm_kernels
    kernel32
    user32
)

# Simple MASM linkage test
add_executable(test_masm_linkage
    test_masm_linkage.cpp
)

target_include_directories(test_masm_linkage PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/kernels
)

target_include_directories(test_masm_linkage SYSTEM PRIVATE
    "${_MSVC_ROOT}/include"
    "${_WIN10_SDK_ROOT}/Include/${_SDK_UCRT_VER}/ucrt"
    "${_WIN10_SDK_ROOT}/Include/${_SDK_UM_VER}/shared"
    "${_WIN10_SDK_ROOT}/Include/${_SDK_UM_VER}/um"
)

target_link_directories(test_masm_linkage PRIVATE
    "${_MSVC_ROOT}/lib/x64"
    "${_WIN10_SDK_ROOT}/Lib/${_SDK_UCRT_VER}/ucrt/x64"
    "${_WIN10_SDK_ROOT}/Lib/${_SDK_UM_VER}/um/x64"
)

target_link_libraries(test_masm_linkage PRIVATE
    telemetry_masm_kernels
    kernel32
    user32
)

# Use static runtime
if(MSVC)
    set_property(TARGET test_masm_linkage PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
    )
endif()

# Use static runtime
if(MSVC)
    set_property(TARGET ab_test_runner PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
    )
endif()

# AVX-512 support
if(ENABLE_AVX512)
    if(MSVC)
        target_compile_options(ab_test_runner PRIVATE /arch:AVX512)
    endif()
endif()

message(STATUS "A/B test runner target: ab_test_runner")

# Add MASM kernels subdirectory
add_subdirectory(kernels)

# Post-build: Generate test GGUF
add_custom_command(TARGET model_stack_validation POST_BUILD
    COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/minimal_gguf_generator.py ${CMAKE_CURRENT_BINARY_DIR}/test_model.gguf
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Generating minimal test GGUF file"
)

# Install
install(TARGETS model_stack_validation DESTINATION bin)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/test_model.gguf DESTINATION bin)