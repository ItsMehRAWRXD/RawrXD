# ============================================================================
# MASM Kernels Build Configuration
# ============================================================================
# Builds AVX-512 optimized assembly kernels for RawrXD inference engine.
#
# Requirements:
#   - ml64.exe (Microsoft Macro Assembler for x64)
#   - Visual Studio 2019+ or Windows SDK 10.0.22621.0+
#   - AVX-512 capable CPU for runtime (optional for build)
#
# Output:
#   - masm_kernels.lib (static library)
#   - silu_activation_avx512.obj
#   - rmsnorm_forward_avx512.obj (future)
#   - q4_0_dequantize_avx512.obj (future)
#   - q8_0_dequantize_avx512.obj (future)
# ============================================================================

cmake_minimum_required(VERSION 3.20)

# ============================================================================
# MASM Assembler Detection
# ============================================================================

# Find ml64.exe (Microsoft Macro Assembler for x64).
# Never hardcode a machine-specific VS/MSVC version path — GitHub-hosted
# runners (and local installs) move between VS 2022/18 and MSVC 14.50/14.51+.
if(CMAKE_ASM_MASM_COMPILER AND EXISTS "${CMAKE_ASM_MASM_COMPILER}")
    set(ML64_EXE "${CMAKE_ASM_MASM_COMPILER}")
endif()

if(NOT ML64_EXE)
    find_program(ML64_EXE NAMES ml64.exe)
endif()

if(NOT ML64_EXE AND DEFINED ENV{VCToolsInstallDir})
    file(TO_CMAKE_PATH "$ENV{VCToolsInstallDir}" _VCTOOLS_DIR)
    if(EXISTS "${_VCTOOLS_DIR}/bin/Hostx64/x64/ml64.exe")
        set(ML64_EXE "${_VCTOOLS_DIR}/bin/Hostx64/x64/ml64.exe")
    endif()
endif()

if(NOT ML64_EXE AND DEFINED _MSVC_ROOT AND EXISTS "${_MSVC_ROOT}/bin/Hostx64/x64/ml64.exe")
    set(ML64_EXE "${_MSVC_ROOT}/bin/Hostx64/x64/ml64.exe")
endif()

if(NOT ML64_EXE OR NOT EXISTS "${ML64_EXE}")
    message(WARNING "[MASM] ml64.exe not found (CMAKE_ASM_MASM_COMPILER='${CMAKE_ASM_MASM_COMPILER}'). Skipping telemetry_masm_kernels.")
    return()
endif()

message(STATUS "[MASM] Found ml64.exe: ${ML64_EXE}")

# ============================================================================
# MASM Compilation Function
# ============================================================================

function(add_masm_source target_name asm_file)
    # Get the object file name
    get_filename_component(asm_name ${asm_file} NAME_WE)
    set(obj_file "${CMAKE_CURRENT_BINARY_DIR}/${asm_name}.obj")
    
    # Get the directory containing the .asm file
    get_filename_component(asm_dir ${asm_file} DIRECTORY)
    
    # Compile .asm to .obj
    add_custom_command(
        OUTPUT ${obj_file}
        COMMAND ${ML64_EXE}
            /c                           # Compile only, no link
            /W3                          # Warning level 3
            /nologo                      # No logo
            /Zi                          # Debug information
            /Fl                          # Generate listing file
            /Fo ${obj_file}              # Output object file
            ${CMAKE_CURRENT_SOURCE_DIR}/${asm_file}
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${asm_file}
        COMMENT "[MASM] Assembling ${asm_file} -> ${obj_file}"
        VERBATIM
    )
    
    # Add the object file to the target
    target_sources(${target_name} PRIVATE ${obj_file})
    
    # Add include directory for headers
    target_include_directories(${target_name} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/..
    )
endfunction()

# ============================================================================
# MASM Kernels Library
# ============================================================================

# Note: Using different name to avoid conflict with main project's masm_kernels target
add_library(telemetry_masm_kernels STATIC)

# Add dummy C++ file to force CMake to use C++ linker
target_sources(telemetry_masm_kernels PRIVATE masm_kernels_dummy.cpp)

# Add MASM source files
# add_masm_source(telemetry_masm_kernels masm/silu_activation_avx512.asm)  # Old kernel (has errors)
# add_masm_source(telemetry_masm_kernels masm/silu_activation_avx512_fixed.asm)  # Superseded by v2
add_masm_source(telemetry_masm_kernels masm/silu_activation_avx512_fixed_v2.asm)  # Production kernel with FAST_EXP2
add_masm_source(telemetry_masm_kernels masm/rmsnorm_forward_avx2.asm)
# add_masm_source(telemetry_masm_kernels masm/softmax_forward_avx2.asm)  # Has undefined symbols
add_masm_source(telemetry_masm_kernels masm/test_minimal.asm)
add_masm_source(telemetry_masm_kernels masm/silu_correct.asm)
add_masm_source(telemetry_masm_kernels masm/rmsnorm_fixed.asm)
add_masm_source(telemetry_masm_kernels masm/rmsnorm_tiled.asm)
add_masm_source(telemetry_masm_kernels masm/softmax_fixed.asm)
add_masm_source(telemetry_masm_kernels masm/silu_clamped.asm)
add_masm_source(telemetry_masm_kernels masm/abi_integrity_test.asm)
add_masm_source(telemetry_masm_kernels masm/abi_integrity_simple.asm)
add_masm_source(telemetry_masm_kernels masm/q4_0_dequant.asm)
add_masm_source(telemetry_masm_kernels masm/q4_0_dequant_optimized.asm)
add_masm_source(telemetry_masm_kernels masm/RawrXD_TreeAttention_Kernel.asm)
add_masm_source(telemetry_masm_kernels masm/tree_attention_masm_val038.asm)  # VAL-038.1 MASM mechanical translation

# Add C++ wrapper files (if any)
# target_sources(telemetry_masm_kernels PRIVATE kernels/masm_kernels_wrapper.cpp)

# Include directories
target_include_directories(telemetry_masm_kernels PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/..
)

# Link libraries (if needed)
target_link_libraries(telemetry_masm_kernels PRIVATE
    kernel32
    user32
)

# ============================================================================
# MASM Kernels Test Executable
# ============================================================================

add_executable(masm_kernels_test
    masm_kernels_simple_test.cpp
)

target_link_libraries(masm_kernels_test PRIVATE
    telemetry_masm_kernels
)

target_include_directories(masm_kernels_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/..
)

# Add MSVC and Windows SDK include directories (inherited from parent)
if(DEFINED _MSVC_ROOT AND DEFINED _WIN10_SDK_ROOT)
    target_include_directories(masm_kernels_test SYSTEM PRIVATE
        "${_MSVC_ROOT}/include"
        "${_WIN10_SDK_ROOT}/Include/${_SDK_UCRT_VER}/ucrt"
        "${_WIN10_SDK_ROOT}/Include/${_SDK_UM_VER}/shared"
        "${_WIN10_SDK_ROOT}/Include/${_SDK_UM_VER}/um"
    )
    
    target_link_directories(masm_kernels_test PRIVATE
        "${_MSVC_ROOT}/lib/x64"
        "${_WIN10_SDK_ROOT}/Lib/${_SDK_UCRT_VER}/ucrt/x64"
        "${_WIN10_SDK_ROOT}/Lib/${_SDK_UM_VER}/um/x64"
    )
endif()

# Use static runtime to avoid DLL dependencies
if(MSVC)
    set_property(TARGET masm_kernels_test PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
    )
endif()

# ============================================================================
# Integration with Validation Harness
# ============================================================================

# If building as part of validation harness, link telemetry_masm_kernels
if(TARGET telemetry_validation)
    target_link_libraries(telemetry_validation PRIVATE telemetry_masm_kernels)
    target_include_directories(telemetry_validation PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
    )
endif()

# ============================================================================
# Installation
# ============================================================================

install(TARGETS telemetry_masm_kernels
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

install(FILES
    kernels/masm_kernels.hpp
    DESTINATION include
)

# ============================================================================
# Build Information
# ============================================================================

message(STATUS "[MASM] Configuration:")
message(STATUS "  Assembler: ${ML64_EXE}")
message(STATUS "  Output: masm_kernels.lib")
message(STATUS "  Sources:")
message(STATUS "    - silu_activation_avx512.asm")
message(STATUS "  Targets:")
message(STATUS "    - masm_kernels (static library)")
message(STATUS "    - masm_kernels_test (test executable)")