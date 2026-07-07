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

# Find ml64.exe (Microsoft Macro Assembler for x64)
# Use explicit path from user memory
set(ML64_EXE "C:/VS2022Enterprise/VC/Tools/MSVC/14.50.35717/bin/Hostx64/x64/ml64.exe")

# Verify ml64.exe exists
if(NOT EXISTS "${ML64_EXE}")
    message(FATAL_ERROR "ml64.exe not found at ${ML64_EXE}. Please verify Visual Studio 2022 installation.")
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
add_masm_source(telemetry_masm_kernels masm/silu_activation_avx512.asm)
add_masm_source(telemetry_masm_kernels masm/rmsnorm_forward_avx2.asm)
add_masm_source(telemetry_masm_kernels masm/softmax_forward_avx2.asm)
add_masm_source(telemetry_masm_kernels masm/test_minimal.asm)
add_masm_source(telemetry_masm_kernels masm/silu_correct.asm)

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