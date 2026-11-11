#=============================================================================
# RawrXD CMake MASM Integration Module
# Phase 21 - Production Hardening
# Version: 1.0.0
#=============================================================================
# Usage:
#   include(RawrXD_MASM)
#   rawrxd_add_masm_target(
#       TARGET MyKernel
#       SOURCES kernel1.asm kernel2.asm
#       ARCH x64
#       OPTIMIZE_LEVEL 3
#   )
#=============================================================================

cmake_minimum_required(VERSION 3.20)

#-----------------------------------------------------------------------------
# Detect MASM Assembler
#-----------------------------------------------------------------------------
function(rawrxd_detect_masm)
    set(MASM_FOUND FALSE PARENT_SCOPE)
    set(MASM_COMPILER "" PARENT_SCOPE)
    
    # Priority 1: Visual Studio bundled ml64.exe
    if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
        get_filename_component(MSVC_BIN_DIR ${CMAKE_CXX_COMPILER} DIRECTORY)
        get_filename_component(MSVC_ROOT ${MSVC_BIN_DIR} DIRECTORY)
        
        set(ML64_CANDIDATES
            "${MSVC_BIN_DIR}/ml64.exe"
            "${MSVC_ROOT}/bin/Hostx64/x64/ml64.exe"
            "${MSVC_ROOT}/bin/Hostx86/x64/ml64.exe"
            "${MSVC_BIN_DIR}/x64/ml64.exe"
        )
        
        foreach(candidate ${ML64_CANDIDATES})
            if(EXISTS ${candidate})
                set(MASM_COMPILER ${candidate} PARENT_SCOPE)
                set(MASM_FOUND TRUE PARENT_SCOPE)
                message(STATUS "[MASM] Found ml64.exe: ${candidate}")
                return()
            endif()
        endforeach()
    endif()
    
    # Priority 2: System PATH search
    find_program(ML64_EXE ml64.exe PATHS 
        "C:/Program Files/Microsoft Visual Studio/2022/*/VC/Tools/MSVC/*/bin/Hostx64/x64"
        "C:/Program Files (x86)/Microsoft Visual Studio/2019/*/VC/Tools/MSVC/*/bin/Hostx64/x64"
        "C:/BuildTools/VC/Tools/MSVC/*/bin/Hostx64/x64"
    )
    
    if(ML64_EXE)
        set(MASM_COMPILER ${ML64_EXE} PARENT_SCOPE)
        set(MASM_FOUND TRUE PARENT_SCOPE)
        message(STATUS "[MASM] Found ml64.exe in PATH: ${ML64_EXE}")
        return()
    endif()
    
    # Priority 3: Alternative assemblers
    find_program(UASM_EXE uasm.exe jwasm.exe)
    if(UASM_EXE)
        set(MASM_COMPILER ${UASM_EXE} PARENT_SCOPE)
        set(MASM_FOUND TRUE PARENT_SCOPE)
        set(MASM_IS_UASM TRUE PARENT_SCOPE)
        message(STATUS "[MASM] Found alternative assembler: ${UASM_EXE}")
        return()
    endif()
    
    message(WARNING "[MASM] ml64.exe not found. MASM targets will be skipped.")
    message(WARNING "[MASM] Install Visual Studio Build Tools with C++ workload.")
endfunction()

#-----------------------------------------------------------------------------
# MASM Compilation Flags
#-----------------------------------------------------------------------------
function(rawrxd_get_masm_flags ARCH OPT_LEVEL OUT_FLAGS)
    set(flags "")
    
    if(ARCH STREQUAL "x64")
        list(APPEND flags /c /Cx /W3 /nologo)
        list(APPEND flags /D_WIN64 /D_M_X64)
    elseif(ARCH STREQUAL "x86")
        list(APPEND flags /c /coff /W3 /nologo)
        list(APPEND flags /D_WIN32 /D_M_IX86)
    else()
        message(FATAL_ERROR "[MASM] Unsupported architecture: ${ARCH}")
    endif()
    
    if(OPT_LEVEL GREATER_EQUAL 3)
        list(APPEND flags /Zi)
    endif()
    
    list(APPEND flags /I"${CMAKE_CURRENT_SOURCE_DIR}")
    list(APPEND flags /I"${CMAKE_SOURCE_DIR}/src/include")
    list(APPEND flags /I"${CMAKE_SOURCE_DIR}/src/kernels")
    
    get_directory_property(COMPILE_DEFINITIONS COMPILE_DEFINITIONS)
    foreach(def ${COMPILE_DEFINITIONS})
        list(APPEND flags /D${def})
    endforeach()
    
    list(APPEND flags /DRAWRXD_KERNEL)
    list(APPEND flags /DASM_KERNEL)
    
    set(${OUT_FLAGS} ${flags} PARENT_SCOPE)
endfunction()

#-----------------------------------------------------------------------------
# Add MASM Source to Target
#-----------------------------------------------------------------------------
function(rawrxd_add_masm_sources TARGET_NAME)
    set(options OPTIONAL)
    set(oneValueArgs ARCH OPTIMIZE_LEVEL)
    set(multiValueArgs SOURCES)
    cmake_parse_arguments(MASM "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
    
    if(NOT MASM_ARCH)
        set(MASM_ARCH "x64")
    endif()
    if(NOT MASM_OPTIMIZE_LEVEL)
        set(MASM_OPTIMIZE_LEVEL 2)
    endif()
    
    rawrxd_detect_masm()
    
    if(NOT MASM_FOUND)
        message(WARNING "[MASM] Cannot add MASM sources to ${TARGET_NAME} - no assembler found")
        return()
    endif()
    
    rawrxd_get_masm_flags(${MASM_ARCH} ${MASM_OPTIMIZE_LEVEL} MASM_FLAGS)
    
    foreach(src ${MASM_SOURCES})
        get_filename_component(src_name ${src} NAME_WE)
        get_filename_component(src_abs ${src} ABSOLUTE)
        
        set(obj_file "${CMAKE_CURRENT_BINARY_DIR}/${src_name}.obj")
        set(lst_file "${CMAKE_CURRENT_BINARY_DIR}/${src_name}.lst")
        
        add_custom_command(
            OUTPUT ${obj_file}
            COMMAND ${MASM_COMPILER} ${MASM_FLAGS} /Fo"${obj_file}" /Fl"${lst_file}" "${src_abs}"
            DEPENDS ${src_abs}
            COMMENT "[MASM] Assembling ${src_name}.asm"
            VERBATIM
        )
        
        target_sources(${TARGET_NAME} PRIVATE ${obj_file})
        
        set_source_files_properties(${obj_file} 
            PROPERTIES 
                EXTERNAL_OBJECT TRUE
                GENERATED TRUE
        )
        
        message(STATUS "[MASM] Added ${src} -> ${obj_file}")
    endforeach()
    
    if(MSVC)
        target_link_options(${TARGET_NAME} PRIVATE /MACHINE:X64 /SUBSYSTEM:CONSOLE)
    endif()
endfunction()

#-----------------------------------------------------------------------------
# Standalone MASM Library Target
#-----------------------------------------------------------------------------
function(rawrxd_add_masm_library LIB_NAME)
    set(options STATIC SHARED)
    set(oneValueArgs ARCH OPTIMIZE_LEVEL OUTPUT_DIR)
    set(multiValueArgs SOURCES LINK_LIBRARIES)
    cmake_parse_arguments(MASM_LIB "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
    
    if(NOT MASM_LIB_ARCH)
        set(MASM_LIB_ARCH "x64")
    endif()
    if(NOT MASM_LIB_OPTIMIZE_LEVEL)
        set(MASM_LIB_OPTIMIZE_LEVEL 2)
    endif()
    
    rawrxd_detect_masm()
    
    if(NOT MASM_FOUND)
        message(FATAL_ERROR "[MASM] Cannot build library ${LIB_NAME} - no assembler found")
    endif()
    
    rawrxd_get_masm_flags(${MASM_LIB_ARCH} ${MASM_LIB_OPTIMIZE_LEVEL} MASM_FLAGS)
    
    set(all_objects)
    
    foreach(src ${MASM_LIB_SOURCES})
        get_filename_component(src_name ${src} NAME_WE)
        get_filename_component(src_abs ${src} ABSOLUTE)
        
        set(obj_file "${CMAKE_CURRENT_BINARY_DIR}/${src_name}.obj")
        set(lst_file "${CMAKE_CURRENT_BINARY_DIR}/${src_name}.lst")
        
        add_custom_command(
            OUTPUT ${obj_file}
            COMMAND ${MASM_COMPILER} ${MASM_FLAGS} /Fo"${obj_file}" /Fl"${lst_file}" "${src_abs}"
            DEPENDS ${src_abs}
            COMMENT "[MASM] Assembling ${src_name}.asm for ${LIB_NAME}"
            VERBATIM
        )
        
        list(APPEND all_objects ${obj_file})
    endforeach()
    
    add_library(${LIB_NAME} OBJECT ${all_objects})
    set_target_properties(${LIB_NAME} PROPERTIES LINKER_LANGUAGE CXX)
    
    if(MASM_LIB_LINK_LIBRARIES)
        target_link_libraries(${LIB_NAME} ${MASM_LIB_LINK_LIBRARIES})
    endif()
    
    message(STATUS "[MASM] Created library ${LIB_NAME}")
endfunction()

#-----------------------------------------------------------------------------
# Build-Time Validation: Shadow Run
#-----------------------------------------------------------------------------
function(rawrxd_add_masm_test TEST_NAME ASM_SOURCE)
    set(oneValueArgs EXPECTED_CYCLES TOLERANCE ARCH)
    cmake_parse_arguments(TEST "" "${oneValueArgs}" "" ${ARGN})
    
    if(NOT TEST_ARCH)
        set(TEST_ARCH "x64")
    endif()
    if(NOT TEST_TOLERANCE)
        set(TEST_TOLERANCE 5.0)
    endif()
    
    get_filename_component(src_name ${ASM_SOURCE} NAME_WE)
    set(test_src "${CMAKE_CURRENT_BINARY_DIR}/${src_name}_test.cpp")
    
    file(WRITE ${test_src} "#include <windows.h>\n#include <iostream>\n#include <cstdint>\nextern \"C\" {\n    void __cdecl ApplyLoRA_Fixed(void* o, const void* i, const void* w, int r, int c, float a);\n}\nint main() {\n    const int N = 4096;\n    const size_t SZ = N * N * sizeof(float);\n    float* inp = (float*)_aligned_malloc(SZ, 64);\n    float* wgt = (float*)_aligned_malloc(SZ, 64);\n    float* out = (float*)_aligned_malloc(SZ, 64);\n    for(int i=0;i<N*N;i++){inp[i]=1.0f;wgt[i]=0.01f;}\n    ApplyLoRA_Fixed(out, inp, wgt, N, N, 1.0f);\n    LARGE_INTEGER f,s,e;\n    QueryPerformanceFrequency(&f);\n    QueryPerformanceCounter(&s);\n    for(int i=0;i<100;i++) ApplyLoRA_Fixed(out,inp,wgt,N,N,1.0f);\n    QueryPerformanceCounter(&e);\n    double us = ((double)(e.QuadPart-s.QuadPart)*1e6)/f.QuadPart/100.0;\n    std::cout << \"AVG_US: \" << us << std::endl;\n    _aligned_free(inp);_aligned_free(wgt);_aligned_free(out);\n    return (us < 50.0) ? 0 : 1;\n}")
    
    add_executable(${TEST_NAME} ${test_src})
    rawrxd_add_masm_sources(${TEST_NAME} SOURCES ${ASM_SOURCE} ARCH ${TEST_ARCH} OPTIMIZE_LEVEL 3)
    
    if(MSVC)
        target_compile_options(${TEST_NAME} PRIVATE /O2 /arch:AVX2)
    endif()
    
    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
    set_tests_properties(${TEST_NAME} PROPERTIES TIMEOUT 30 LABELS "masm;performance;kernel")
    message(STATUS "[MASM] Added build-time test: ${TEST_NAME}")
endfunction()

message(STATUS "[MASM] RawrXD MASM Integration Module loaded")
