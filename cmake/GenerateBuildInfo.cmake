# GenerateBuildInfo.cmake
# Generates build information header at compile time
#
# Usage:
#   include(GenerateBuildInfo)
#   rawrxd_generate_build_info()

find_package(Git QUIET)

function(rawrxd_generate_build_info)
    set(options)
    set(oneValueArgs OUTPUT_DIR)
    set(multiValueArgs)
    
    cmake_parse_arguments(ARG "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
    
    if(NOT ARG_OUTPUT_DIR)
        set(ARG_OUTPUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
    endif()
    
    set(GENERATED_DIR "${ARG_OUTPUT_DIR}")
    file(MAKE_DIRECTORY ${GENERATED_DIR})
    
    # Gather build info
    set(RAWRXD_BUILD_VERSION "${PROJECT_VERSION}")
    
    # Git information
    if(GIT_FOUND)
        execute_process(
            COMMAND ${GIT_EXECUTABLE} rev-parse --short HEAD
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            OUTPUT_VARIABLE RAWRXD_GIT_COMMIT
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET
        )
        execute_process(
            COMMAND ${GIT_EXECUTABLE} rev-parse --abbrev-ref HEAD
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            OUTPUT_VARIABLE RAWRXD_GIT_BRANCH
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET
        )
    else()
        set(RAWRXD_GIT_COMMIT "unknown")
        set(RAWRXD_GIT_BRANCH "unknown")
    endif()
    
    # Build timestamp
    string(TIMESTAMP RAWRXD_BUILD_DATE "%Y-%m-%d")
    string(TIMESTAMP RAWRXD_BUILD_TIME "%H:%M:%S")
    
    # Compiler info
    if(MSVC)
        set(RAWRXD_COMPILER "MSVC")
        set(RAWRXD_COMPILER_VERSION "${MSVC_VERSION}")
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        set(RAWRXD_COMPILER "GCC")
        set(RAWRXD_COMPILER_VERSION "${CMAKE_CXX_COMPILER_VERSION}")
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        set(RAWRXD_COMPILER "Clang")
        set(RAWRXD_COMPILER_VERSION "${CMAKE_CXX_COMPILER_VERSION}")
    else()
        set(RAWRXD_COMPILER "${CMAKE_CXX_COMPILER_ID}")
        set(RAWRXD_COMPILER_VERSION "${CMAKE_CXX_COMPILER_VERSION}")
    endif()
    
    # Build type
    set(RAWRXD_BUILD_TYPE "${CMAKE_BUILD_TYPE}")
    if(NOT RAWRXD_BUILD_TYPE)
        set(RAWRXD_BUILD_TYPE "Unknown")
    endif()
    
    # Platform
    if(WIN32)
        set(RAWRXD_TARGET_PLATFORM "Windows")
    elseif(APPLE)
        set(RAWRXD_TARGET_PLATFORM "macOS")
    elseif(UNIX)
        set(RAWRXD_TARGET_PLATFORM "Linux")
    else()
        set(RAWRXD_TARGET_PLATFORM "Unknown")
    endif()
    
    # Architecture
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64|x86_64|x64")
        set(RAWRXD_TARGET_ARCH "x64")
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "ARM64|aarch64")
        set(RAWRXD_TARGET_ARCH "ARM64")
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "i386|i686|x86")
        set(RAWRXD_TARGET_ARCH "x86")
    else()
        set(RAWRXD_TARGET_ARCH "${CMAKE_SYSTEM_PROCESSOR}")
    endif()
    
    # Feature flags
    if(RAWRXD_ENABLE_VULKAN)
        set(RAWRXD_HAS_VULKAN 1)
    else()
        set(RAWRXD_HAS_VULKAN 0)
    endif()
    
    if(RAWRXD_ENABLE_CUDA)
        set(RAWRXD_HAS_CUDA 1)
    else()
        set(RAWRXD_HAS_CUDA 0)
    endif()
    
    if(RAWRXD_ENABLE_ROCM)
        set(RAWRXD_HAS_ROCM 1)
    else()
        set(RAWRXD_HAS_ROCM 0)
    endif()
    
    if(RAWRXD_ENABLE_OPENCL)
        set(RAWRXD_HAS_OPENCL 1)
    else()
        set(RAWRXD_HAS_OPENCL 0)
    endif()
    
    if(RAWRXD_ENABLE_METAL)
        set(RAWRXD_HAS_METAL 1)
    else()
        set(RAWRXD_HAS_METAL 0)
    endif()
    
    if(RAWRXD_ENABLE_MASM)
        set(RAWRXD_HAS_MASM 1)
    else()
        set(RAWRXD_HAS_MASM 0)
    endif()
    
    if(RAWRXD_ENABLE_AVX512)
        set(RAWRXD_HAS_AVX512 1)
    else()
        set(RAWRXD_HAS_AVX512 0)
    endif()
    
    if(RAWRXD_ENABLE_AMX)
        set(RAWRXD_HAS_AMX 1)
    else()
        set(RAWRXD_HAS_AMX 0)
    endif()
    
    # Generate header file
    set(BUILD_INFO_H "${GENERATED_DIR}/rawrxd_build_info_generated.h")
    
    file(WRITE ${BUILD_INFO_H} "/* Auto-generated build info header - DO NOT EDIT */\n")
    file(APPEND ${BUILD_INFO_H} "#pragma once\n\n")
    
    file(APPEND ${BUILD_INFO_H} "#define RAWRXD_BUILD_VERSION \"${RAWRXD_BUILD_VERSION}\"\n")
    file(APPEND ${BUILD_INFO_H} "#define RAWRXD_GIT_COMMIT \"${RAWRXD_GIT_COMMIT}\"\n")
    file(APPEND ${BUILD_INFO_H} "#define RAWRXD_GIT_BRANCH \"${RAWRXD_GIT_BRANCH}\"\n")
    file(APPEND ${BUILD_INFO_H} "#define RAWRXD_BUILD_DATE \"${RAWRXD_BUILD_DATE}\"\n")
    file(APPEND ${BUILD_INFO_H} "#define RAWRXD_BUILD_TIME \"${RAWRXD_BUILD_TIME}\"\n")
    file(APPEND ${BUILD_INFO_H} "#define RAWRXD_COMPILER \"${RAWRXD_COMPILER}\"\n")
    file(APPEND ${BUILD_INFO_H} "#define RAWRXD_COMPILER_VERSION \"${RAWRXD_COMPILER_VERSION}\"\n")
    file(APPEND ${BUILD_INFO_H} "#define RAWRXD_BUILD_TYPE \"${RAWRXD_BUILD_TYPE}\"\n")
    file(APPEND ${BUILD_INFO_H} "#define RAWRXD_TARGET_PLATFORM \"${RAWRXD_TARGET_PLATFORM}\"\n")
    file(APPEND ${BUILD_INFO_H} "#define RAWRXD_TARGET_ARCH \"${RAWRXD_TARGET_ARCH}\"\n")
    file(APPEND ${BUILD_INFO_H} "\n")
    file(APPEND ${BUILD_INFO_H} "#define RAWRXD_HAS_VULKAN ${RAWRXD_HAS_VULKAN}\n")
    file(APPEND ${BUILD_INFO_H} "#define RAWRXD_HAS_CUDA ${RAWRXD_HAS_CUDA}\n")
    file(APPEND ${BUILD_INFO_H} "#define RAWRXD_HAS_ROCM ${RAWRXD_HAS_ROCM}\n")
    file(APPEND ${BUILD_INFO_H} "#define RAWRXD_HAS_OPENCL ${RAWRXD_HAS_OPENCL}\n")
    file(APPEND ${BUILD_INFO_H} "#define RAWRXD_HAS_METAL ${RAWRXD_HAS_METAL}\n")
    file(APPEND ${BUILD_INFO_H} "#define RAWRXD_HAS_MASM ${RAWRXD_HAS_MASM}\n")
    file(APPEND ${BUILD_INFO_H} "#define RAWRXD_HAS_AVX512 ${RAWRXD_HAS_AVX512}\n")
    file(APPEND ${BUILD_INFO_H} "#define RAWRXD_HAS_AMX ${RAWRXD_HAS_AMX}\n")
    
    message(STATUS "Generated build info: ${BUILD_INFO_H}")
    
    # Add include directory
    include_directories(${GENERATED_DIR})
    
    # Create a custom target to regenerate on each build
    add_custom_target(rawrxd_build_info
        COMMAND ${CMAKE_COMMAND} -E echo "Build info: ${RAWRXD_BUILD_VERSION} (${RAWRXD_GIT_COMMIT})"
        COMMENT "RawrXD Build Info: ${RAWRXD_BUILD_VERSION}"
    )
endfunction()
