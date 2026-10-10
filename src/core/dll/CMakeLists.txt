# RawrXDCore DLL - Shared Library Build
# Demonstrates full VS compatibility with DLL export/import

cmake_minimum_required(VERSION 3.20)

# Ensure RAWRXD_SOURCE_DIR is defined (for out-of-tree builds)
if(NOT DEFINED RAWRXD_SOURCE_DIR)
    set(RAWRXD_SOURCE_DIR "${CMAKE_SOURCE_DIR}")
endif()

# Include shared library support
include(${RAWRXD_SOURCE_DIR}/cmake/RawrXDSharedLibrary.cmake)

# The production inference engine: the certified 300-operation Deep2 IR executor.
# RAWRXD_MODELGENIE_PRODUCTION_RUNTIME_001 - one implementation shared by the
# standalone verification harness and this DLL. src/deep2/Deep2Engine.cpp is
# intentionally NOT built (unverified, non-IR path).
include(${RAWRXD_SOURCE_DIR}/cmake/ModelGenieRuntime.cmake)

# Determine library type: use shared when BUILD_SHARED_LIBS=ON, unless explicitly STATIC_ONLY
set(RAWRXD_CORE_STATIC_ONLY FALSE)
if(NOT BUILD_SHARED_LIBS)
    set(RAWRXD_CORE_STATIC_ONLY TRUE)
endif()

# Create the library target
# Inference is served exclusively by the ModelGenie IR executor
# (ModelGenieRuntime, linked below). Deep2InferenceAdapter.cpp and
# cpu_inference_engine.cpp are deliberately excluded: both depend on
# src/deep2/Deep2Engine.cpp, which is intentionally NOT built here
# (unverified, non-IR path).
if(RAWRXD_CORE_STATIC_ONLY)
    add_library(RawrXDCore STATIC
        RawrXDCore.cpp
        ${RAWRXD_SOURCE_DIR}/src/GGUFLoader.cpp
    )
else()
    add_library(RawrXDCore SHARED
        RawrXDCore.cpp
        ${RAWRXD_SOURCE_DIR}/src/GGUFLoader.cpp
    )
endif()

# Generate export header (always: RawrXDCore.h includes it unconditionally,
# and the template resolves to empty macros on non-Windows platforms).
rawrxd_generate_export_header(RawrXDCore ${CMAKE_CURRENT_BINARY_DIR}/RawrXDCore_exports.h)
if(NOT RAWRXD_CORE_STATIC_ONLY)
    target_compile_definitions(RawrXDCore PRIVATE RawrXDCore_EXPORTS)
endif()

# Include directories - use PRIVATE to avoid CMP0104 policy issues
target_include_directories(RawrXDCore PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${RAWRXD_SOURCE_DIR}/include
    ${RAWRXD_SOURCE_DIR}/src
    ${RAWRXD_SOURCE_DIR}/src/core
    ${RAWRXD_SOURCE_DIR}/src/deep2
    ${RAWRXD_SOURCE_DIR}/src/deep2/modelgenie
    ${RAWRXD_SOURCE_DIR}/src/modelgenie
    ${RAWRXD_SOURCE_DIR}/generated/DeepSeek-V2-Lite-Chat
    ${RAWRXD_SOURCE_DIR}/tools
    ${CMAKE_CURRENT_BINARY_DIR}
    C:/VulkanSDK/1.4.357.0/Include
)

# Compile definitions
# NOMINMAX: windows.h must not macroize min/max - GGUFLoader.hpp and
# the ModelGenie generated headers use std::numeric_limits<>::max().
target_compile_definitions(RawrXDCore PRIVATE
    RAWRXD_CORE_DLL_BUILD
    RAWRXD_MODELGENIE_PRODUCTION_RUNTIME_001
    NOMINMAX
    WIN32_LEAN_AND_MEAN
)

# Link libraries
target_link_libraries(RawrXDCore PRIVATE psapi ModelGenieRuntime)

# Set C++ standard
set_target_properties(RawrXDCore PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
)

# Set DLL-specific properties
set_target_properties(RawrXDCore PROPERTIES
    VERSION 14.7.3
    SOVERSION 14
    DEBUG_POSTFIX "d"
    WINDOWS_EXPORT_ALL_SYMBOLS ON
    POSITION_INDEPENDENT_CODE ON
)

# Per-configuration output directories (multi-config VS generator)
set_target_properties(RawrXDCore PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin/Debug"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin/Release"
    RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}/bin/RelWithDebInfo"
    RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL "${CMAKE_BINARY_DIR}/bin/MinSizeRel"
    
    LIBRARY_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/lib/Debug"
    LIBRARY_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/lib/Release"
    LIBRARY_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}/lib/RelWithDebInfo"
    LIBRARY_OUTPUT_DIRECTORY_MINSIZEREL "${CMAKE_BINARY_DIR}/lib/MinSizeRel"
    
    ARCHIVE_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/lib/Debug"
    ARCHIVE_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/lib/Release"
    ARCHIVE_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}/lib/RelWithDebInfo"
    ARCHIVE_OUTPUT_DIRECTORY_MINSIZEREL "${CMAKE_BINARY_DIR}/lib/MinSizeRel"
)

# MSVC Runtime: MultiThreadedDLL (/MD /MDd) for DLLs
if(MSVC)
    if(NOT RAWRXD_CORE_STATIC_ONLY)
        # Shared library - use DLL runtime (/MD /MDd)
        set_target_properties(RawrXDCore PROPERTIES
            MSVC_RUNTIME_LIBRARY_DEBUG "MultiThreadedDebugDLL"
            MSVC_RUNTIME_LIBRARY_RELEASE "MultiThreadedDLL"
            MSVC_RUNTIME_LIBRARY_RELWITHDEBINFO "MultiThreadedDLL"
            MSVC_RUNTIME_LIBRARY_MINSIZEREL "MultiThreadedDLL"
        )
    else()
        # Static library - use static runtime (/MT /MTd)
        set_target_properties(RawrXDCore PROPERTIES
            MSVC_RUNTIME_LIBRARY_DEBUG "MultiThreadedDebug"
            MSVC_RUNTIME_LIBRARY_RELEASE "MultiThreaded"
            MSVC_RUNTIME_LIBRARY_RELWITHDEBINFO "MultiThreaded"
            MSVC_RUNTIME_LIBRARY_MINSIZEREL "MultiThreaded"
        )
    endif()
    
    target_compile_options(RawrXDCore PRIVATE
        $<$<AND:$<COMPILE_LANGUAGE:CXX>,$<CONFIG:Debug>>:/MDd>
        $<$<AND:$<COMPILE_LANGUAGE:C>,$<CONFIG:Debug>>:/MDd>
        $<$<AND:$<COMPILE_LANGUAGE:CXX>,$<CONFIG:Release>>:/MD>
        $<$<AND:$<COMPILE_LANGUAGE:C>,$<CONFIG:Release>>:/MD>
        $<$<AND:$<COMPILE_LANGUAGE:CXX>,$<CONFIG:RelWithDebInfo>>:/MD>
        $<$<AND:$<COMPILE_LANGUAGE:C>,$<CONFIG:RelWithDebInfo>>:/MD>
        $<$<AND:$<COMPILE_LANGUAGE:CXX>,$<CONFIG:MinSizeRel>>:/MD>
        $<$<AND:$<COMPILE_LANGUAGE:C>,$<CONFIG:MinSizeRel>>:/MD>
    )
endif()

# Install headers and library
install(TARGETS RawrXDCore
    EXPORT RawrXDCoreTargets
    LIBRARY DESTINATION bin
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    PUBLIC_HEADER DESTINATION include/rawrxd
)

install(FILES RawrXDCore.h
    DESTINATION include/rawrxd
)

# Export CMake config for downstream consumers
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/RawrXDCoreConfigVersion.cmake
    VERSION 14.7.3
    COMPATIBILITY SameMajorVersion
)

configure_package_config_file(
    ${CMAKE_SOURCE_DIR}/cmake/RawrXDCoreConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/RawrXDCoreConfig.cmake
    INSTALL_DESTINATION lib/cmake/RawrXDCore
)

install(EXPORT RawrXDCoreTargets
    FILE RawrXDCoreTargets.cmake
    NAMESPACE RawrXD::
    DESTINATION lib/cmake/RawrXDCore
)

# Example executable that uses the DLL
# Use standard CMake for the test executable
add_executable(RawrXDCore_Test test_main.cpp)
target_link_libraries(RawrXDCore_Test PRIVATE RawrXDCore)
target_include_directories(RawrXDCore_Test PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

# Set test executable properties
set_target_properties(RawrXDCore_Test PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin/Debug"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin/Release"
    DEBUG_POSTFIX "d"
)

if(MSVC)
    set_target_properties(RawrXDCore_Test PROPERTIES
        MSVC_RUNTIME_LIBRARY_DEBUG "MultiThreadedDebugDLL"
        MSVC_RUNTIME_LIBRARY_RELEASE "MultiThreadedDLL"
        MSVC_RUNTIME_LIBRARY_RELWITHDEBINFO "MultiThreadedDLL"
        MSVC_RUNTIME_LIBRARY_MINSIZEREL "MultiThreadedDLL"
    )
endif()

# Add test
if(BUILD_TESTING)
    add_test(NAME RawrXDCore_BasicTest
        COMMAND RawrXDCore_Test
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/bin/$<CONFIG>
    )
endif()

message(STATUS "[RawrXDCore] DLL target configured with full VS compatibility")