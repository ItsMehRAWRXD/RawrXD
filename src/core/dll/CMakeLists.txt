# RawrXDCore DLL - Shared Library Build
# Demonstrates full VS compatibility with DLL export/import

cmake_minimum_required(VERSION 3.20)

# Ensure RAWRXD_SOURCE_DIR is defined (for out-of-tree builds)
if(NOT DEFINED RAWRXD_SOURCE_DIR)
    set(RAWRXD_SOURCE_DIR "${CMAKE_SOURCE_DIR}")
endif()

# Include shared library support
include(${RAWRXD_SOURCE_DIR}/cmake/RawrXDSharedLibrary.cmake)

# Determine library type: use shared when BUILD_SHARED_LIBS=ON, unless explicitly STATIC_ONLY
set(RAWRXD_CORE_STATIC_ONLY FALSE)
if(NOT BUILD_SHARED_LIBS)
    set(RAWRXD_CORE_STATIC_ONLY TRUE)
endif()

# Create the library with proper exports
# Note: STATIC_ONLY is a boolean option - only pass it when TRUE
if(RAWRXD_CORE_STATIC_ONLY)
    rawrxd_add_shared_library(RawrXDCore
        STATIC_ONLY
        SOURCES
            RawrXDCore.cpp
        HEADERS
            RawrXDCore.h
        INCLUDE_DIRS
            ${CMAKE_CURRENT_SOURCE_DIR}
            ${RAWRXD_SOURCE_DIR}/include
            ${RAWRXD_SOURCE_DIR}/src
        COMPILE_DEFINITIONS
            RAWRXD_CORE_DLL_BUILD
    )
else()
    rawrxd_add_shared_library(RawrXDCore
        SOURCES
            RawrXDCore.cpp
        HEADERS
            RawrXDCore.h
        INCLUDE_DIRS
            ${CMAKE_CURRENT_SOURCE_DIR}
            ${RAWRXD_SOURCE_DIR}/include
            ${RAWRXD_SOURCE_DIR}/src
        COMPILE_DEFINITIONS
            RAWRXD_CORE_DLL_BUILD
    )
endif()

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
    # Explicitly set target properties to override any auto-generated values
    set_target_properties(RawrXDCore PROPERTIES
        MSVC_RUNTIME_LIBRARY_DEBUG "MultiThreadedDebugDLL"
        MSVC_RUNTIME_LIBRARY_RELEASE "MultiThreadedDLL"
        MSVC_RUNTIME_LIBRARY_RELWITHDEBINFO "MultiThreadedDLL"
        MSVC_RUNTIME_LIBRARY_MINSIZEREL "MultiThreadedDLL"
    )
    
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
rawrxd_add_executable(RawrXDCore_Test
    SOURCES
        test_main.cpp
    LINK_LIBRARIES
        RawrXDCore
)

# Set test executable properties
set_target_properties(RawrXDCore_Test PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin/Debug"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin/Release"
    DEBUG_POSTFIX "d"
)

if(MSVC)
    set_target_properties(RawrXDCore_Test PROPERTIES
        MSVC_RUNTIME_LIBRARY "MultiThreadedDLL$<$<CONFIG:Debug>:Debug>"
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