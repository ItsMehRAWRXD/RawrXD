# RawrXDSharedLibrary.cmake
# Provides cross-platform shared library (DLL/so/dylib) support with proper
# export/import macros for Visual Studio compatibility.
#
# Usage:
#   include(cmake/RawrXDSharedLibrary.cmake)
#   rawrxd_add_shared_library(MyLib src1.cpp src2.h)
#   target_link_libraries(MyTarget PRIVATE MyLib)

cmake_minimum_required(VERSION 3.20)

# Template directory is the cmake directory under the project source root
# This works regardless of where this file is included from
set(RAWRXD_SHARED_LIB_TEMPLATE_DIR "${CMAKE_SOURCE_DIR}/cmake")

# =============================================================================
# Platform-specific export/import macro generation
# =============================================================================

function(rawrxd_generate_export_header TARGET_NAME OUTPUT_HEADER)
    set(EXPORT_MACRO_NAME "${TARGET_NAME}_EXPORT")
    set(EXPORT_MACRO_NAME_UPPER "${EXPORT_MACRO_NAME}")

    message(STATUS "[RawrXDSharedLib] Generating export header for ${TARGET_NAME} using template dir: ${RAWRXD_SHARED_LIB_TEMPLATE_DIR}")
    
    configure_file(
        ${RAWRXD_SHARED_LIB_TEMPLATE_DIR}/RawrXDExportTemplate.h.in
        ${OUTPUT_HEADER}
        @ONLY
    )
endfunction()

# Template for export header - will be written by the function above
# This creates a proper dllimport/dllexport header for Windows
# and empty macros for Unix-like systems.

# =============================================================================
# Main function to create a shared library with proper exports
# =============================================================================

function(rawrxd_add_shared_library TARGET_NAME)
    set(options STATIC_ONLY NO_EXPORT_HEADER)
    set(oneValueArgs OUTPUT_NAME VERSION SOVERSION PUBLIC_HEADER PRIVATE_HEADER)
    set(multiValueArgs SOURCES HEADERS INCLUDE_DIRS COMPILE_DEFINITIONS LINK_LIBRARIES
        COMPILE_OPTIONS LINK_OPTIONS DEPENDS)

    cmake_parse_arguments(RAWR_SHARED "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    # Determine library type
    if(RAWR_SHARED_STATIC_ONLY)
        set(LIB_TYPE STATIC)
    else()
        set(LIB_TYPE SHARED)
    endif()

    # Create the library target
    add_library(${TARGET_NAME} ${LIB_TYPE} ${RAWR_SHARED_SOURCES} ${RAWR_SHARED_HEADERS})

    # Set output name if specified
    if(RAWR_SHARED_OUTPUT_NAME)
        set_target_properties(${TARGET_NAME} PROPERTIES OUTPUT_NAME ${RAWR_SHARED_OUTPUT_NAME})
    endif()

    # Set version info for shared libraries
    if(RAWR_SHARED_VERSION)
        set_target_properties(${TARGET_NAME} PROPERTIES VERSION ${RAWR_SHARED_VERSION})
    endif()
    if(RAWR_SHARED_SOVERSION)
        set_target_properties(${TARGET_NAME} PROPERTIES SOVERSION ${RAWR_SHARED_SOVERSION})
    endif()

    # Handle public/private headers for installation
    if(RAWR_SHARED_PUBLIC_HEADER)
        set_target_properties(${TARGET_NAME} PROPERTIES PUBLIC_HEADER ${RAWR_SHARED_PUBLIC_HEADER})
    endif()
    if(RAWR_SHARED_PRIVATE_HEADER)
        set_target_properties(${TARGET_NAME} PROPERTIES PRIVATE_HEADER ${RAWR_SHARED_PRIVATE_HEADER})
    endif()

    # Generate export header for shared libraries on Windows
    if(NOT RAWR_SHARED_STATIC_ONLY AND NOT RAWR_SHARED_NO_EXPORT_HEADER AND WIN32)
        set(EXPORT_HEADER "${CMAKE_CURRENT_BINARY_DIR}/${TARGET_NAME}_exports.h")
        rawrxd_generate_export_header(${TARGET_NAME} ${EXPORT_HEADER})
        target_include_directories(${TARGET_NAME} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
        target_compile_definitions(${TARGET_NAME} PRIVATE ${TARGET_NAME}_EXPORTS)
    endif()

    # Include directories
    if(RAWR_SHARED_INCLUDE_DIRS)
        target_include_directories(${TARGET_NAME} PUBLIC ${RAWR_SHARED_INCLUDE_DIRS})
    endif()

    # Compile definitions
    if(RAWR_SHARED_COMPILE_DEFINITIONS)
        target_compile_definitions(${TARGET_NAME} PUBLIC ${RAWR_SHARED_COMPILE_DEFINITIONS})
    endif()

    # Link libraries
    if(RAWR_SHARED_LINK_LIBRARIES)
        target_link_libraries(${TARGET_NAME} PUBLIC ${RAWR_SHARED_LINK_LIBRARIES})
    endif()

    # Compile options
    if(RAWR_SHARED_COMPILE_OPTIONS)
        target_compile_options(${TARGET_NAME} PUBLIC ${RAWR_SHARED_COMPILE_OPTIONS})
    endif()

    # Link options
    if(RAWR_SHARED_LINK_OPTIONS)
        target_link_options(${TARGET_NAME} PUBLIC ${RAWR_SHARED_LINK_OPTIONS})
    endif()

    # Dependencies
    if(RAWR_SHARED_DEPENDS)
        add_dependencies(${TARGET_NAME} ${RAWR_SHARED_DEPENDS})
    endif()

    # Set common properties for Visual Studio compatibility
    if(MSVC)
        # Use MultiThreadedDLL for all configs - let compile flags handle /MDd vs /MD
        # Explicitly set per-config to avoid CMake 4.4 auto-generation of invalid "MultiThreadedDLLDebug"
        set_target_properties(${TARGET_NAME} PROPERTIES
            MSVC_RUNTIME_LIBRARY_DEBUG "MultiThreadedDLL"
            MSVC_RUNTIME_LIBRARY_RELEASE "MultiThreadedDLL"
            MSVC_RUNTIME_LIBRARY_RELWITHDEBINFO "MultiThreadedDLL"
            MSVC_RUNTIME_LIBRARY_MINSIZEREL "MultiThreadedDLL"
        )
        
        # Also set compile options for /MDd in Debug, /MD in Release
        target_compile_options(${TARGET_NAME} PRIVATE
            $<$<AND:$<COMPILE_LANGUAGE:CXX>,$<CONFIG:Debug>>:/MDd>
            $<$<AND:$<COMPILE_LANGUAGE:C>,$<CONFIG:Debug>>:/MDd>
            $<$<AND:$<COMPILE_LANGUAGE:CXX>,$<CONFIG:Release>>:/MD>
            $<$<AND:$<COMPILE_LANGUAGE:C>,$<CONFIG:Release>>:/MD>
            $<$<AND:$<COMPILE_LANGUAGE:CXX>,$<CONFIG:RelWithDebInfo>>:/MD>
            $<$<AND:$<COMPILE_LANGUAGE:C>,$<CONFIG:RelWithDebInfo>>:/MD>
            $<$<AND:$<COMPILE_LANGUAGE:CXX>,$<CONFIG:MinSizeRel>>:/MD>
            $<$<AND:$<COMPILE_LANGUAGE:C>,$<CONFIG:MinSizeRel>>:/MD>
        )
        
        # Enable DLL export decorations
        if(NOT RAWR_SHARED_STATIC_ONLY)
            set_target_properties(${TARGET_NAME} PROPERTIES
                WINDOWS_EXPORT_ALL_SYMBOLS TRUE
            )
        endif()
        
        # Set debug postfix for easier debugging
        set_target_properties(${TARGET_NAME} PROPERTIES
            DEBUG_POSTFIX "d"
        )
    endif()

    # POSITION_INDEPENDENT_CODE for shared libraries on Unix
    if(NOT WIN32 AND NOT RAWR_SHARED_STATIC_ONLY)
        set_target_properties(${TARGET_NAME} PROPERTIES POSITION_INDEPENDENT_CODE ON)
    endif()

    # Set C++ standard
    target_compile_features(${TARGET_NAME} PUBLIC cxx_std_20)

    # Installation rules (optional, can be customized)
    if(RAWR_SHARED_PUBLIC_HEADER)
        install(TARGETS ${TARGET_NAME}
            EXPORT ${TARGET_NAME}Targets
            LIBRARY DESTINATION lib
            ARCHIVE DESTINATION lib
            RUNTIME DESTINATION bin
            PUBLIC_HEADER DESTINATION include
        )
    endif()

    message(STATUS "[RawrXD] Created ${LIB_TYPE} library: ${TARGET_NAME}")
endfunction()

# =============================================================================
# Function to create an executable that links to shared libraries
# =============================================================================

function(rawrxd_add_executable TARGET_NAME)
    set(options NO_RUNTIME_DLL)
    set(oneValueArgs OUTPUT_NAME)
    set(multiValueArgs SOURCES HEADERS INCLUDE_DIRS COMPILE_DEFINITIONS LINK_LIBRARIES
        COMPILE_OPTIONS LINK_OPTIONS DEPENDS)

    cmake_parse_arguments(RAWR_EXE "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    add_executable(${TARGET_NAME} ${RAWR_EXE_SOURCES} ${RAWR_EXE_HEADERS})

    if(RAWR_EXE_OUTPUT_NAME)
        set_target_properties(${TARGET_NAME} PROPERTIES OUTPUT_NAME ${RAWR_EXE_OUTPUT_NAME})
    endif()

    if(RAWR_EXE_INCLUDE_DIRS)
        target_include_directories(${TARGET_NAME} PRIVATE ${RAWR_EXE_INCLUDE_DIRS})
    endif()

    if(RAWR_EXE_COMPILE_DEFINITIONS)
        target_compile_definitions(${TARGET_NAME} PRIVATE ${RAWR_EXE_COMPILE_DEFINITIONS})
    endif()

    if(RAWR_EXE_LINK_LIBRARIES)
        target_link_libraries(${TARGET_NAME} PRIVATE ${RAWR_EXE_LINK_LIBRARIES})
    endif()

    if(RAWR_EXE_COMPILE_OPTIONS)
        target_compile_options(${TARGET_NAME} PRIVATE ${RAWR_EXE_COMPILE_OPTIONS})
    endif()

    if(RAWR_EXE_LINK_OPTIONS)
        target_link_options(${TARGET_NAME} PRIVATE ${RAWR_EXE_LINK_OPTIONS})
    endif()

    if(RAWR_EXE_DEPENDS)
        add_dependencies(${TARGET_NAME} ${RAWR_EXE_DEPENDS})
    endif()

# VS-specific settings for executables
    if(MSVC)
        if(NOT RAWR_EXE_NO_RUNTIME_DLL)
            # Use MultiThreaded DLL runtime for executables linking to DLLs (/MD /MDd)
            set_target_properties(${TARGET_NAME} PROPERTIES
                MSVC_RUNTIME_LIBRARY_DEBUG "MultiThreadedDLLDebug"
                MSVC_RUNTIME_LIBRARY_RELEASE "MultiThreadedDLL"
                MSVC_RUNTIME_LIBRARY_RELWITHDEBINFO "MultiThreadedDLL"
                MSVC_RUNTIME_LIBRARY_MINSIZEREL "MultiThreadedDLL"
            )
        else()
            # Static runtime for standalone executables
            set_target_properties(${TARGET_NAME} PROPERTIES
                MSVC_RUNTIME_LIBRARY_DEBUG "MultiThreadedDebug"
                MSVC_RUNTIME_LIBRARY_RELEASE "MultiThreaded"
                MSVC_RUNTIME_LIBRARY_RELWITHDEBINFO "MultiThreaded"
                MSVC_RUNTIME_LIBRARY_MINSIZEREL "MultiThreaded"
            )
        endif()
        
        set_target_properties(${TARGET_NAME} PROPERTIES
            DEBUG_POSTFIX "d"
        )
    endif()

    target_compile_features(${TARGET_NAME} PRIVATE cxx_std_20)

    message(STATUS "[RawrXD] Created executable: ${TARGET_NAME}")
endfunction()

# =============================================================================
# Helper to create a module definition (.def) file for explicit exports
# =============================================================================

function(rawrxd_create_module_def TARGET_NAME EXPORT_SYMBOLS OUTPUT_DEF)
    # Generate .def file for precise export control
    file(WRITE ${OUTPUT_DEF} "LIBRARY ${TARGET_NAME}\nEXPORTS\n")
    foreach(sym ${EXPORT_SYMBOLS})
        file(APPEND ${OUTPUT_DEF} "    ${sym}\n")
    endforeach()
    
    target_link_options(${TARGET_NAME} PRIVATE "/DEF:${OUTPUT_DEF}")
endfunction()

# =============================================================================
# Macro to define DLL import/export in source code
# =============================================================================

# Usage in header:
#   #include "MyLib_exports.h"
#   class MYLIB_EXPORT MyClass { ... };
#   MYLIB_EXPORT void myFunction();

# The export header template is generated by rawrxd_generate_export_header
# and follows this pattern:
#
# #ifndef MYLIB_EXPORTS_H
# #define MYLIB_EXPORTS_H
# 
# #ifdef _WIN32
#   #ifdef MYLIB_EXPORTS
#     #define MYLIB_EXPORT __declspec(dllexport)
#   #else
#     #define MYLIB_EXPORT __declspec(dllimport)
#   #endif
# #else
#   #define MYLIB_EXPORT __attribute__((visibility("default")))
# #endif
# 
# #endif

# =============================================================================
# Convenience macro for creating both static and shared variants
# =============================================================================

function(rawrxd_add_library_both STATIC_NAME SHARED_NAME)
    set(options)
    set(oneValueArgs)
    set(multiValueArgs SOURCES HEADERS INCLUDE_DIRS COMPILE_DEFINITIONS LINK_LIBRARIES
        COMPILE_OPTIONS LINK_OPTIONS)

    cmake_parse_arguments(RAWR_BOTH "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    # Static library
    add_library(${STATIC_NAME} STATIC ${RAWR_BOTH_SOURCES} ${RAWR_BOTH_HEADERS})
    target_include_directories(${STATIC_NAME} PUBLIC ${RAWR_BOTH_INCLUDE_DIRS})
    target_compile_definitions(${STATIC_NAME} PUBLIC ${RAWR_BOTH_COMPILE_DEFINITIONS})
    target_link_libraries(${STATIC_NAME} PUBLIC ${RAWR_BOTH_LINK_LIBRARIES})
    target_compile_options(${STATIC_NAME} PUBLIC ${RAWR_BOTH_COMPILE_OPTIONS})
    target_link_options(${STATIC_NAME} PUBLIC ${RAWR_BOTH_LINK_OPTIONS})
    target_compile_features(${STATIC_NAME} PUBLIC cxx_std_20)
    
    if(MSVC)
        set_target_properties(${STATIC_NAME} PROPERTIES
            MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
        )
    endif()

    # Shared library
    rawrxd_add_shared_library(${SHARED_NAME}
        SOURCES ${RAWR_BOTH_SOURCES}
        HEADERS ${RAWR_BOTH_HEADERS}
        INCLUDE_DIRS ${RAWR_BOTH_INCLUDE_DIRS}
        COMPILE_DEFINITIONS ${RAWR_BOTH_COMPILE_DEFINITIONS}
        LINK_LIBRARIES ${RAWR_BOTH_LINK_LIBRARIES}
        COMPILE_OPTIONS ${RAWR_BOTH_COMPILE_OPTIONS}
        LINK_OPTIONS ${RAWR_BOTH_LINK_OPTIONS}
    )

    # Alias for easy switching
    add_library(RawrXD::${STATIC_NAME} ALIAS ${STATIC_NAME})
    add_library(RawrXD::${SHARED_NAME} ALIAS ${SHARED_NAME})
endfunction()