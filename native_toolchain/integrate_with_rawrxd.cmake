# ============================================================================
# Native Toolchain Integration for RawrXD
# Replaces Microsoft ML64.EXE and LINK.EXE with native implementations
# ============================================================================

# Native toolchain directory
set(NATIVE_TOOLCHAIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/native_toolchain")

# Native toolchain executables
set(NATIVE_ASSEMBLER "${NATIVE_TOOLCHAIN_DIR}/minimal_assembler.exe")
set(NATIVE_LINKER "${NATIVE_TOOLCHAIN_DIR}/minimal_linker.exe")
set(NATIVE_LIBRARIAN "${NATIVE_TOOLCHAIN_DIR}/native_librarian.exe")
set(NATIVE_RUNTIME "${NATIVE_TOOLCHAIN_DIR}/native_runtime.obj")

# Check if native toolchain exists
if(EXISTS "${NATIVE_ASSEMBLER}" AND EXISTS "${NATIVE_LINKER}")
    message(STATUS "[Native Toolchain] Found native assembler and linker")
    set(NATIVE_TOOLCHAIN_AVAILABLE TRUE)
else()
    message(WARNING "[Native Toolchain] Native tools not found, falling back to Microsoft tools")
    set(NATIVE_TOOLCHAIN_AVAILABLE FALSE)
endif()

# Function to assemble with native toolchain
function(native_assemble_asm input_file output_file)
    if(NATIVE_TOOLCHAIN_AVAILABLE)
        add_custom_command(
            OUTPUT "${output_file}"
            COMMAND "${NATIVE_ASSEMBLER}" "${input_file}" "${output_file}"
            DEPENDS "${input_file}" "${NATIVE_ASSEMBLER}"
            COMMENT "Assembling ${input_file} with native assembler"
            VERBATIM
        )
    else()
        # Fallback to ML64
        add_custom_command(
            OUTPUT "${output_file}"
            COMMAND "${CMAKE_ASM_COMPILER}" /c /Fo "${output_file}" "${input_file}"
            DEPENDS "${input_file}"
            COMMENT "Assembling ${input_file} with ML64 (fallback)"
            VERBATIM
        )
    endif()
endfunction()

# Function to link with native toolchain
function(native_link_executable output_name)
    set(options "")
    set(oneValueArgs "")
    set(multiValueArgs OBJECTS LIBRARIES)
    cmake_parse_arguments(NATIVE_LINK "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
    
    # Collect all object files
    set(all_objects "${NATIVE_LINK_OBJECTS}")
    
    if(NATIVE_TOOLCHAIN_AVAILABLE)
        # For now, native linker only supports single object
        # TODO: Extend to support multiple objects and libraries
        list(GET all_objects 0 first_obj)
        add_custom_command(
            OUTPUT "${output_name}"
            COMMAND "${NATIVE_LINKER}" "${first_obj}" "${output_name}"
            DEPENDS ${all_objects} "${NATIVE_LINKER}"
            COMMENT "Linking ${output_name} with native linker"
            VERBATIM
        )
    else()
        # Fallback to Microsoft linker
        add_executable(${output_name} ${all_objects})
        target_link_libraries(${output_name} ${NATIVE_LINK_LIBRARIES})
    endif()
endfunction()

# Function to create static library with native librarian
function(native_create_library lib_name)
    set(options "")
    set(oneValueArgs "")
    set(multiValueArgs OBJECTS)
    cmake_parse_arguments(NATIVE_LIB "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
    
    set(lib_path "${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}/${lib_name}.lib")
    
    if(NATIVE_TOOLCHAIN_AVAILABLE)
        # Build command line for librarian
        set(librarian_args "/OUT:${lib_path}")
        foreach(obj ${NATIVE_LIB_OBJECTS})
            list(APPEND librarian_args "${obj}")
        endforeach()
        
        add_custom_command(
            OUTPUT "${lib_path}"
            COMMAND "${NATIVE_LIBRARIAN}" ${librarian_args}
            DEPENDS ${NATIVE_LIB_OBJECTS} "${NATIVE_LIBRARIAN}"
            COMMENT "Creating library ${lib_name} with native librarian"
            VERBATIM
        )
    else()
        # Fallback to Microsoft lib.exe
        add_library(${lib_name} STATIC ${NATIVE_LIB_OBJECTS})
    endif()
endfunction()

# ============================================================================
# Integration with RawrXD build targets
# ============================================================================

# Option to enable native toolchain
option(RAWRXD_USE_NATIVE_TOOLCHAIN "Use native toolchain instead of Microsoft tools" OFF)

if(RAWRXD_USE_NATIVE_TOOLCHAIN)
    if(NATIVE_TOOLCHAIN_AVAILABLE)
        message(STATUS "[Native Toolchain] ENABLED - Using native assembler/linker")
        
        # Override ASM compiler
        set(CMAKE_ASM_COMPILER "${NATIVE_ASSEMBLER}")
        set(CMAKE_ASM_COMPILE_OBJECT "<CMAKE_ASM_COMPILER> <SOURCE> <OBJECT>")
        
        # Override linker
        set(CMAKE_LINKER "${NATIVE_LINKER}")
        set(CMAKE_C_LINK_EXECUTABLE "<CMAKE_LINKER> <OBJECTS> <TARGET>")
        set(CMAKE_CXX_LINK_EXECUTABLE "<CMAKE_LINKER> <OBJECTS> <TARGET>")
        
    else()
        message(FATAL_ERROR "[Native Toolchain] Requested but not available. Run build_native_toolchain.bat first.")
    endif()
else()
    message(STATUS "[Native Toolchain] DISABLED - Using Microsoft tools (set RAWRXD_USE_NATIVE_TOOLCHAIN=ON to enable)")
endif()

# ============================================================================
# Test target for native toolchain
# ============================================================================

if(NATIVE_TOOLCHAIN_AVAILABLE)
    add_custom_target(test_native_toolchain
        COMMAND "${NATIVE_ASSEMBLER}" "${NATIVE_TOOLCHAIN_DIR}/test_program.asm" 
                "${CMAKE_BINARY_DIR}/native_test.obj"
        COMMAND "${NATIVE_LINKER}" "${CMAKE_BINARY_DIR}/native_test.obj"
                "${CMAKE_BINARY_DIR}/native_test.exe"
        COMMENT "Testing native toolchain..."
        VERBATIM
    )
    
    add_custom_target(verify_native_toolchain
        COMMAND ${CMAKE_COMMAND} -E echo "Native Toolchain Verification"
        COMMAND ${CMAKE_COMMAND} -E echo "  Assembler: ${NATIVE_ASSEMBLER}"
        COMMAND ${CMAKE_COMMAND} -E echo "  Linker: ${NATIVE_LINKER}"
        COMMAND ${CMAKE_COMMAND} -E echo "  Librarian: ${NATIVE_LIBRARIAN}"
        COMMAND ${CMAKE_COMMAND} -E echo ""
        COMMAND ${CMAKE_COMMAND} -E echo "To use native toolchain, configure with:"
        COMMAND ${CMAKE_COMMAND} -E echo "  cmake -DRAWRXD_USE_NATIVE_TOOLCHAIN=ON ..."
        COMMENT "Native toolchain info"
    )
endif()
