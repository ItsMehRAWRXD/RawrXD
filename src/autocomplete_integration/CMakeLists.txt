# Autocomplete Integration Module - CMake Configuration
# Phase 17: Unified Tiered Autocomplete System

cmake_minimum_required(VERSION 3.20)

# Module name
set(AUTOCOMPLETE_MODULE autocomplete_integration)

# Source files
set(AUTOCOMPLETE_SOURCES
    UnifiedAutocompleteEngine.cpp
)

# Header files
set(AUTOCOMPLETE_HEADERS
    UnifiedAutocompleteEngine.h
)

# Create the library
add_library(${AUTOCOMPLETE_MODULE} STATIC
    ${AUTOCOMPLETE_SOURCES}
    ${AUTOCOMPLETE_HEADERS}
)

# Include directories
target_include_directories(${AUTOCOMPLETE_MODULE}
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/../semantic_index
        ${CMAKE_CURRENT_SOURCE_DIR}/../ast_parser
)

# Link dependencies
target_link_libraries(${AUTOCOMPLETE_MODULE}
    PUBLIC
        semantic_index
        ast_parser
)

# Compiler options
if(MSVC)
    target_compile_options(${AUTOCOMPLETE_MODULE}
        PRIVATE
            /O2
            /W3
            /EHsc
    )
endif()

# Smoke test executable
add_executable(unified_autocomplete_smoke_test
    unified_autocomplete_smoke_test.cpp
)

target_link_libraries(unified_autocomplete_smoke_test
    PRIVATE
        ${AUTOCOMPLETE_MODULE}
)

# Installation
install(TARGETS ${AUTOCOMPLETE_MODULE}
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)

install(FILES ${AUTOCOMPLETE_HEADERS}
    DESTINATION include/autocomplete_integration
)