# AST Parser Module - CMake Configuration
# Phase 17: Advanced Intelligence - Workstream 2

cmake_minimum_required(VERSION 3.20)

# Module name
set(AST_PARSER_MODULE ast_parser)

# Source files
set(AST_PARSER_SOURCES
    ASTContextProvider.cpp
)

# Header files
set(AST_PARSER_HEADERS
    ASTContextProvider.h
)

# Try to find tree-sitter
find_package(tree-sitter CONFIG QUIET)
find_library(TREE_SITTER_LIB tree-sitter PATHS ${CMAKE_PREFIX_PATH})

if(tree-sitter_FOUND OR TREE_SITTER_LIB)
    message(STATUS "tree-sitter found - using real AST parsing")
    set(USE_REAL_AST_PARSER TRUE)
    set(AST_PARSER_BACKEND_LIBS ${TREE_SITTER_LIB})
else()
    message(STATUS "tree-sitter not found - using mock AST provider")
    set(USE_REAL_AST_PARSER FALSE)
    set(AST_PARSER_BACKEND_LIBS "")
endif()

# Create the library
add_library(${AST_PARSER_MODULE} STATIC
    ${AST_PARSER_SOURCES}
    ${AST_PARSER_HEADERS}
)

# Define backend macro
if(USE_REAL_AST_PARSER)
    target_compile_definitions(${AST_PARSER_MODULE}
        PRIVATE USE_REAL_AST_PARSER
    )
endif()

# Include directories
target_include_directories(${AST_PARSER_MODULE}
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
)

if(USE_REAL_AST_PARSER)
    target_include_directories(${AST_PARSER_MODULE}
        PRIVATE
            ${tree-sitter_INCLUDE_DIRS}
    )
endif()

# Link libraries
target_link_libraries(${AST_PARSER_MODULE}
    PUBLIC
        ${AST_PARSER_BACKEND_LIBS}
)

# Compiler options
if(MSVC)
    target_compile_options(${AST_PARSER_MODULE}
        PRIVATE
            /O2
            /W3
    )
endif()

# Smoke test
add_executable(ast_parser_smoke_test
    ast_parser_smoke_test.cpp
)

target_link_libraries(ast_parser_smoke_test
    PRIVATE
        ${AST_PARSER_MODULE}
)

# Installation
install(TARGETS ${AST_PARSER_MODULE}
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)

install(FILES ${AST_PARSER_HEADERS}
    DESTINATION include/ast_parser
)