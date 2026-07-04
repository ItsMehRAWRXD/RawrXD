# RawrXD-Script Phase 1 Build Configuration
# Bytecode Spec + C++ Parser

cmake_minimum_required(VERSION 3.20)

project(RawrXD-Script VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Source files
set(SCRIPT_SOURCES
    compiler/main.cpp
    lexer/lexer.cpp
    lexer/token.cpp
    parser/parser.cpp
    ast/ast.cpp
    bytecode/bytecode.cpp
    bytecode/disassembler.cpp
)

# Header files (for IDE)
set(SCRIPT_HEADERS
    lexer/token.hpp
    lexer/lexer.hpp
    parser/parser.hpp
    ast/ast.hpp
    bytecode/bytecode.hpp
)

# Main compiler executable
add_executable(rawrxd-js ${SCRIPT_SOURCES} ${SCRIPT_HEADERS})

target_include_directories(rawrxd-js PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# Compiler flags
if(MSVC)
    target_compile_options(rawrxd-js PRIVATE /W4 /EHsc)
else()
    target_compile_options(rawrxd-js PRIVATE -Wall -Wextra -Wpedantic)
endif()

# Tests
enable_testing()
add_subdirectory(tests)

# Install
install(TARGETS rawrxd-js DESTINATION bin)
