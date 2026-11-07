# =============================================================================
# cmake/CompilerChecks.cmake - Validate Compiler Capabilities
# =============================================================================

# Check for C++20 support
include(CheckCXXCompilerFlag)
if(MSVC)
 check_cxx_compiler_flag("/std:c++20" COMPILER_SUPPORTS_CXX20)
else()
 check_cxx_compiler_flag("-std=c++20" COMPILER_SUPPORTS_CXX20)
endif()

if(NOT COMPILER_SUPPORTS_CXX20)
    message(FATAL_ERROR "C++20 support is required. Use a compiler with C++20 support")
endif()

if(MSVC)
 check_cxx_compiler_flag("/permissive-" COMPILER_SUPPORTS_PERMISSIVE)
endif()
