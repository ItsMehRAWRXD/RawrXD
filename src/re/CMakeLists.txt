# ============================================================================
# RawrXD Multi-Architecture Reverse Engineering Framework
# ============================================================================
# CMake configuration for Capstone, Keystone, and Unicorn integration
# 
# Supported Architectures:
#   - x86 (32/64-bit)
#   - ARM (32/64-bit, Thumb/Thumb2)
#   - MIPS (32/64-bit, microMIPS)
#   - PowerPC (32/64-bit)
#   - ARC
#   - RISC-V (32/64-bit)
#   - V850
#
# Dependencies:
#   - Capstone (disassembly)
#   - Keystone (assembly)
#   - Unicorn (emulation)
# ============================================================================

cmake_minimum_required(VERSION 3.20)

project(RawrXD_RE_Framework VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ============================================================================
# Find Dependencies
# ============================================================================

# Capstone
find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(CAPSTONE capstone)
endif()

if(NOT CAPSTONE_FOUND)
    # Try to find Capstone manually
    find_path(CAPSTONE_INCLUDE_DIR 
        NAMES capstone/capstone.h
        PATHS 
            ${CMAKE_SOURCE_DIR}/../third_party/capstone/include
            /usr/include
            /usr/local/include
            "C:/Program Files/Capstone/include"
    )
    find_library(CAPSTONE_LIBRARY
        NAMES capstone
        PATHS
            ${CMAKE_SOURCE_DIR}/../third_party/capstone
            /usr/lib
            /usr/local/lib
            "C:/Program Files/Capstone/lib"
    )
    if(CAPSTONE_INCLUDE_DIR AND CAPSTONE_LIBRARY)
        set(CAPSTONE_FOUND TRUE)
        set(CAPSTONE_INCLUDE_DIRS ${CAPSTONE_INCLUDE_DIR})
        set(CAPSTONE_LIBRARIES ${CAPSTONE_LIBRARY})
    endif()
endif()

# Keystone
if(PKG_CONFIG_FOUND)
    pkg_check_modules(KEYSTONE keystone)
endif()

if(NOT KEYSTONE_FOUND)
    find_path(KEYSTONE_INCLUDE_DIR
        NAMES keystone/keystone.h
        PATHS
            ${CMAKE_SOURCE_DIR}/../third_party/keystone/include
            /usr/include
            /usr/local/include
            "C:/Program Files/Keystone/include"
    )
    find_library(KEYSTONE_LIBRARY
        NAMES keystone
        PATHS
            ${CMAKE_SOURCE_DIR}/../third_party/keystone
            /usr/lib
            /usr/local/lib
            "C:/Program Files/Keystone/lib"
    )
    if(KEYSTONE_INCLUDE_DIR AND KEYSTONE_LIBRARY)
        set(KEYSTONE_FOUND TRUE)
        set(KEYSTONE_INCLUDE_DIRS ${KEYSTONE_INCLUDE_DIR})
        set(KEYSTONE_LIBRARIES ${KEYSTONE_LIBRARY})
    endif()
endif()

# Unicorn
if(PKG_CONFIG_FOUND)
    pkg_check_modules(UNICORN unicorn)
endif()

if(NOT UNICORN_FOUND)
    find_path(UNICORN_INCLUDE_DIR
        NAMES unicorn/unicorn.h
        PATHS
            ${CMAKE_SOURCE_DIR}/../third_party/unicorn/include
            /usr/include
            /usr/local/include
            "C:/Program Files/Unicorn/include"
    )
    find_library(UNICORN_LIBRARY
        NAMES unicorn
        PATHS
            ${CMAKE_SOURCE_DIR}/../third_party/unicorn
            /usr/lib
            /usr/local/lib
            "C:/Program Files/Unicorn/lib"
    )
    if(UNICORN_INCLUDE_DIR AND UNICORN_LIBRARY)
        set(UNICORN_FOUND TRUE)
        set(UNICORN_INCLUDE_DIRS ${UNICORN_INCLUDE_DIR})
        set(UNICORN_LIBRARIES ${UNICORN_LIBRARY})
    endif()
endif()

# ============================================================================
# Status Report
# ============================================================================

message(STATUS "RawrXD RE Framework Configuration")
message(STATUS "====================================")
if(CAPSTONE_FOUND)
    message(STATUS "  Capstone:   FOUND")
    message(STATUS "    Include:  ${CAPSTONE_INCLUDE_DIRS}")
    message(STATUS "    Library:  ${CAPSTONE_LIBRARIES}")
else()
    message(STATUS "  Capstone:   NOT FOUND (disassembly disabled)")
endif()

if(KEYSTONE_FOUND)
    message(STATUS "  Keystone:   FOUND")
    message(STATUS "    Include:  ${KEYSTONE_INCLUDE_DIRS}")
    message(STATUS "    Library:  ${KEYSTONE_LIBRARIES}")
else()
    message(STATUS "  Keystone:   NOT FOUND (assembly disabled)")
endif()

if(UNICORN_FOUND)
    message(STATUS "  Unicorn:    FOUND")
    message(STATUS "    Include:  ${UNICORN_INCLUDE_DIRS}")
    message(STATUS "    Library:  ${UNICORN_LIBRARIES}")
else()
    message(STATUS "  Unicorn:    NOT FOUND (emulation disabled)")
endif()

# ============================================================================
# RE Framework Library
# ============================================================================

set(RE_SOURCES
    src/rawr_arch.cpp
)

set(RE_HEADERS
    include/rawr_arch.hpp
)

if(CAPSTONE_FOUND)
    list(APPEND RE_SOURCES src/rawr_disasm.cpp)
    list(APPEND RE_HEADERS include/rawr_disasm.hpp)
endif()

if(KEYSTONE_FOUND)
    list(APPEND RE_SOURCES src/rawr_asm.cpp)
    list(APPEND RE_HEADERS include/rawr_asm.hpp)
endif()

if(UNICORN_FOUND)
    list(APPEND RE_SOURCES src/rawr_emu.cpp)
    list(APPEND RE_HEADERS include/rawr_emu.hpp)
endif()

add_library(rawr_re_framework STATIC ${RE_SOURCES})

target_include_directories(rawr_re_framework
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

if(CAPSTONE_FOUND)
    target_include_directories(rawr_re_framework PRIVATE ${CAPSTONE_INCLUDE_DIRS})
    target_link_libraries(rawr_re_framework PUBLIC ${CAPSTONE_LIBRARIES})
    target_compile_definitions(rawr_re_framework PRIVATE HAS_CAPSTONE)
endif()

if(KEYSTONE_FOUND)
    target_include_directories(rawr_re_framework PRIVATE ${KEYSTONE_INCLUDE_DIRS})
    target_link_libraries(rawr_re_framework PUBLIC ${KEYSTONE_LIBRARIES})
    target_compile_definitions(rawr_re_framework PRIVATE HAS_KEYSTONE)
endif()

if(UNICORN_FOUND)
    target_include_directories(rawr_re_framework PRIVATE ${UNICORN_INCLUDE_DIRS})
    target_link_libraries(rawr_re_framework PUBLIC ${UNICORN_LIBRARIES})
    target_compile_definitions(rawr_re_framework PRIVATE HAS_UNICORN)
endif()

# ============================================================================
# Test Executable
# ============================================================================

if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/test/re_framework_test.cpp)
    add_executable(re_framework_test test/re_framework_test.cpp)
    target_link_libraries(re_framework_test PRIVATE rawr_re_framework)
    
    if(MSVC)
        target_compile_options(re_framework_test PRIVATE /W4 /WX-)
    endif()
    
    enable_testing()
    add_test(NAME re_framework_test COMMAND re_framework_test)
endif()

# ============================================================================
# Installation
# ============================================================================

install(TARGETS rawr_re_framework
    EXPORT RawrXD_RE_Targets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

install(FILES ${RE_HEADERS}
    DESTINATION include/rawr_re
)

install(EXPORT RawrXD_RE_Targets
    FILE RawrXD_RE_Targets.cmake
    NAMESPACE RawrXD::
    DESTINATION lib/cmake/RawrXD_RE
)
