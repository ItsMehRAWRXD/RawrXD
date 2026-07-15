# Executor Layer CMakeLists.txt
# Layer 2: Decides HOW - kernel dispatch, memory allocation

cmake_minimum_required(VERSION 3.20)
project(RawrXD-Executor VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(EXECUTOR_SOURCES
    executor.cpp
)

set(EXECUTOR_HEADERS
    executor.h
)

# Create static library
add_library(RawrXD-Executor STATIC ${EXECUTOR_SOURCES} ${EXECUTOR_HEADERS})

# Set include directories
target_include_directories(RawrXD-Executor
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<INSTALL_INTERFACE:include>
)

# Compiler options
if(MSVC)
    target_compile_options(RawrXD-Executor PRIVATE
        /W4
        /WX-
        /EHsc
        /MP
    )
else()
    target_compile_options(RawrXD-Executor PRIVATE
        -Wall
        -Wextra
        -Wpedantic
    )
endif()

# Install headers
install(FILES ${EXECUTOR_HEADERS}
    DESTINATION include/rawrxd/executor
)

install(TARGETS RawrXD-Executor
    DESTINATION lib
)
