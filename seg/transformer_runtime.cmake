# Transformer Runtime - Standalone CMake Configuration
# Usage: cmake -P transformer_runtime.cmake or include in parent CMakeLists.txt

cmake_minimum_required(VERSION 3.16)

# If being run as standalone
if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    project(TransformerRuntime VERSION 1.0.0 LANGUAGES CXX)
    set(CMAKE_CXX_STANDARD 17)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
endif()

# Options
option(TRANSFORMER_ENABLE_VULKAN "Enable Vulkan backend" OFF)

# Find Vulkan if enabled
if(TRANSFORMER_ENABLE_VULKAN)
    find_package(Vulkan QUIET)
    if(Vulkan_FOUND)
        message(STATUS "Vulkan found: ${Vulkan_VERSION}")
    else()
        message(WARNING "Vulkan not found, GPU backend disabled")
    endif()
endif()

# Source files
set(TRANSFORMER_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/transformer_layer_runtime.cpp
)

set(TRANSFORMER_HEADERS
    ${CMAKE_CURRENT_LIST_DIR}/transformer_layer_runtime.hpp
)

# Create library
add_library(transformer_runtime STATIC ${TRANSFORMER_SOURCES} ${TRANSFORMER_HEADERS})

target_include_directories(transformer_runtime
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}>
        $<INSTALL_INTERFACE:include/transformer>
)

if(TRANSFORMER_ENABLE_VULKAN AND Vulkan_FOUND)
    target_link_libraries(transformer_runtime PUBLIC Vulkan::Vulkan)
    target_compile_definitions(transformer_runtime PUBLIC VULKAN_BACKEND_ENABLED)
    message(STATUS "Vulkan backend enabled for transformer runtime")
endif()

# Compiler-specific options
if(MSVC)
    target_compile_options(transformer_runtime PRIVATE /W4 /O2 /arch:AVX2)
    target_compile_definitions(transformer_runtime PRIVATE _CRT_SECURE_NO_WARNINGS)
else()
    target_compile_options(transformer_runtime PRIVATE -Wall -Wextra -O3 -march=native)
endif()

# Test executable
add_executable(test_transformer_runtime ${CMAKE_CURRENT_LIST_DIR}/test_transformer_runtime.cpp)
target_link_libraries(test_transformer_runtime PRIVATE transformer_runtime)

if(MSVC)
    target_compile_options(test_transformer_runtime PRIVATE /W4 /O2 /arch:AVX2)
    target_compile_definitions(test_transformer_runtime PRIVATE _CRT_SECURE_NO_WARNINGS)
else()
    target_compile_options(test_transformer_runtime PRIVATE -Wall -Wextra -O3 -march=native)
endif()

# Print configuration
message(STATUS "")
message(STATUS "Transformer Runtime Configuration:")
message(STATUS "  Sources: ${TRANSFORMER_SOURCES}")
message(STATUS "  Headers: ${TRANSFORMER_HEADERS}")
message(STATUS "  Vulkan Backend: ${TRANSFORMER_ENABLE_VULKAN}")
if(TRANSFORMER_ENABLE_VULKAN AND Vulkan_FOUND)
    message(STATUS "  Vulkan Version: ${Vulkan_VERSION}")
endif()
message(STATUS "")
