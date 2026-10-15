# Deep2 GPU Production Hardening — Build Configuration

cmake_minimum_required(VERSION 3.20)
project(Deep2_GPU_Production_Hardening LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# MSVC settings
if(MSVC)
    add_compile_options(/W3 /permissive- /EHsc /std:c++20)
    add_compile_options($<$<CONFIG:Release>:/O2> $<$<CONFIG:Debug>:/Od /Zi>)
    add_definitions(-DNOMINMAX -D_WIN32_WINNT=0x0A00 -D_CRT_SECURE_NO_WARNINGS)
endif()

# Vulkan
find_package(Vulkan REQUIRED)
if(NOT Vulkan_FOUND)
    message(FATAL_ERROR "Vulkan SDK not found. Install Vulkan SDK 1.3+")
endif()

# Source files (patched versions overlay original)
set(PATCHED_SOURCES
    src/deep2/vulkan_compute.h
    src/deep2/vulkan_compute.cpp
    # Other patched files would be listed here
)

# Main library
add_library(deep2_gpu_hardening STATIC
    src/deep2/vulkan_compute.cpp
    # ... other deep2 sources ...
)

target_include_directories(deep2_gpu_hardening PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${Vulkan_INCLUDE_DIRS}
)

target_link_libraries(deep2_gpu_hardening PUBLIC
    ${Vulkan_LIBRARIES}
)

# Strata benchmark executable
add_executable(deep2_strata_bench
    src/tools/deep2_strata_bench.cpp
)

target_link_libraries(deep2_strata_bench PRIVATE
    deep2_gpu_hardening
)

# Install
install(TARGETS deep2_strata_bench RUNTIME DESTINATION bin)
install(TARGETS deep2_gpu_hardening ARCHIVE DESTINATION lib)
install(FILES src/deep2/vulkan_compute.h DESTINATION include/deep2)