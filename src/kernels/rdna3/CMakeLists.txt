# CMakeLists.txt for RDNA3 Kernels
# Target: RX 7800 XT (gfx1101)

cmake_minimum_required(VERSION 3.20)

# RDNA3 Kernel Library
add_library(RDNA3_Kernels STATIC
    RDNA3_GpuDispatcher.cpp
    RDNA3_GpuDispatcher.h
)

# Pre-built assembly object
target_sources(RDNA3_Kernels PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/obj/RDNA3_AllInOne.obj
)

# Include directories
target_include_directories(RDNA3_Kernels PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Compiler flags for C++20
target_compile_features(RDNA3_Kernels PUBLIC cxx_std_20)

# Windows-specific settings
if(WIN32)
    target_compile_definitions(RDNA3_Kernels PRIVATE
        _WIN32_WINNT=0x0A00
        NOMINMAX
    )
endif()

# Installation
install(TARGETS RDNA3_Kernels
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)

install(FILES
    RDNA3_GpuDispatcher.h
    DESTINATION include/rdna3
)

# Print configuration message
message(STATUS "RDNA3 Kernels configured for RX 7800 XT (gfx1101)")
message(STATUS "  Compute Units: 60")
message(STATUS "  LDS per CU: 128KB")
message(STATUS "  VRAM: 16GB")
