# FindRawrXDDeps.cmake
# CMake module to find RawrXD dependencies
#
# This module will define:
#   RAWRXD_VULKAN_FOUND
#   RAWRXD_VULKAN_INCLUDE_DIRS
#   RAWRXD_VULKAN_LIBRARIES
#   RAWRXD_CUDA_FOUND
#   RAWRXD_CUDA_INCLUDE_DIRS
#   RAWRXD_CUDA_LIBRARIES

include(FindPackageHandleStandardArgs)

# Find Vulkan
if(RAWRXD_ENABLE_VULKAN)
    find_path(RAWRXD_VULKAN_INCLUDE_DIR
        NAMES vulkan/vulkan.h
        PATHS
            $ENV{VULKAN_SDK}/Include
            "C:/VulkanSDK/Include"
            "D:/VulkanSDK/Include"
    )
    
    find_library(RAWRXD_VULKAN_LIBRARY
        NAMES vulkan-1 vulkan
        PATHS
            $ENV{VULKAN_SDK}/Lib
            "C:/VulkanSDK/Lib"
            "D:/VulkanSDK/Lib"
    )
    
    if(RAWRXD_VULKAN_INCLUDE_DIR AND RAWRXD_VULKAN_LIBRARY)
        set(RAWRXD_VULKAN_FOUND TRUE)
        set(RAWRXD_VULKAN_INCLUDE_DIRS ${RAWRXD_VULKAN_INCLUDE_DIR})
        set(RAWRXD_VULKAN_LIBRARIES ${RAWRXD_VULKAN_LIBRARY})
    else()
        set(RAWRXD_VULKAN_FOUND FALSE)
    endif()
    
    find_package_handle_standard_args(RawrXDVulkan
        REQUIRED_VARS RAWRXD_VULKAN_INCLUDE_DIR RAWRXD_VULKAN_LIBRARY
    )
endif()

# Find CUDA
if(RAWRXD_ENABLE_CUDA)
    find_path(RAWRXD_CUDA_INCLUDE_DIR
        NAMES cuda_runtime.h
        PATHS
            $ENV{CUDA_PATH}/include
            "C:/Program Files/NVIDIA GPU Computing Toolkit/CUDA/v12.2/include"
            "C:/Program Files/NVIDIA GPU Computing Toolkit/CUDA/v12.1/include"
            "C:/Program Files/NVIDIA GPU Computing Toolkit/CUDA/v12.0/include"
            "C:/Program Files/NVIDIA GPU Computing Toolkit/CUDA/v11.8/include"
    )
    
    find_library(RAWRXD_CUDA_LIBRARY
        NAMES cudart
        PATHS
            $ENV{CUDA_PATH}/lib/x64
            "C:/Program Files/NVIDIA GPU Computing Toolkit/CUDA/v12.2/lib/x64"
            "C:/Program Files/NVIDIA GPU Computing Toolkit/CUDA/v12.1/lib/x64"
            "C:/Program Files/NVIDIA GPU Computing Toolkit/CUDA/v12.0/lib/x64"
            "C:/Program Files/NVIDIA GPU Computing Toolkit/CUDA/v11.8/lib/x64"
    )
    
    if(RAWRXD_CUDA_INCLUDE_DIR AND RAWRXD_CUDA_LIBRARY)
        set(RAWRXD_CUDA_FOUND TRUE)
        set(RAWRXD_CUDA_INCLUDE_DIRS ${RAWRXD_CUDA_INCLUDE_DIR})
        set(RAWRXD_CUDA_LIBRARIES ${RAWRXD_CUDA_LIBRARY})
    else()
        set(RAWRXD_CUDA_FOUND FALSE)
    endif()
    
    find_package_handle_standard_args(RawrXDCUDA
        REQUIRED_VARS RAWRXD_CUDA_INCLUDE_DIR RAWRXD_CUDA_LIBRARY
    )
endif()

# Find ROCm/HIP
if(RAWRXD_ENABLE_ROCM)
    find_path(RAWRXD_ROCM_INCLUDE_DIR
        NAMES hip/hip_runtime.h
        PATHS
            $ENV{ROCM_PATH}/include
            /opt/rocm/include
            "C:/Program Files/AMD/ROCm/*/include"
    )
    
    find_library(RAWRXD_ROCM_LIBRARY
        NAMES amdhip64
        PATHS
            $ENV{ROCM_PATH}/lib
            /opt/rocm/lib
            "C:/Program Files/AMD/ROCm/*/lib"
    )
    
    if(RAWRXD_ROCM_INCLUDE_DIR AND RAWRXD_ROCM_LIBRARY)
        set(RAWRXD_ROCM_FOUND TRUE)
        set(RAWRXD_ROCM_INCLUDE_DIRS ${RAWRXD_ROCM_INCLUDE_DIR})
        set(RAWRXD_ROCM_LIBRARIES ${RAWRXD_ROCM_LIBRARY})
    else()
        set(RAWRXD_ROCM_FOUND FALSE)
    endif()
    
    find_package_handle_standard_args(RawrXDROCM
        REQUIRED_VARS RAWRXD_ROCM_INCLUDE_DIR RAWRXD_ROCM_LIBRARY
    )
endif()

# Find OpenCL
if(RAWRXD_ENABLE_OPENCL)
    find_path(RAWRXD_OPENCL_INCLUDE_DIR
        NAMES CL/cl.h
        PATHS
            $ENV{INTELOCLSDKROOT}/include
            $ENV{AMDAPPSDKROOT}/include
            $ENV{CUDA_PATH}/include
            /usr/include
    )
    
    find_library(RAWRXD_OPENCL_LIBRARY
        NAMES OpenCL
        PATHS
            $ENV{INTELOCLSDKROOT}/lib/x64
            $ENV{AMDAPPSDKROOT}/lib/x86_64
            $ENV{CUDA_PATH}/lib/x64
            /usr/lib/x86_64-linux-gnu
    )
    
    if(RAWRXD_OPENCL_INCLUDE_DIR AND RAWRXD_OPENCL_LIBRARY)
        set(RAWRXD_OPENCL_FOUND TRUE)
        set(RAWRXD_OPENCL_INCLUDE_DIRS ${RAWRXD_OPENCL_INCLUDE_DIR})
        set(RAWRXD_OPENCL_LIBRARIES ${RAWRXD_OPENCL_LIBRARY})
    else()
        set(RAWRXD_OPENCL_FOUND FALSE)
    endif()
    
    find_package_handle_standard_args(RawrXDOpenCL
        REQUIRED_VARS RAWRXD_OPENCL_INCLUDE_DIR RAWRXD_OPENCL_LIBRARY
    )
endif()

# Find Metal (macOS only)
if(RAWRXD_ENABLE_METAL AND APPLE)
    find_library(RAWRXD_METAL_FRAMEWORK Metal)
    find_library(RAWRXD_FOUNDATION_FRAMEWORK Foundation)
    
    if(RAWRXD_METAL_FRAMEWORK AND RAWRXD_FOUNDATION_FRAMEWORK)
        set(RAWRXD_METAL_FOUND TRUE)
        set(RAWRXD_METAL_LIBRARIES 
            ${RAWRXD_METAL_FRAMEWORK}
            ${RAWRXD_FOUNDATION_FRAMEWORK}
        )
    else()
        set(RAWRXD_METAL_FOUND FALSE)
    endif()
    
    find_package_handle_standard_args(RawrXDMetal
        REQUIRED_VARS RAWRXD_METAL_FRAMEWORK
    )
endif()

# Print summary
function(rawrxd_print_deps_summary)
    message(STATUS "")
    message(STATUS "Dependency Summary:")
    message(STATUS "  Vulkan: ${RAWRXD_VULKAN_FOUND}")
    message(STATUS "  CUDA: ${RAWRXD_CUDA_FOUND}")
    message(STATUS "  ROCm: ${RAWRXD_ROCM_FOUND}")
    message(STATUS "  OpenCL: ${RAWRXD_OPENCL_FOUND}")
    if(APPLE)
        message(STATUS "  Metal: ${RAWRXD_METAL_FOUND}")
    endif()
    message(STATUS "")
endfunction()
