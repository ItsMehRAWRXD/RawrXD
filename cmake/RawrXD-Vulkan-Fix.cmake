# RawrXD-Vulkan-Fix.cmake
# Fixes: CMake not finding Vulkan SDK on Windows when installed
#        to non-standard path or when VULKAN_SDK env var is stale.

message(STATUS "[RawrXD] Vulkan detection fix — Phase 4A")

# ─── 1. Hardcode known Vulkan SDK paths ─────────────────────────────
set(_VULKAN_CANDIDATES
    "$ENV{VULKAN_SDK}"
    "$ENV{VULKAN_SDK}/Include"
    "C:/VulkanSDK/1.4.328.1/Include"
    "C:/VulkanSDK/1.3.296.0/Include"
    "C:/VulkanSDK/1.3.290.0/Include"
    "C:/VulkanSDK/1.3.280.0/Include"
    "C:/VulkanSDK/1.3.275.0/Include"
    "C:/VulkanSDK/1.3.268.0/Include"
    "C:/VulkanSDK/1.3.261.1/Include"
    "C:/VulkanSDK/1.3.250.1/Include"
    "C:/VulkanSDK/1.3.239.0/Include"
    "C:/VulkanSDK/1.3.231.1/Include"
    "C:/VulkanSDK/1.3.224.1/Include"
    "C:/VulkanSDK/1.3.216.0/Include"
    "C:/VulkanSDK/1.3.211.0/Include"
    "C:/VulkanSDK/1.3.204.1/Include"
    "C:/VulkanSDK/1.2.198.1/Include"
    "C:/VulkanSDK/1.2.189.2/Include"
)

set(VULKAN_INCLUDE_DIR "")
foreach(_candidate ${_VULKAN_CANDIDATES})
    if(EXISTS "${_candidate}/vulkan/vulkan.h")
        get_filename_component(VULKAN_INCLUDE_DIR "${_candidate}" ABSOLUTE)
        message(STATUS "[RawrXD] Found Vulkan headers: ${VULKAN_INCLUDE_DIR}")
        break()
    endif()
endforeach()

# ─── 2. Find Vulkan library ─────────────────────────────────────────
set(_VULKAN_LIB_CANDIDATES
    "$ENV{VULKAN_SDK}/Lib/vulkan-1.lib"
    "C:/VulkanSDK/1.4.328.1/Lib/vulkan-1.lib"
    "C:/VulkanSDK/1.3.296.0/Lib/vulkan-1.lib"
    "C:/VulkanSDK/1.3.290.0/Lib/vulkan-1.lib"
    "C:/VulkanSDK/1.3.280.0/Lib/vulkan-1.lib"
    "C:/VulkanSDK/1.3.275.0/Lib/vulkan-1.lib"
    "C:/VulkanSDK/1.3.268.0/Lib/vulkan-1.lib"
    "C:/VulkanSDK/1.3.261.1/Lib/vulkan-1.lib"
    "C:/VulkanSDK/1.3.250.1/Lib/vulkan-1.lib"
    "C:/VulkanSDK/1.3.239.0/Lib/vulkan-1.lib"
    "C:/VulkanSDK/1.3.231.1/Lib/vulkan-1.lib"
    "C:/VulkanSDK/1.3.224.1/Lib/vulkan-1.lib"
    "C:/VulkanSDK/1.3.216.0/Lib/vulkan-1.lib"
    "C:/VulkanSDK/1.3.211.0/Lib/vulkan-1.lib"
    "C:/VulkanSDK/1.3.204.1/Lib/vulkan-1.lib"
    "C:/VulkanSDK/1.2.198.1/Lib/vulkan-1.lib"
    "C:/VulkanSDK/1.2.189.2/Lib/vulkan-1.lib"
)

set(VULKAN_LIBRARY "")
foreach(_candidate ${_VULKAN_LIB_CANDIDATES})
    if(EXISTS "${_candidate}")
        get_filename_component(VULKAN_LIBRARY "${_candidate}" ABSOLUTE)
        message(STATUS "[RawrXD] Found Vulkan library: ${VULKAN_LIBRARY}")
        break()
    endif()
endforeach()

# ─── 3. Validation & target creation ──────────────────────────────
if(VULKAN_INCLUDE_DIR AND VULKAN_LIBRARY)
    set(RAWR_ENABLE_VULKAN ON CACHE BOOL "Vulkan compute enabled" FORCE)
    
    if(NOT TARGET Vulkan::Vulkan)
        add_library(Vulkan::Vulkan UNKNOWN IMPORTED)
        set_target_properties(Vulkan::Vulkan PROPERTIES
            IMPORTED_LOCATION "${VULKAN_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${VULKAN_INCLUDE_DIR}"
        )
    endif()
    
    message(STATUS "[RawrXD] ✅ Vulkan FULLY ENABLED")
    message(STATUS "[RawrXD]   Include: ${VULKAN_INCLUDE_DIR}")
    message(STATUS "[RawrXD]   Library: ${VULKAN_LIBRARY}")
    
    add_compile_definitions(
        RAWR_ENABLE_VULKAN=1
        VULKAN_HPP_DISPATCH_LOADER_DYNAMIC=1
    )
    
else()
    message(WARNING "[RawrXD] ⚠️ Vulkan SDK not found - GPU dispatch disabled")
    set(RAWR_ENABLE_VULKAN OFF CACHE BOOL "" FORCE)
endif()
