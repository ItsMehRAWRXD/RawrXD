; ============================================================================
; Vulkan Types and Constants - MASM x64 Implementation
; ============================================================================
; This file defines Vulkan structures, constants, and types for pure MASM x64
; ============================================================================

; Vulkan API Version
VK_API_VERSION_1_0 EQU 4194304  ; 1.0.0
VK_API_VERSION_1_1 EQU 4198400  ; 1.1.0
VK_API_VERSION_1_2 EQU 4202496  ; 1.2.0
VK_API_VERSION_1_3 EQU 4206592  ; 1.3.0

; Result codes
VK_SUCCESS EQU 0
VK_NOT_READY EQU 1
VK_TIMEOUT EQU 2
VK_EVENT_SET EQU 3
VK_EVENT_RESET EQU 4
VK_INCOMPLETE EQU 5
VK_ERROR_OUT_OF_HOST_MEMORY EQU -1
VK_ERROR_OUT_OF_DEVICE_MEMORY EQU -2
VK_ERROR_INITIALIZATION_FAILED EQU -3
VK_ERROR_DEVICE_LOST EQU -4
VK_ERROR_MEMORY_MAP_FAILED EQU -5

; Queue flags
VK_QUEUE_GRAPHICS_BIT EQU 1h
VK_QUEUE_COMPUTE_BIT EQU 2h
VK_QUEUE_TRANSFER_BIT EQU 4h

; Memory property flags
VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT EQU 1h
VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT EQU 2h
VK_MEMORY_PROPERTY_HOST_COHERENT_BIT EQU 4h
VK_MEMORY_PROPERTY_HOST_CACHED_BIT EQU 8h

; Buffer usage flags
VK_BUFFER_USAGE_TRANSFER_SRC_BIT EQU 1h
VK_BUFFER_USAGE_TRANSFER_DST_BIT EQU 2h
VK_BUFFER_USAGE_UNIFORM_BUFFER_BIT EQU 10h
VK_BUFFER_USAGE_STORAGE_BUFFER_BIT EQU 20h

; Structure type enums
VK_STRUCTURE_TYPE_APPLICATION_INFO EQU 0
VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO EQU 1
VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO EQU 3
VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO EQU 12
VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO EQU 5

; Fence create flags
VK_FENCE_CREATE_SIGNALED_BIT EQU 1h

; Command buffer level
VK_COMMAND_BUFFER_LEVEL_PRIMARY EQU 0
VK_COMMAND_BUFFER_LEVEL_SECONDARY EQU 1

; Pipeline bind point
VK_PIPELINE_BIND_POINT_GRAPHICS EQU 0
VK_PIPELINE_BIND_POINT_COMPUTE EQU 1

; ============================================================================
; Vulkan Structures
; ============================================================================

; VkApplicationInfo
VkApplicationInfo STRUCT
    sType               QWORD ?    ; VkStructureType
    pNext               QWORD ?    ; const void*
    pApplicationName    QWORD ?    ; const char*
    applicationVersion  DWORD ?    ; uint32_t
    pEngineName         QWORD ?    ; const char*
    engineVersion       DWORD ?    ; uint32_t
    apiVersion          DWORD ?    ; uint32_t
VkApplicationInfo ENDS

; VkInstanceCreateInfo
VkInstanceCreateInfo STRUCT
    sType                       QWORD ?    ; VkStructureType
    pNext                       QWORD ?    ; const void*
    flags                       DWORD ?    ; VkInstanceCreateFlags
    pApplicationInfo            QWORD ?    ; const VkApplicationInfo*
    enabledLayerCount           DWORD ?    ; uint32_t
    ppEnabledLayerNames         QWORD ?    ; const char* const*
    enabledExtensionCount       DWORD ?    ; uint32_t
    ppEnabledExtensionNames     QWORD ?    ; const char* const*
VkInstanceCreateInfo ENDS

; VkPhysicalDevice Handle
VkPhysicalDevice TYPEDEF QWORD
VkDevice TYPEDEF QWORD
VkInstance TYPEDEF QWORD
VkQueue TYPEDEF QWORD
VkCommandBuffer TYPEDEF QWORD
VkCommandPool TYPEDEF QWORD
VkBuffer TYPEDEF QWORD
VkDeviceMemory TYPEDEF QWORD
VkFence TYPEDEF QWORD
VkSemaphore TYPEDEF QWORD

; VkDeviceQueueCreateInfo
VkDeviceQueueCreateInfo STRUCT
    sType               QWORD ?    ; VkStructureType
    pNext               QWORD ?    ; const void*
    flags               DWORD ?    ; VkDeviceQueueCreateFlags
    queueFamilyIndex    DWORD ?    ; uint32_t
    queueCount          DWORD ?    ; uint32_t
    pQueuePriorities    QWORD ?    ; const float*
VkDeviceQueueCreateInfo ENDS

; VkDeviceCreateInfo
VkDeviceCreateInfo STRUCT
    sType                       QWORD ?    ; VkStructureType
    pNext                       QWORD ?    ; const void*
    flags                       DWORD ?    ; VkDeviceCreateFlags
    queueCreateInfoCount        DWORD ?    ; uint32_t
    pQueueCreateInfos           QWORD ?    ; const VkDeviceQueueCreateInfo*
    enabledLayerCount           DWORD ?    ; uint32_t
    ppEnabledLayerNames         QWORD ?    ; const char* const*
    enabledExtensionCount       DWORD ?    ; uint32_t
    ppEnabledExtensionNames     QWORD ?    ; const char* const*
    pEnabledFeatures            QWORD ?    ; const VkPhysicalDeviceFeatures*
VkDeviceCreateInfo ENDS

; VkBufferCreateInfo
VkBufferCreateInfo STRUCT
    sType                   QWORD ?    ; VkStructureType
    pNext                   QWORD ?    ; const void*
    flags                   DWORD ?    ; VkBufferCreateFlags
    size                    QWORD ?    ; VkDeviceSize
    usage                   DWORD ?    ; VkBufferUsageFlags
    sharingMode             DWORD ?    ; VkSharingMode
    queueFamilyIndexCount   DWORD ?    ; uint32_t
    pQueueFamilyIndices     QWORD ?    ; const uint32_t*
VkBufferCreateInfo ENDS

; VkMemoryAllocateInfo
VkMemoryAllocateInfo STRUCT
    sType               QWORD ?    ; VkStructureType
    pNext               QWORD ?    ; const void*
    allocationSize      QWORD ?    ; VkDeviceSize
    memoryTypeIndex     DWORD ?    ; uint32_t
VkMemoryAllocateInfo ENDS

; VkCommandBufferAllocateInfo
VkCommandBufferAllocateInfo STRUCT
    sType               QWORD ?    ; VkStructureType
    pNext               QWORD ?    ; const void*
    commandPool         QWORD ?    ; VkCommandPool
    level               DWORD ?    ; VkCommandBufferLevel
    commandBufferCount  DWORD ?    ; uint32_t
VkCommandBufferAllocateInfo ENDS

; VkFenceCreateInfo
VkFenceCreateInfo STRUCT
    sType   QWORD ?    ; VkStructureType
    pNext   QWORD ?    ; const void*
    flags   DWORD ?    ; VkFenceCreateFlags
VkFenceCreateInfo ENDS

; ============================================================================
; Custom internal structures for tracking
; ============================================================================

; Internal instance tracking
VkInternalInstance STRUCT
    handle              QWORD ?    ; VkInstance
    physicalDevice      QWORD ?    ; VkPhysicalDevice
    device              QWORD ?    ; VkDevice
    computeQueue        QWORD ?    ; VkQueue
    commandPool         QWORD ?    ; VkCommandPool
    queueFamilyIndex    DWORD ?    ; uint32_t
    isInitialized       DWORD ?    ; bool (0 or 1)
VkInternalInstance ENDS

; Internal buffer tracking
VkInternalBuffer STRUCT
    buffer      QWORD ?    ; VkBuffer
    memory      QWORD ?    ; VkDeviceMemory
    size        QWORD ?    ; VkDeviceSize
    flags       DWORD ?    ; usage flags
    mapped      QWORD ?    ; void* (if host-visible)
VkInternalBuffer ENDS

; Tensor descriptor
TensorDescriptor STRUCT
    data        QWORD ?    ; void* to data
    dimensions  DWORD 8 DUP (?)    ; int32_t[8] shape
    numDims     DWORD ?    ; number of dimensions
    dataType    DWORD ?    ; type enum (FP32, FP16, INT8, etc.)
    totalSize   QWORD ?    ; total size in bytes
TensorDescriptor ENDS

; ============================================================================
; End of vulkan_types.inc
; ============================================================================
