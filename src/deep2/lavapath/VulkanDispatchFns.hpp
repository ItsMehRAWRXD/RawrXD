#pragma once
/* VulkanDispatchFns — opaque PFNs for scoreboard async. LIVE=0. ≤99. */
#include <cstdint>

namespace Deep2 {
namespace scoreboard {

using VkDeviceOpaque = void*;
using VkQueueOpaque = void*;
using VkFenceOpaque = void*;

using PfnCreateFence = int (*)(VkDeviceOpaque, VkFenceOpaque* out, void* ud);
using PfnDestroyFence = void (*)(VkDeviceOpaque, VkFenceOpaque, void* ud);
using PfnResetFences = int (*)(VkDeviceOpaque, uint32_t, VkFenceOpaque*, void*);
using PfnWaitFences = int (*)(VkDeviceOpaque, uint32_t, VkFenceOpaque*, int waitAll,
                              uint64_t timeoutNs, void* ud);
using PfnGetFenceStatus = int (*)(VkDeviceOpaque, VkFenceOpaque, void* ud);
using PfnQueueSubmit = int (*)(VkQueueOpaque, uint32_t, void* submits, VkFenceOpaque,
                               void* ud);

struct VkDispatchFns {
    VkDeviceOpaque device = nullptr;
    VkQueueOpaque queue = nullptr;
    void* ud = nullptr;
    PfnCreateFence createFence = nullptr;
    PfnDestroyFence destroyFence = nullptr;
    PfnResetFences resetFences = nullptr;
    PfnWaitFences waitFences = nullptr;
    PfnGetFenceStatus getFenceStatus = nullptr;
    PfnQueueSubmit queueSubmit = nullptr;
};

} /* namespace scoreboard */
} /* namespace Deep2 */
