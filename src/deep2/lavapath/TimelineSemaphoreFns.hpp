#pragma once
/* TimelineSemaphoreFns — opaque PFNs (no vulkan.h at tip). LIVE=0. ≤99. */
#include <cstdint>

namespace Deep2 {
namespace scoreboard {

using VkDev = void*;
using VkQue = void*;
using VkSem = void*;

/* Returns 0 on success (Vulkan-shaped). */
using PfnCreateTimelineSem = int (*)(VkDev, uint64_t initial, VkSem* out, void* ud);
using PfnDestroySem = void (*)(VkDev, VkSem, void* ud);
using PfnGetSemCounter = int (*)(VkDev, VkSem, uint64_t* valueOut, void* ud);
using PfnWaitTimeline = int (*)(VkDev, VkSem, uint64_t value, uint64_t timeoutNs,
                                void* ud);
using PfnQueueSubmitCmds = int (*)(VkQue, void* cmdBuffers, uint32_t cmdCount,
                                   VkSem waitSem, uint64_t waitValue,
                                   VkSem signalSem, uint64_t signalValue, void* ud);

struct TimelineSemaphoreFns {
    VkDev device = nullptr;
    VkQue transferQ = nullptr;
    VkQue computeQ = nullptr;
    void* ud = nullptr;
    PfnCreateTimelineSem createTimeline = nullptr;
    PfnDestroySem destroySem = nullptr;
    PfnGetSemCounter getCounter = nullptr;
    PfnWaitTimeline waitTimeline = nullptr;
    PfnQueueSubmitCmds queueSubmit = nullptr;
};

} /* namespace scoreboard */
} /* namespace Deep2 */
