/* d2_live_vk_lane.cpp — device-local fill submit + collect */
#define VK_NO_PROTOTYPES
#include <vulkan/vulkan.h>
#include <windows.h>
#include <string.h>
#include "d2_live_vk.h"

extern PFN_vkGetDeviceProcAddr g_gdpa; /* set in open — reload locally */
static PFN_vkCreateBuffer g_cb;
static PFN_vkDestroyBuffer g_db;
static PFN_vkGetBufferMemoryRequirements g_br;
static PFN_vkAllocateMemory g_am;
static PFN_vkFreeMemory g_fm;
static PFN_vkBindBufferMemory g_bb;
static PFN_vkAllocateCommandBuffers g_ac;
static PFN_vkFreeCommandBuffers g_fc;
static PFN_vkBeginCommandBuffer g_bc;
static PFN_vkEndCommandBuffer g_ec;
static PFN_vkCmdFillBuffer g_fill;
static PFN_vkQueueSubmit g_qs;
static PFN_vkQueueWaitIdle g_qi;
static PFN_vkDestroyCommandPool g_dcp;
static PFN_vkDestroyDevice g_dd;
static PFN_vkGetPhysicalDeviceMemoryProperties g_mp;
static PFN_vkDestroyInstance g_di;
static int g_syms;

static void load_syms(VkDevice dev, VkInstance inst, PFN_vkGetInstanceProcAddr gipa) {
    if (g_syms) return;
    auto gdpa = (PFN_vkGetDeviceProcAddr)gipa(inst, "vkGetDeviceProcAddr");
    g_cb = (PFN_vkCreateBuffer)gdpa(dev, "vkCreateBuffer");
    g_db = (PFN_vkDestroyBuffer)gdpa(dev, "vkDestroyBuffer");
    g_br = (PFN_vkGetBufferMemoryRequirements)gdpa(dev, "vkGetBufferMemoryRequirements");
    g_am = (PFN_vkAllocateMemory)gdpa(dev, "vkAllocateMemory");
    g_fm = (PFN_vkFreeMemory)gdpa(dev, "vkFreeMemory");
    g_bb = (PFN_vkBindBufferMemory)gdpa(dev, "vkBindBufferMemory");
    g_ac = (PFN_vkAllocateCommandBuffers)gdpa(dev, "vkAllocateCommandBuffers");
    g_fc = (PFN_vkFreeCommandBuffers)gdpa(dev, "vkFreeCommandBuffers");
    g_bc = (PFN_vkBeginCommandBuffer)gdpa(dev, "vkBeginCommandBuffer");
    g_ec = (PFN_vkEndCommandBuffer)gdpa(dev, "vkEndCommandBuffer");
    g_fill = (PFN_vkCmdFillBuffer)gdpa(dev, "vkCmdFillBuffer");
    g_qs = (PFN_vkQueueSubmit)gdpa(dev, "vkQueueSubmit");
    g_qi = (PFN_vkQueueWaitIdle)gdpa(dev, "vkQueueWaitIdle");
    g_dcp = (PFN_vkDestroyCommandPool)gdpa(dev, "vkDestroyCommandPool");
    g_dd = (PFN_vkDestroyDevice)gdpa(dev, "vkDestroyDevice");
    g_mp = (PFN_vkGetPhysicalDeviceMemoryProperties)gipa(inst, "vkGetPhysicalDeviceMemoryProperties");
    g_di = (PFN_vkDestroyInstance)gipa(inst, "vkDestroyInstance");
    g_syms = 1;
}

static uint32_t find_local(VkPhysicalDevice p, uint32_t bits) {
    VkPhysicalDeviceMemoryProperties mp; g_mp(p, &mp);
    for (uint32_t i = 0; i < mp.memoryTypeCount; ++i)
        if ((bits & (1u << i)) &&
            (mp.memoryTypes[i].propertyFlags & VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT))
            return i;
    return UINT32_MAX;
}

extern "C" int d2_live_enqueue_lane(D2LiveCtx* c, uint32_t gpu, uint64_t bytes) {
    if (!c || !c->ready || gpu > 1 || !bytes) return 0;
    D2LiveLane* L = &c->lane[gpu];
    auto gipa = (PFN_vkGetInstanceProcAddr)GetProcAddress((HMODULE)c->lib, "vkGetInstanceProcAddr");
    load_syms((VkDevice)L->dev, (VkInstance)c->inst, gipa);
    if (L->buf) { g_db((VkDevice)L->dev, (VkBuffer)L->buf, 0); L->buf = 0; }
    if (L->mem) { g_fm((VkDevice)L->dev, (VkDeviceMemory)L->mem, 0); L->mem = 0; }
    VkBufferCreateInfo bi{VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO};
    bi.size = bytes; bi.usage = VK_BUFFER_USAGE_TRANSFER_DST_BIT | VK_BUFFER_USAGE_STORAGE_BUFFER_BIT;
    VkBuffer buf = 0;
    if (g_cb((VkDevice)L->dev, &bi, 0, &buf) != VK_SUCCESS) return 0;
    VkMemoryRequirements req; g_br((VkDevice)L->dev, buf, &req);
    uint32_t mi = find_local((VkPhysicalDevice)L->phys, req.memoryTypeBits);
    if (mi == UINT32_MAX) { g_db((VkDevice)L->dev, buf, 0); return 0; }
    VkMemoryAllocateInfo ai{VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO};
    ai.allocationSize = req.size; ai.memoryTypeIndex = mi;
    VkDeviceMemory mem = 0;
    if (g_am((VkDevice)L->dev, &ai, 0, &mem) != VK_SUCCESS) {
        g_db((VkDevice)L->dev, buf, 0); return 0;
    }
    g_bb((VkDevice)L->dev, buf, mem, 0);
    L->buf = buf; L->mem = mem; L->local_bytes = bytes;
    VkCommandBufferAllocateInfo cai{VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO};
    cai.commandPool = (VkCommandPool)L->pool; cai.commandBufferCount = 1;
    cai.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    VkCommandBuffer cb = 0;
    if (g_ac((VkDevice)L->dev, &cai, &cb) != VK_SUCCESS) return 0;
    VkCommandBufferBeginInfo bgi{VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO};
    bgi.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    g_bc(cb, &bgi);
    /* multiple fills to create sustained local traffic */
    for (int i = 0; i < 8; ++i) g_fill(cb, buf, 0, bytes, 0xA5A5A5A5u + (uint32_t)i);
    g_ec(cb);
    L->cb = cb; L->submitted = 0; L->collected = 0;
    L->start_ns = d2_live_qpc_ns();
    VkSubmitInfo si{VK_STRUCTURE_TYPE_SUBMIT_INFO};
    si.commandBufferCount = 1; si.pCommandBuffers = &cb;
    if (g_qs((VkQueue)L->q, 1, &si, VK_NULL_HANDLE) != VK_SUCCESS) {
        L->device_lost = 1; return 0;
    }
    L->submitted = 1; L->real_forwards = 1; return 1;
}

extern "C" int d2_live_collect_lane(D2LiveCtx* c, uint32_t gpu) {
    if (!c || gpu > 1) return 0;
    D2LiveLane* L = &c->lane[gpu];
    if (!L->submitted) return 0;
    auto gipa = (PFN_vkGetInstanceProcAddr)GetProcAddress((HMODULE)c->lib, "vkGetInstanceProcAddr");
    load_syms((VkDevice)L->dev, (VkInstance)c->inst, gipa);
    if (g_qi((VkQueue)L->q) != VK_SUCCESS) { L->device_lost = 1; return 0; }
    L->end_ns = d2_live_qpc_ns();
    L->collected = 1;
    if (L->cb) {
        g_fc((VkDevice)L->dev, (VkCommandPool)L->pool, 1, (VkCommandBuffer*)&L->cb);
        L->cb = 0;
    }
    return (L->end_ns > L->start_ns) ? 1 : 0;
}

extern "C" void d2_live_close(D2LiveCtx* c) {
    if (!c) return;
    auto gipa = (PFN_vkGetInstanceProcAddr)GetProcAddress((HMODULE)c->lib, "vkGetInstanceProcAddr");
    for (int i = 0; i < 2; ++i) {
        D2LiveLane* L = &c->lane[i];
        if (!L->dev) continue;
        load_syms((VkDevice)L->dev, (VkInstance)c->inst, gipa);
        if (L->buf) g_db((VkDevice)L->dev, (VkBuffer)L->buf, 0);
        if (L->mem) g_fm((VkDevice)L->dev, (VkDeviceMemory)L->mem, 0);
        if (L->pool) g_dcp((VkDevice)L->dev, (VkCommandPool)L->pool, 0);
        g_dd((VkDevice)L->dev, 0);
    }
    if (c->inst && g_di) g_di((VkInstance)c->inst, 0);
    if (c->lib) FreeLibrary((HMODULE)c->lib);
    memset(c, 0, sizeof *c);
}
