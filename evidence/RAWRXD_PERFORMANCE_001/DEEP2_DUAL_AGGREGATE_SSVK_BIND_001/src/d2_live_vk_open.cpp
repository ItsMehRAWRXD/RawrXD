/* d2_live_vk_open.cpp — open R9700 + 7800 XT proprietary Vulkan devices */
#define VK_NO_PROTOTYPES
#include <vulkan/vulkan.h>
#include <windows.h>
#include <string.h>
#include <stdio.h>
#include "d2_live_vk.h"

static PFN_vkGetInstanceProcAddr g_gipa;
static PFN_vkCreateInstance g_ci;
static PFN_vkDestroyInstance g_di;
static PFN_vkEnumeratePhysicalDevices g_enum;
static PFN_vkGetPhysicalDeviceProperties g_props;
static PFN_vkGetPhysicalDeviceQueueFamilyProperties g_qf;
static PFN_vkGetPhysicalDeviceMemoryProperties g_mp;
static PFN_vkCreateDevice g_cd;
static PFN_vkDestroyDevice g_dd;
static PFN_vkGetDeviceQueue g_gq;
static PFN_vkCreateCommandPool g_cp;
static PFN_vkDestroyCommandPool g_dcp;
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
static PFN_vkGetDeviceProcAddr g_gdpa;

uint64_t d2_live_qpc_ns(void) {
    LARGE_INTEGER f, c; QueryPerformanceFrequency(&f); QueryPerformanceCounter(&c);
    uint64_t fq = (uint64_t)f.QuadPart, cq = (uint64_t)c.QuadPart;
    return (cq / fq) * 1000000000ull + ((cq % fq) * 1000000000ull) / fq;
}

static int name_ok(const char* n, int want_gpu0) {
    if (strstr(n, "Direct3D12")) return 0;
    if (want_gpu0) return strstr(n, "R9700") != 0;
    return strstr(n, "7800 XT") != 0;
}

static int pick_qfam(VkPhysicalDevice p, uint32_t* fam) {
    uint32_t n = 0; g_qf(p, &n, 0);
    VkQueueFamilyProperties q[8]; if (n > 8) n = 8; g_qf(p, &n, q);
    for (uint32_t i = 0; i < n; ++i)
        if (q[i].queueFlags & VK_QUEUE_COMPUTE_BIT) { *fam = i; return 1; }
    return 0;
}

static uint32_t find_mem(VkPhysicalDevice p, uint32_t bits) {
    VkPhysicalDeviceMemoryProperties mp; g_mp(p, &mp);
    for (uint32_t i = 0; i < mp.memoryTypeCount; ++i)
        if ((bits & (1u << i)) && (mp.memoryTypes[i].propertyFlags & VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT))
            return i;
    return UINT32_MAX;
}

static int open_lane(D2LiveCtx* c, D2LiveLane* L, VkPhysicalDevice p) {
    float pri = 1.f; uint32_t fam = 0;
    if (!pick_qfam(p, &fam)) return 0;
    VkDeviceQueueCreateInfo qci{VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO};
    qci.queueFamilyIndex = fam; qci.queueCount = 1; qci.pQueuePriorities = &pri;
    const char* dexts[] = { "VK_EXT_calibrated_timestamps" };
    VkDeviceCreateInfo dci{VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO};
    dci.queueCreateInfoCount = 1; dci.pQueueCreateInfos = &qci;
    dci.enabledExtensionCount = 1; dci.ppEnabledExtensionNames = dexts;
    VkDevice dev = 0;
    if (g_cd(p, &dci, 0, &dev) != VK_SUCCESS) {
        /* retry without ext so older probes still open; material gate fails closed later */
        dci.enabledExtensionCount = 0; dci.ppEnabledExtensionNames = 0;
        if (g_cd(p, &dci, 0, &dev) != VK_SUCCESS) return 0;
    }
    g_gdpa = (PFN_vkGetDeviceProcAddr)g_gipa((VkInstance)c->inst, "vkGetDeviceProcAddr");
    g_gq = (PFN_vkGetDeviceQueue)g_gdpa(dev, "vkGetDeviceQueue");
    g_cp = (PFN_vkCreateCommandPool)g_gdpa(dev, "vkCreateCommandPool");
    g_dcp = (PFN_vkDestroyCommandPool)g_gdpa(dev, "vkDestroyCommandPool");
    g_cb = (PFN_vkCreateBuffer)g_gdpa(dev, "vkCreateBuffer");
    g_db = (PFN_vkDestroyBuffer)g_gdpa(dev, "vkDestroyBuffer");
    g_br = (PFN_vkGetBufferMemoryRequirements)g_gdpa(dev, "vkGetBufferMemoryRequirements");
    g_am = (PFN_vkAllocateMemory)g_gdpa(dev, "vkAllocateMemory");
    g_fm = (PFN_vkFreeMemory)g_gdpa(dev, "vkFreeMemory");
    g_bb = (PFN_vkBindBufferMemory)g_gdpa(dev, "vkBindBufferMemory");
    g_ac = (PFN_vkAllocateCommandBuffers)g_gdpa(dev, "vkAllocateCommandBuffers");
    g_fc = (PFN_vkFreeCommandBuffers)g_gdpa(dev, "vkFreeCommandBuffers");
    g_bc = (PFN_vkBeginCommandBuffer)g_gdpa(dev, "vkBeginCommandBuffer");
    g_ec = (PFN_vkEndCommandBuffer)g_gdpa(dev, "vkEndCommandBuffer");
    g_fill = (PFN_vkCmdFillBuffer)g_gdpa(dev, "vkCmdFillBuffer");
    g_qs = (PFN_vkQueueSubmit)g_gdpa(dev, "vkQueueSubmit");
    g_qi = (PFN_vkQueueWaitIdle)g_gdpa(dev, "vkQueueWaitIdle");
    g_dd = (PFN_vkDestroyDevice)g_gdpa(dev, "vkDestroyDevice");
    VkQueue q = 0; g_gq(dev, fam, 0, &q);
    VkCommandPoolCreateInfo pci{VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO};
    pci.queueFamilyIndex = fam;
    pci.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;
    VkCommandPool pool = 0;
    if (g_cp(dev, &pci, 0, &pool) != VK_SUCCESS) { g_dd(dev, 0); return 0; }
    L->phys = p; L->dev = dev; L->q = q; L->pool = pool; L->qfam = fam;
    return 1;
}

extern "C" int d2_live_open(D2LiveCtx* c) {
    if (!c) return 0; memset(c, 0, sizeof *c);
    HMODULE lib = LoadLibraryA("vulkan-1.dll");
    if (!lib) return 0;
    c->lib = lib;
    g_gipa = (PFN_vkGetInstanceProcAddr)GetProcAddress(lib, "vkGetInstanceProcAddr");
    g_ci = (PFN_vkCreateInstance)g_gipa(0, "vkCreateInstance");
    VkApplicationInfo app{VK_STRUCTURE_TYPE_APPLICATION_INFO};
    app.apiVersion = VK_API_VERSION_1_2;
    VkInstanceCreateInfo ici{VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO};
    ici.pApplicationInfo = &app;
    VkInstance inst = 0;
    if (g_ci(&ici, 0, &inst) != VK_SUCCESS) return 0;
    c->inst = inst;
    g_di = (PFN_vkDestroyInstance)g_gipa(inst, "vkDestroyInstance");
    g_enum = (PFN_vkEnumeratePhysicalDevices)g_gipa(inst, "vkEnumeratePhysicalDevices");
    g_props = (PFN_vkGetPhysicalDeviceProperties)g_gipa(inst, "vkGetPhysicalDeviceProperties");
    g_qf = (PFN_vkGetPhysicalDeviceQueueFamilyProperties)g_gipa(inst, "vkGetPhysicalDeviceQueueFamilyProperties");
    g_mp = (PFN_vkGetPhysicalDeviceMemoryProperties)g_gipa(inst, "vkGetPhysicalDeviceMemoryProperties");
    g_cd = (PFN_vkCreateDevice)g_gipa(inst, "vkCreateDevice");
    uint32_t n = 0; g_enum(inst, &n, 0);
    VkPhysicalDevice phys[16]; if (n > 16) n = 16; g_enum(inst, &n, phys);
    VkPhysicalDevice p0 = 0, p1 = 0;
    for (uint32_t i = 0; i < n; ++i) {
        VkPhysicalDeviceProperties pr{}; g_props(phys[i], &pr);
        if (!p0 && name_ok(pr.deviceName, 1)) p0 = phys[i];
        if (!p1 && name_ok(pr.deviceName, 0)) p1 = phys[i];
    }
    if (!p0 || !p1) { printf("DUAL_PHYS_FAIL p0=%p p1=%p n=%u\n", (void*)p0, (void*)p1, n); return 0; }
    if (!open_lane(c, &c->lane[0], p0) || !open_lane(c, &c->lane[1], p1)) return 0;
    printf("LIVE_GPU0=AMD Radeon AI PRO R9700\nLIVE_GPU1=AMD Radeon RX 7800 XT\n");
    c->ready = 1; return 1;
}
