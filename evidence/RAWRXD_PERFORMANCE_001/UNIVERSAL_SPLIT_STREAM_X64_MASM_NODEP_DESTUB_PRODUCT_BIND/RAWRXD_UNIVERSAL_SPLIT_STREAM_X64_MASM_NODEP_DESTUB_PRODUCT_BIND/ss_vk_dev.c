/* ss_vk_dev.c — instance + LUID-matched device with Win32 external memory */
#include "ss_vk_api.h"
#include <string.h>
static int has_ext(SsVk *v, VkPhysicalDevice p, const char *name)
{
    uint32_t n = 0, i;
    VkExtensionProperties *e;
    v->a.enum_ext(p, 0, &n, 0);
    if (!n) return 0;
    e = (VkExtensionProperties *)HeapAlloc(GetProcessHeap(), 0, n * sizeof *e);
    if (!e) return 0;
    v->a.enum_ext(p, 0, &n, e);
    for (i = 0; i < n; ++i)
        if (!strcmp(e[i].extensionName, name)) { HeapFree(GetProcessHeap(), 0, e); return 1; }
    HeapFree(GetProcessHeap(), 0, e);
    return 0;
}
static int pick_q(SsVk *v, VkPhysicalDevice p, uint32_t *fam)
{
    uint32_t n = 0, i; VkQueueFamilyProperties *q;
    v->a.qfams(p, &n, 0);
    q = (VkQueueFamilyProperties *)HeapAlloc(GetProcessHeap(), 0, n * sizeof *q);
    if (!q) return 100;
    v->a.qfams(p, &n, q);
    for (i = 0; i < n; ++i)
        if (q[i].queueFlags & (VK_QUEUE_TRANSFER_BIT | VK_QUEUE_COMPUTE_BIT | VK_QUEUE_GRAPHICS_BIT)) {
            *fam = i; HeapFree(GetProcessHeap(), 0, q); return 0;
        }
    HeapFree(GetProcessHeap(), 0, q);
    return 100;
}
int ss_vk_dev(SsVk *v, uint64_t luid)
{
    VkApplicationInfo app = { VK_STRUCTURE_TYPE_APPLICATION_INFO };
    VkInstanceCreateInfo ici = { VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO };
    uint32_t n = 0, i; VkPhysicalDevice phys[8];
    const char *dext[3] = {
        "VK_KHR_external_memory_win32",
        "VK_KHR_external_semaphore_win32",
        "VK_KHR_timeline_semaphore"
    };
    float pri = 1.f; VkDeviceQueueCreateInfo qci = { VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO };
    VkDeviceCreateInfo dci = { VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO };
    if (!v || !luid || !v->a.create_inst) return 100;
    app.apiVersion = VK_API_VERSION_1_2;
    ici.pApplicationInfo = &app;
    if (v->a.create_inst(&ici, 0, &v->inst) != VK_SUCCESS) return 100;
    v->a.destroy_inst = (PFN_vkDestroyInstance)v->a.gipa(v->inst, "vkDestroyInstance");
    v->a.enum_phys = (PFN_vkEnumeratePhysicalDevices)v->a.gipa(v->inst, "vkEnumeratePhysicalDevices");
    v->a.props2 = (PFN_vkGetPhysicalDeviceProperties2)v->a.gipa(v->inst, "vkGetPhysicalDeviceProperties2");
    v->a.qfams = (PFN_vkGetPhysicalDeviceQueueFamilyProperties)v->a.gipa(v->inst, "vkGetPhysicalDeviceQueueFamilyProperties");
    v->a.enum_ext = (PFN_vkEnumerateDeviceExtensionProperties)v->a.gipa(v->inst, "vkEnumerateDeviceExtensionProperties");
    v->a.create_dev = (PFN_vkCreateDevice)v->a.gipa(v->inst, "vkCreateDevice");
    v->a.memprops = (PFN_vkGetPhysicalDeviceMemoryProperties)v->a.gipa(v->inst, "vkGetPhysicalDeviceMemoryProperties");
    if (!v->a.enum_phys || !v->a.props2 || !v->a.enum_ext || !v->a.create_dev) return 100;
    v->a.enum_phys(v->inst, &n, 0);
    if (!n || n > 8) n = n > 8 ? 8 : n;
    if (!n || v->a.enum_phys(v->inst, &n, phys) != VK_SUCCESS) return 100;
    for (i = 0; i < n; ++i) {
        VkPhysicalDeviceIDProperties idp = { VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_ID_PROPERTIES };
        VkPhysicalDeviceProperties2 p2 = { VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROPERTIES_2 };
        uint64_t got = 0;
        p2.pNext = &idp;
        v->a.props2(phys[i], &p2);
        if (!idp.deviceLUIDValid) continue;
        memcpy(&got, idp.deviceLUID, 8);
        if (got != luid) continue;
        if (!has_ext(v, phys[i], dext[0]) || !has_ext(v, phys[i], dext[1])) continue;
        if (pick_q(v, phys[i], &v->qfam)) continue;
        v->phys = phys[i]; v->luid = got; v->luid_ok = 1;
        if (has_ext(v, phys[i], dext[2])) v->retain = 3; else v->retain = 2;
        break;
    }
    if (!v->luid_ok) return 100;
    qci.queueFamilyIndex = v->qfam; qci.queueCount = 1; qci.pQueuePriorities = &pri;
    {
        VkPhysicalDeviceTimelineSemaphoreFeatures tsf = {
            VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_TIMELINE_SEMAPHORE_FEATURES
        };
        tsf.timelineSemaphore = VK_TRUE;
        dci.pNext = &tsf;
        dci.queueCreateInfoCount = 1; dci.pQueueCreateInfos = &qci;
        dci.enabledExtensionCount = v->retain == 3 ? 3u : 2u;
        dci.ppEnabledExtensionNames = dext;
        if (v->a.create_dev(v->phys, &dci, 0, &v->dev) != VK_SUCCESS) return 100;
    }
    v->a.gdpa = (PFN_vkGetDeviceProcAddr)v->a.gipa(v->inst, "vkGetDeviceProcAddr");
    v->a.get_q = (PFN_vkGetDeviceQueue)v->a.gdpa(v->dev, "vkGetDeviceQueue");
    v->a.get_q(v->dev, v->qfam, 0, &v->q);
    return v->q ? 0 : 100;
}
