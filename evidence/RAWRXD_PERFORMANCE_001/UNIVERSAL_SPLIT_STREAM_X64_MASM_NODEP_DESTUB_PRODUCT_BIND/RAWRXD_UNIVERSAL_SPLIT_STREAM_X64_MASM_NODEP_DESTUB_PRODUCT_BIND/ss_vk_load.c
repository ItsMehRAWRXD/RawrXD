/* ss_vk_load.c — LoadLibrary vulkan-1.dll; no authority mint */
#include "ss_vk_api.h"
#include <string.h>
static void *gp(SsVk *v, const char *n)
{
    return v && v->a.gipa ? (void *)v->a.gipa(NULL, n) : 0;
}
int ss_vk_load(SsVk *v)
{
    if (!v) return 100;
    memset(v, 0, sizeof *v);
    v->a.lib = LoadLibraryA("vulkan-1.dll");
    if (!v->a.lib)
        v->a.lib = LoadLibraryA("C:\\Windows\\System32\\vulkan-1.dll");
    if (!v->a.lib) return 100;
    v->a.gipa = (PFN_vkGetInstanceProcAddr)GetProcAddress(v->a.lib, "vkGetInstanceProcAddr");
    if (!v->a.gipa) return 100;
    v->a.create_inst = (PFN_vkCreateInstance)gp(v, "vkCreateInstance");
    v->a.enum_phys = (PFN_vkEnumeratePhysicalDevices)gp(v, "vkEnumeratePhysicalDevices");
    v->a.props2 = (PFN_vkGetPhysicalDeviceProperties2)gp(v, "vkGetPhysicalDeviceProperties2");
    v->a.qfams = (PFN_vkGetPhysicalDeviceQueueFamilyProperties)gp(v, "vkGetPhysicalDeviceQueueFamilyProperties");
    v->a.memprops = (PFN_vkGetPhysicalDeviceMemoryProperties)gp(v, "vkGetPhysicalDeviceMemoryProperties");
    v->a.enum_ext = (PFN_vkEnumerateDeviceExtensionProperties)gp(v, "vkEnumerateDeviceExtensionProperties");
    v->a.create_dev = (PFN_vkCreateDevice)gp(v, "vkCreateDevice");
    if (!v->a.create_inst)
        return 100;
    v->retain = 1;
    return 0;
}
