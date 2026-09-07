// VwaGpuDma_Session.cpp — boot Vulkan session (LoadLibrary)
#include "VwaGpuDma_Session.hpp"
namespace Deep2 {
#if VWA_GPU_DMA_VK
namespace {
GpuDmaSession* g_ses = nullptr;

bool LoadFns(VkFns& f) {
    f.dll = LoadLibraryA("vulkan-1.dll");
    if (!f.dll) return false;
    auto L = [&](const char* n) { return GetProcAddress(f.dll, n); };
    f.CreateInstance = (PFN_vkCreateInstance)L("vkCreateInstance");
    f.DestroyInstance = (PFN_vkDestroyInstance)L("vkDestroyInstance");
    f.EnumeratePhysicalDevices = (PFN_vkEnumeratePhysicalDevices)L("vkEnumeratePhysicalDevices");
    f.GetPhysQFam = (PFN_vkGetPhysicalDeviceQueueFamilyProperties)L(
        "vkGetPhysicalDeviceQueueFamilyProperties");
    f.GetPhysMem = (PFN_vkGetPhysicalDeviceMemoryProperties)L(
        "vkGetPhysicalDeviceMemoryProperties");
    f.CreateDevice = (PFN_vkCreateDevice)L("vkCreateDevice");
    f.DestroyDevice = (PFN_vkDestroyDevice)L("vkDestroyDevice");
    f.GetDeviceQueue = (PFN_vkGetDeviceQueue)L("vkGetDeviceQueue");
    f.CreateCommandPool = (PFN_vkCreateCommandPool)L("vkCreateCommandPool");
    f.DestroyCommandPool = (PFN_vkDestroyCommandPool)L("vkDestroyCommandPool");
    f.AllocateCommandBuffers = (PFN_vkAllocateCommandBuffers)L("vkAllocateCommandBuffers");
    f.FreeCommandBuffers = (PFN_vkFreeCommandBuffers)L("vkFreeCommandBuffers");
    f.BeginCommandBuffer = (PFN_vkBeginCommandBuffer)L("vkBeginCommandBuffer");
    f.EndCommandBuffer = (PFN_vkEndCommandBuffer)L("vkEndCommandBuffer");
    f.CmdCopyBuffer = (PFN_vkCmdCopyBuffer)L("vkCmdCopyBuffer");
    f.QueueSubmit = (PFN_vkQueueSubmit)L("vkQueueSubmit");
    f.CreateBuffer = (PFN_vkCreateBuffer)L("vkCreateBuffer");
    f.DestroyBuffer = (PFN_vkDestroyBuffer)L("vkDestroyBuffer");
    f.GetBufferMemoryRequirements =
        (PFN_vkGetBufferMemoryRequirements)L("vkGetBufferMemoryRequirements");
    f.AllocateMemory = (PFN_vkAllocateMemory)L("vkAllocateMemory");
    f.FreeMemory = (PFN_vkFreeMemory)L("vkFreeMemory");
    f.BindBufferMemory = (PFN_vkBindBufferMemory)L("vkBindBufferMemory");
    f.MapMemory = (PFN_vkMapMemory)L("vkMapMemory");
    f.UnmapMemory = (PFN_vkUnmapMemory)L("vkUnmapMemory");
    f.CreateFence = (PFN_vkCreateFence)L("vkCreateFence");
    f.DestroyFence = (PFN_vkDestroyFence)L("vkDestroyFence");
    f.WaitForFences = (PFN_vkWaitForFences)L("vkWaitForFences");
    return f.CreateInstance && f.CmdCopyBuffer && f.WaitForFences;
}

GpuDmaSession* Boot() {
    auto* s = new GpuDmaSession();
    if (!LoadFns(s->f)) { delete s; return nullptr; }
    VkApplicationInfo app{VK_STRUCTURE_TYPE_APPLICATION_INFO};
    app.pApplicationName = "VwaGpuDma";
    app.apiVersion = VK_API_VERSION_1_2;
    VkInstanceCreateInfo ici{VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO};
    ici.pApplicationInfo = &app;
    if (s->f.CreateInstance(&ici, nullptr, &s->inst) != VK_SUCCESS) {
        FreeLibrary(s->f.dll); delete s; return nullptr;
    }
    uint32_t n = 0;
    s->f.EnumeratePhysicalDevices(s->inst, &n, nullptr);
    if (!n) { s->f.DestroyInstance(s->inst, nullptr); FreeLibrary(s->f.dll); delete s; return nullptr; }
    VkPhysicalDevice phys[8]{};
    if (n > 8) n = 8;
    s->f.EnumeratePhysicalDevices(s->inst, &n, phys);
    s->phys = phys[0];
    uint32_t qn = 0;
    s->f.GetPhysQFam(s->phys, &qn, nullptr);
    VkQueueFamilyProperties qf[8]{};
    if (qn > 8) qn = 8;
    s->f.GetPhysQFam(s->phys, &qn, qf);
    for (uint32_t i = 0; i < qn; ++i)
        if (qf[i].queueFlags & (VK_QUEUE_TRANSFER_BIT | VK_QUEUE_COMPUTE_BIT |
                                VK_QUEUE_GRAPHICS_BIT)) {
            s->qfam = i; break;
        }
    float pri = 1.f;
    VkDeviceQueueCreateInfo qci{VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO};
    qci.queueFamilyIndex = s->qfam; qci.queueCount = 1; qci.pQueuePriorities = &pri;
    VkDeviceCreateInfo dci{VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO};
    dci.queueCreateInfoCount = 1; dci.pQueueCreateInfos = &qci;
    if (s->f.CreateDevice(s->phys, &dci, nullptr, &s->dev) != VK_SUCCESS) {
        s->f.DestroyInstance(s->inst, nullptr); FreeLibrary(s->f.dll); delete s; return nullptr;
    }
    s->f.GetDeviceQueue(s->dev, s->qfam, 0, &s->queue);
    VkCommandPoolCreateInfo pci{VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO};
    pci.queueFamilyIndex = s->qfam;
    pci.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;
    if (s->f.CreateCommandPool(s->dev, &pci, nullptr, &s->pool) != VK_SUCCESS) {
        s->f.DestroyDevice(s->dev, nullptr);
        s->f.DestroyInstance(s->inst, nullptr); FreeLibrary(s->f.dll); delete s; return nullptr;
    }
    return s;
}
} // namespace

GpuDmaSession* GpuDma_Session() {
    if (!g_ses) g_ses = Boot();
    return g_ses;
}

bool GpuDma_MakeBuf(GpuDmaSession* s, VkDeviceSize sz, VkBufferUsageFlags usage,
                   VkMemoryPropertyFlags props, VkBuffer& outB, VkDeviceMemory& outM) {
    VkBufferCreateInfo bi{VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO};
    bi.size = sz; bi.usage = usage; bi.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
    if (s->f.CreateBuffer(s->dev, &bi, nullptr, &outB) != VK_SUCCESS) return false;
    VkMemoryRequirements mr{};
    s->f.GetBufferMemoryRequirements(s->dev, outB, &mr);
    VkPhysicalDeviceMemoryProperties mp{};
    s->f.GetPhysMem(s->phys, &mp);
    uint32_t idx = UINT32_MAX;
    for (uint32_t i = 0; i < mp.memoryTypeCount; ++i)
        if ((mr.memoryTypeBits & (1u << i)) &&
            (mp.memoryTypes[i].propertyFlags & props) == props) {
            idx = i; break;
        }
    VkMemoryAllocateInfo ai{VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO};
    ai.allocationSize = mr.size; ai.memoryTypeIndex = idx;
    if (idx == UINT32_MAX || s->f.AllocateMemory(s->dev, &ai, nullptr, &outM) != VK_SUCCESS) {
        s->f.DestroyBuffer(s->dev, outB, nullptr); outB = VK_NULL_HANDLE; return false;
    }
    s->f.BindBufferMemory(s->dev, outB, outM, 0);
    return true;
}
#endif
} // namespace Deep2
