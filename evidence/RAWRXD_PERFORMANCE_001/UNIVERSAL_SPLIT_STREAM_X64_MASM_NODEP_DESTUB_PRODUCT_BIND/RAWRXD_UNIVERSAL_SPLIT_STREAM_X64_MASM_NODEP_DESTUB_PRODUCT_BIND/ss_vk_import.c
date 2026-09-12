/* ss_vk_import.c — import exact D3D12 HOT NT handle; do not CloseHandle */
#include "ss_vk_api.h"
static uint32_t pick_type(uint32_t bits, const VkPhysicalDeviceMemoryProperties *mp)
{
    uint32_t i;
    for (i = 0; i < mp->memoryTypeCount; ++i)
        if ((bits & (1u << i)) && (mp->memoryTypes[i].propertyFlags & VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT))
            return i;
    for (i = 0; i < mp->memoryTypeCount; ++i)
        if (bits & (1u << i)) return i;
    return 0xFFFFFFFFu;
}
static void bind_dev_fns(SsVk *v)
{
    v->a.create_buf = (PFN_vkCreateBuffer)v->a.gdpa(v->dev, "vkCreateBuffer");
    v->a.destroy_buf = (PFN_vkDestroyBuffer)v->a.gdpa(v->dev, "vkDestroyBuffer");
    v->a.buf_req = (PFN_vkGetBufferMemoryRequirements)v->a.gdpa(v->dev, "vkGetBufferMemoryRequirements");
    v->a.alloc_mem = (PFN_vkAllocateMemory)v->a.gdpa(v->dev, "vkAllocateMemory");
    v->a.free_mem = (PFN_vkFreeMemory)v->a.gdpa(v->dev, "vkFreeMemory");
    v->a.bind_mem = (PFN_vkBindBufferMemory)v->a.gdpa(v->dev, "vkBindBufferMemory");
    v->a.mem_hp = (PFN_vkGetMemoryWin32HandlePropertiesKHR)v->a.gdpa(v->dev, "vkGetMemoryWin32HandlePropertiesKHR");
    if (!v->a.mem_hp)
        v->a.mem_hp = (PFN_vkGetMemoryWin32HandlePropertiesKHR)v->a.gipa(v->inst, "vkGetMemoryWin32HandlePropertiesKHR");
}
int ss_vk_import(SsVk *v, void *nt, uint64_t bytes)
{
    VkExternalMemoryBufferCreateInfo ext = { VK_STRUCTURE_TYPE_EXTERNAL_MEMORY_BUFFER_CREATE_INFO };
    VkBufferCreateInfo bi = { VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO };
    VkMemoryRequirements req; VkMemoryWin32HandlePropertiesKHR hp = { VK_STRUCTURE_TYPE_MEMORY_WIN32_HANDLE_PROPERTIES_KHR };
    VkPhysicalDeviceMemoryProperties mp; VkMemoryDedicatedAllocateInfo ded = { VK_STRUCTURE_TYPE_MEMORY_DEDICATED_ALLOCATE_INFO };
    VkImportMemoryWin32HandleInfoKHR imp = { VK_STRUCTURE_TYPE_IMPORT_MEMORY_WIN32_HANDLE_INFO_KHR };
    VkMemoryAllocateInfo ai = { VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO };
    uint32_t bits, ty;
    if (!v || !v->dev || !nt || !bytes) return 100;
    bind_dev_fns(v);
    if (!v->a.create_buf || !v->a.mem_hp || !v->a.alloc_mem || !v->a.bind_mem) return 100;
    ext.handleTypes = VK_EXTERNAL_MEMORY_HANDLE_TYPE_D3D12_RESOURCE_BIT;
    bi.size = bytes;
    bi.usage = VK_BUFFER_USAGE_TRANSFER_SRC_BIT | VK_BUFFER_USAGE_STORAGE_BUFFER_BIT;
    bi.pNext = &ext;
    if (v->a.create_buf(v->dev, &bi, 0, &v->wbuf) != VK_SUCCESS) return 100;
    v->a.buf_req(v->dev, v->wbuf, &req);
    if (v->a.mem_hp(v->dev, VK_EXTERNAL_MEMORY_HANDLE_TYPE_D3D12_RESOURCE_BIT, (HANDLE)nt, &hp) != VK_SUCCESS)
        return 100;
    bits = req.memoryTypeBits & hp.memoryTypeBits;
    v->a.memprops(v->phys, &mp);
    ty = pick_type(bits, &mp);
    if (ty == 0xFFFFFFFFu) return 100;
    ded.buffer = v->wbuf;
    imp.pNext = &ded;
    imp.handleType = VK_EXTERNAL_MEMORY_HANDLE_TYPE_D3D12_RESOURCE_BIT;
    imp.handle = (HANDLE)nt;
    ai.pNext = &imp;
    ai.allocationSize = req.size;
    ai.memoryTypeIndex = ty;
    if (v->a.alloc_mem(v->dev, &ai, 0, &v->wmem) != VK_SUCCESS) return 100;
    v->imported = 1;
    v->bytes = bytes;
    v->retain = 1;
    if (v->a.bind_mem(v->dev, v->wbuf, v->wmem, 0) != VK_SUCCESS) return 100;
    v->bound = 1;
    return 0;
}
