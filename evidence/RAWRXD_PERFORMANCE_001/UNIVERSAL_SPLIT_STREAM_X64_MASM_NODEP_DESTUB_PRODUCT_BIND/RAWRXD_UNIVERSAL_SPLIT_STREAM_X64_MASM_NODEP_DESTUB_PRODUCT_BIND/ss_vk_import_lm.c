/* ss_vk_import_lm.c — import lm-head HOT as lbuf on same VkDevice */
#include "ss_vk_api.h"
static uint32_t pick(uint32_t bits, const VkPhysicalDeviceMemoryProperties *mp)
{
    uint32_t i;
    for (i = 0; i < mp->memoryTypeCount; ++i)
        if ((bits & (1u << i)) && (mp->memoryTypes[i].propertyFlags & VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT))
            return i;
    for (i = 0; i < mp->memoryTypeCount; ++i)
        if (bits & (1u << i)) return i;
    return 0xFFFFFFFFu;
}
int ss_vk_import_lm(SsVk *v, void *nt, uint64_t bytes)
{
    VkExternalMemoryBufferCreateInfo ext = { VK_STRUCTURE_TYPE_EXTERNAL_MEMORY_BUFFER_CREATE_INFO };
    VkBufferCreateInfo bi = { VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO };
    VkMemoryRequirements req;
    VkMemoryWin32HandlePropertiesKHR hp = { VK_STRUCTURE_TYPE_MEMORY_WIN32_HANDLE_PROPERTIES_KHR };
    VkPhysicalDeviceMemoryProperties mp;
    VkMemoryDedicatedAllocateInfo ded = { VK_STRUCTURE_TYPE_MEMORY_DEDICATED_ALLOCATE_INFO };
    VkImportMemoryWin32HandleInfoKHR imp = { VK_STRUCTURE_TYPE_IMPORT_MEMORY_WIN32_HANDLE_INFO_KHR };
    VkMemoryAllocateInfo ai = { VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO };
    uint32_t bits, ty;
    if (!v || !v->dev || !nt || !bytes || !v->a.create_buf || !v->a.mem_hp) return 100;
    if (v->lbuf && v->a.destroy_buf) v->a.destroy_buf(v->dev, v->lbuf, 0);
    if (v->lmem && v->a.free_mem) v->a.free_mem(v->dev, v->lmem, 0);
    v->lbuf = 0; v->lmem = 0; v->lbytes = 0;
    ext.handleTypes = VK_EXTERNAL_MEMORY_HANDLE_TYPE_D3D12_RESOURCE_BIT;
    bi.size = bytes;
    bi.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT;
    bi.pNext = &ext;
    if (v->a.create_buf(v->dev, &bi, 0, &v->lbuf) != VK_SUCCESS) return 100;
    v->a.buf_req(v->dev, v->lbuf, &req);
    if (v->a.mem_hp(v->dev, VK_EXTERNAL_MEMORY_HANDLE_TYPE_D3D12_RESOURCE_BIT, (HANDLE)nt, &hp) != VK_SUCCESS)
        return 100;
    bits = req.memoryTypeBits & hp.memoryTypeBits;
    v->a.memprops(v->phys, &mp);
    ty = pick(bits, &mp);
    if (ty == 0xFFFFFFFFu) return 100;
    ded.buffer = v->lbuf; imp.pNext = &ded;
    imp.handleType = VK_EXTERNAL_MEMORY_HANDLE_TYPE_D3D12_RESOURCE_BIT;
    imp.handle = (HANDLE)nt;
    ai.pNext = &imp; ai.allocationSize = req.size; ai.memoryTypeIndex = ty;
    if (v->a.alloc_mem(v->dev, &ai, 0, &v->lmem) != VK_SUCCESS) return 100;
    if (v->a.bind_mem(v->dev, v->lbuf, v->lmem, 0) != VK_SUCCESS) return 100;
    v->lbytes = bytes;
    return 0;
}
