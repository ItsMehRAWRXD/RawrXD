// VwaGpuDma.cpp — DEVICE_LOCAL alloc + vkCmdCopyBuffer H2D
#include "VwaGpuDma.hpp"
#include "VwaGpuDma_Session.hpp"
#include <cstring>

namespace Deep2 {

void* GpuDma_AllocDevice(size_t bytes, GpuDmaWitness* w) {
#if !VWA_GPU_DMA_VK
    (void)bytes; (void)w; return nullptr;
#else
    GpuDmaSession* s = GpuDma_Session();
    if (!s || !bytes) return nullptr;
    auto* db = new GpuDmaDeviceBuf();
    db->ses = s;
    db->bytes = bytes;
    if (!GpuDma_MakeBuf(s, bytes,
                        VK_BUFFER_USAGE_TRANSFER_DST_BIT | VK_BUFFER_USAGE_STORAGE_BUFFER_BIT,
                        VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT, db->buf, db->mem)) {
        delete db; return nullptr;
    }
    if (w) {
        w->deviceObjectNonNull = true;
        w->deviceSelectionInVwa = false;
        w->calledGpuApiInVwa = false;
    }
    return db;
#endif
}

bool GpuDma_HostToDevice(const void* host, void* device, size_t bytes, GpuDmaWitness* w) {
#if !VWA_GPU_DMA_VK
    (void)host; (void)device; (void)bytes; (void)w; return false;
#else
    auto* db = static_cast<GpuDmaDeviceBuf*>(device);
    if (!host || !db || !db->ses || !bytes || bytes > db->bytes) return false;
    GpuDmaSession* s = db->ses;
    VkBuffer staging = VK_NULL_HANDLE;
    VkDeviceMemory stagingMem = VK_NULL_HANDLE;
    if (!GpuDma_MakeBuf(s, bytes, VK_BUFFER_USAGE_TRANSFER_SRC_BIT,
                        VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT,
                        staging, stagingMem))
        return false;
    void* mapped = nullptr;
    s->f.MapMemory(s->dev, stagingMem, 0, bytes, 0, &mapped);
    std::memcpy(mapped, host, bytes);
    s->f.UnmapMemory(s->dev, stagingMem);
    VkCommandBufferAllocateInfo cai{VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO};
    cai.commandPool = s->pool;
    cai.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    cai.commandBufferCount = 1;
    VkCommandBuffer cmd = VK_NULL_HANDLE;
    s->f.AllocateCommandBuffers(s->dev, &cai, &cmd);
    VkCommandBufferBeginInfo bi{VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO};
    bi.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    s->f.BeginCommandBuffer(cmd, &bi);
    VkBufferCopy copy{};
    copy.size = bytes;
    s->f.CmdCopyBuffer(cmd, staging, db->buf, 1, &copy);
    s->f.EndCommandBuffer(cmd);
    VkFence fence = VK_NULL_HANDLE;
    VkFenceCreateInfo fi{VK_STRUCTURE_TYPE_FENCE_CREATE_INFO};
    s->f.CreateFence(s->dev, &fi, nullptr, &fence);
    VkSubmitInfo si{VK_STRUCTURE_TYPE_SUBMIT_INFO};
    si.commandBufferCount = 1;
    si.pCommandBuffers = &cmd;
    const bool submitted = s->f.QueueSubmit(s->queue, 1, &si, fence) == VK_SUCCESS;
    const bool completed =
        submitted &&
        s->f.WaitForFences(s->dev, 1, &fence, VK_TRUE, 10000000000ull) == VK_SUCCESS;
    s->f.DestroyFence(s->dev, fence, nullptr);
    s->f.FreeCommandBuffers(s->dev, s->pool, 1, &cmd);
    s->f.DestroyBuffer(s->dev, staging, nullptr);
    s->f.FreeMemory(s->dev, stagingMem, nullptr);
    if (w) {
        w->hostStageBytes = bytes;
        w->deviceStageBytes = bytes;
        w->gpuDmaBytes = completed ? bytes : 0;
        w->uploadSubmits = submitted ? 1u : 0u;
        w->uploadCompletions = completed ? 1u : 0u;
        w->deviceObjectNonNull = true;
        w->realGpuDma = completed;
        w->calledGpuApiInVwa = false;
        w->deviceSelectionInVwa = false;
    }
    return completed;
#endif
}

void GpuDma_FreeDevice(void* device) {
#if !VWA_GPU_DMA_VK
    (void)device;
#else
    auto* db = static_cast<GpuDmaDeviceBuf*>(device);
    if (!db) return;
    if (db->ses && db->buf) db->ses->f.DestroyBuffer(db->ses->dev, db->buf, nullptr);
    if (db->ses && db->mem) db->ses->f.FreeMemory(db->ses->dev, db->mem, nullptr);
    delete db;
#endif
}

} // namespace Deep2
