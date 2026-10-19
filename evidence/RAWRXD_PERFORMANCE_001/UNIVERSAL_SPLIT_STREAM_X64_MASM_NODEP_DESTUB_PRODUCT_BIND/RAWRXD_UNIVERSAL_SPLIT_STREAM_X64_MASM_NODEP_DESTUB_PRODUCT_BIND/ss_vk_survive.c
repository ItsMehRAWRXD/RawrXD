/* ss_vk_survive.c — DEVICE_LOST messenger isolation after full forward */
#include "ss_vk_survive.h"
#include "ss_vk_api.h"
#include "ss_vk_block_util.h"
#include <stdio.h>
#include <string.h>
void ss_vk_survive_print(const SsSurviveSnap *s)
{
    if (!s) return;
    printf("DEEP2_POST_FORWARD_DEVICE_SURVIVAL when=%s\n",
           s->when ? s->when : "?");
    printf("DEVICE_ALIVE=%d QIDLE_OK=%d NOOP_SUBMIT_OK=%d EMBD_SUBMIT_OK=%d\n",
           s->device_alive, s->qidle_ok, s->noop_submit_ok, s->embd_submit_ok);
    printf("LAST_VR=%d HEAP0_BUDGET=%llu HEAP0_USAGE=%llu\n",
           (int)s->last_vr,
           (unsigned long long)s->heap0_budget,
           (unsigned long long)s->heap0_usage);
    printf("HEAP1_BUDGET=%llu HEAP1_USAGE=%llu\n",
           (unsigned long long)s->heap1_budget,
           (unsigned long long)s->heap1_usage);
    printf("DEVICE_LOST=%d PROMOTE=0\n", s->device_alive ? 0 : 1);
    fflush(stdout);
}
int ss_vk_survive_budget(SsVk *v, SsSurviveSnap *s)
{
    VkPhysicalDeviceMemoryProperties mp;
    if (!v || !s || !v->phys || !v->a.memprops) return 100;
    v->a.memprops(v->phys, &mp);
    s->heap0_budget = mp.memoryHeapCount > 0 ? mp.memoryHeaps[0].size : 0;
    s->heap1_budget = mp.memoryHeapCount > 1 ? mp.memoryHeaps[1].size : 0;
    s->heap0_usage = 0; s->heap1_usage = 0;
    return 0;
}
int ss_vk_survive_noop(SsVk *v, SsSurviveSnap *s)
{
    VkBufferCreateInfo bi = { VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO };
    VkMemoryRequirements req; VkMemoryAllocateInfo ai = { VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO };
    VkCommandBufferAllocateInfo cai = { VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO };
    VkCommandBufferBeginInfo bgi = { VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO };
    VkSubmitInfo sub = { VK_STRUCTURE_TYPE_SUBMIT_INFO };
    VkBuffer b = 0; VkDeviceMemory m = 0; VkCommandBuffer cb = 0;
    VkResult vr; uint32_t ty = 0xFFFFFFFFu, i;
    VkPhysicalDeviceMemoryProperties mp;
    if (!v || !s || !v->dev || !v->pool || !v->q) return 100;
    s->last_vr = 0; s->noop_submit_ok = 0; s->qidle_ok = 0;
    vr = v->a.qidle(v->q);
    s->last_vr = (int32_t)vr;
    if (vr == VK_ERROR_DEVICE_LOST) { s->device_alive = 0; return 100; }
    if (vr != VK_SUCCESS) return 100;
    s->qidle_ok = 1;
    bi.size = 256; bi.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT;
    if (v->a.create_buf(v->dev, &bi, 0, &b) != VK_SUCCESS) return 100;
    v->a.buf_req(v->dev, b, &req);
    v->a.memprops(v->phys, &mp);
    for (i = 0; i < mp.memoryTypeCount; ++i)
        if ((req.memoryTypeBits & (1u << i)) &&
            (mp.memoryTypes[i].propertyFlags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT)) {
            ty = i; break;
        }
    if (ty == 0xFFFFFFFFu) { ss_vk_dropb(v, &b, &m); return 100; }
    ai.allocationSize = req.size; ai.memoryTypeIndex = ty;
    if (v->a.alloc_mem(v->dev, &ai, 0, &m) != VK_SUCCESS) {
        ss_vk_dropb(v, &b, &m); return 100;
    }
    if (v->a.bind_mem(v->dev, b, m, 0) != VK_SUCCESS) {
        ss_vk_dropb(v, &b, &m); return 100;
    }
    cai.commandPool = v->pool; cai.commandBufferCount = 1;
    vr = v->a.alloc_cb(v->dev, &cai, &cb);
    s->last_vr = (int32_t)vr;
    if (vr != VK_SUCCESS) {
        if (vr == VK_ERROR_DEVICE_LOST) s->device_alive = 0;
        ss_vk_dropb(v, &b, &m); return 100;
    }
    if (v->a.begin_cb(cb, &bgi) != VK_SUCCESS || v->a.end_cb(cb) != VK_SUCCESS) {
        if (v->a.free_cb) v->a.free_cb(v->dev, v->pool, 1, &cb);
        ss_vk_dropb(v, &b, &m); return 100;
    }
    sub.commandBufferCount = 1; sub.pCommandBuffers = &cb;
    vr = v->a.qsubmit(v->q, 1, &sub, 0);
    s->last_vr = (int32_t)vr;
    if (vr == VK_ERROR_DEVICE_LOST) s->device_alive = 0;
    if (vr == VK_SUCCESS) {
        s->noop_submit_ok = 1;
        vr = v->a.qidle(v->q);
        s->last_vr = (int32_t)vr;
        if (vr == VK_ERROR_DEVICE_LOST) s->device_alive = 0;
        else if (vr == VK_SUCCESS) s->qidle_ok = 1;
    }
    if (v->a.free_cb) v->a.free_cb(v->dev, v->pool, 1, &cb);
    ss_vk_dropb(v, &b, &m);
    return (s->device_alive && s->noop_submit_ok) ? 0 : 100;
}
