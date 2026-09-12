/* ss_vk_sync.c — import D3D12 shared fence; wait before visibility */
#include "ss_vk_api.h"
int ss_vk_sync(SsVk *v, void *fence_nt, uint64_t fence_val)
{
    VkSemaphoreTypeCreateInfo ti = { VK_STRUCTURE_TYPE_SEMAPHORE_TYPE_CREATE_INFO };
    VkSemaphoreCreateInfo si = { VK_STRUCTURE_TYPE_SEMAPHORE_CREATE_INFO };
    VkImportSemaphoreWin32HandleInfoKHR imp = { VK_STRUCTURE_TYPE_IMPORT_SEMAPHORE_WIN32_HANDLE_INFO_KHR };
    VkTimelineSemaphoreSubmitInfo ts = { VK_STRUCTURE_TYPE_TIMELINE_SEMAPHORE_SUBMIT_INFO };
    VkSubmitInfo sub = { VK_STRUCTURE_TYPE_SUBMIT_INFO };
    VkPipelineStageFlags st = VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT;
    if (!v || !v->dev || !fence_nt || !fence_val) return 100;
    v->a.create_sem = (PFN_vkCreateSemaphore)v->a.gdpa(v->dev, "vkCreateSemaphore");
    v->a.destroy_sem = (PFN_vkDestroySemaphore)v->a.gdpa(v->dev, "vkDestroySemaphore");
    v->a.imp_sem = (PFN_vkImportSemaphoreWin32HandleKHR)v->a.gdpa(v->dev, "vkImportSemaphoreWin32HandleKHR");
    v->a.qsubmit = (PFN_vkQueueSubmit)v->a.gdpa(v->dev, "vkQueueSubmit");
    v->a.qidle = (PFN_vkQueueWaitIdle)v->a.gdpa(v->dev, "vkQueueWaitIdle");
    if (!v->a.imp_sem)
        v->a.imp_sem = (PFN_vkImportSemaphoreWin32HandleKHR)v->a.gipa(v->inst, "vkImportSemaphoreWin32HandleKHR");
    if (!v->a.create_sem || !v->a.imp_sem || !v->a.qsubmit) return 100;
    ti.semaphoreType = VK_SEMAPHORE_TYPE_TIMELINE;
    si.pNext = &ti;
    if (v->a.create_sem(v->dev, &si, 0, &v->sem) != VK_SUCCESS) return 100;
    imp.semaphore = v->sem;
    imp.handleType = VK_EXTERNAL_SEMAPHORE_HANDLE_TYPE_D3D12_FENCE_BIT;
    imp.handle = (HANDLE)fence_nt;
    if (v->a.imp_sem(v->dev, &imp) != VK_SUCCESS) return 100;
    ts.waitSemaphoreValueCount = 1;
    ts.pWaitSemaphoreValues = &fence_val;
    sub.pNext = &ts;
    sub.waitSemaphoreCount = 1;
    sub.pWaitSemaphores = &v->sem;
    sub.pWaitDstStageMask = &st;
    if (v->a.qsubmit(v->q, 1, &sub, 0) != VK_SUCCESS) return 100;
    if (v->a.qidle(v->q) != VK_SUCCESS) return 100;
    v->sync_ok = 1;
    return 0;
}
