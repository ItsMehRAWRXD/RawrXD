/* ss_vk_drop.c — destroy Vulkan objects; do not CloseHandle NT resources */
#include "ss_vk_api.h"
void ss_vk_drop(SsVk *v)
{
    if (!v) return;
    if (v->dev && v->a.gdpa) {
        if (!v->a.destroy_buf)
            v->a.destroy_buf = (PFN_vkDestroyBuffer)v->a.gdpa(v->dev, "vkDestroyBuffer");
        if (!v->a.free_mem)
            v->a.free_mem = (PFN_vkFreeMemory)v->a.gdpa(v->dev, "vkFreeMemory");
        if (!v->a.destroy_pool)
            v->a.destroy_pool = (PFN_vkDestroyCommandPool)v->a.gdpa(v->dev, "vkDestroyCommandPool");
        if (!v->a.destroy_sem)
            v->a.destroy_sem = (PFN_vkDestroySemaphore)v->a.gdpa(v->dev, "vkDestroySemaphore");
        if (!v->a.destroy_pipe)
            v->a.destroy_pipe = (PFN_vkDestroyPipeline)v->a.gdpa(v->dev, "vkDestroyPipeline");
        if (!v->a.destroy_pl)
            v->a.destroy_pl = (PFN_vkDestroyPipelineLayout)v->a.gdpa(v->dev, "vkDestroyPipelineLayout");
        if (!v->a.destroy_dsl)
            v->a.destroy_dsl = (PFN_vkDestroyDescriptorSetLayout)v->a.gdpa(v->dev, "vkDestroyDescriptorSetLayout");
        if (!v->a.destroy_dp)
            v->a.destroy_dp = (PFN_vkDestroyDescriptorPool)v->a.gdpa(v->dev, "vkDestroyDescriptorPool");
        if (!v->a.destroy_sm)
            v->a.destroy_sm = (PFN_vkDestroyShaderModule)v->a.gdpa(v->dev, "vkDestroyShaderModule");
        if (!v->a.destroy_dev)
            v->a.destroy_dev = (PFN_vkDestroyDevice)v->a.gdpa(v->dev, "vkDestroyDevice");
        if (v->pipe && v->a.destroy_pipe) v->a.destroy_pipe(v->dev, v->pipe, 0);
        if (v->pl && v->a.destroy_pl) v->a.destroy_pl(v->dev, v->pl, 0);
        if (v->dsl && v->a.destroy_dsl) v->a.destroy_dsl(v->dev, v->dsl, 0);
        if (v->dpool && v->a.destroy_dp) v->a.destroy_dp(v->dev, v->dpool, 0);
        if (v->sm && v->a.destroy_sm) v->a.destroy_sm(v->dev, v->sm, 0);
        if (v->outb && v->a.destroy_buf) v->a.destroy_buf(v->dev, v->outb, 0);
        if (v->outmem && v->a.free_mem) v->a.free_mem(v->dev, v->outmem, 0);
        if (v->vis && v->a.destroy_buf) v->a.destroy_buf(v->dev, v->vis, 0);
        if (v->vismem && v->a.free_mem) v->a.free_mem(v->dev, v->vismem, 0);
        if (v->wbuf && v->a.destroy_buf) v->a.destroy_buf(v->dev, v->wbuf, 0);
        if (v->wmem && v->a.free_mem) v->a.free_mem(v->dev, v->wmem, 0);
        if (v->pool && v->a.destroy_pool) v->a.destroy_pool(v->dev, v->pool, 0);
        if (v->sem && v->a.destroy_sem) v->a.destroy_sem(v->dev, v->sem, 0);
        if (v->a.destroy_dev) v->a.destroy_dev(v->dev, 0);
    }
    if (v->inst && v->a.destroy_inst) v->a.destroy_inst(v->inst, 0);
    if (v->a.lib) FreeLibrary(v->a.lib);
    v->dev = 0; v->inst = 0; v->a.lib = 0;
}
