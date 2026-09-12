/* ss_vk_api.h — import + imported model op; no logits/token mint */
#ifndef SS_VK_API_H
#define SS_VK_API_H
#define VK_NO_PROTOTYPES
#define VK_USE_PLATFORM_WIN32_KHR
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <vulkan/vulkan.h>
#include <stdint.h>
typedef struct {
    HMODULE lib;
    PFN_vkGetInstanceProcAddr gipa;
    PFN_vkGetDeviceProcAddr gdpa;
    PFN_vkCreateInstance create_inst;
    PFN_vkDestroyInstance destroy_inst;
    PFN_vkEnumeratePhysicalDevices enum_phys;
    PFN_vkGetPhysicalDeviceProperties2 props2;
    PFN_vkGetPhysicalDeviceQueueFamilyProperties qfams;
    PFN_vkGetPhysicalDeviceMemoryProperties memprops;
    PFN_vkEnumerateDeviceExtensionProperties enum_ext;
    PFN_vkCreateDevice create_dev;
    PFN_vkDestroyDevice destroy_dev;
    PFN_vkGetDeviceQueue get_q;
    PFN_vkCreateBuffer create_buf;
    PFN_vkDestroyBuffer destroy_buf;
    PFN_vkGetBufferMemoryRequirements buf_req;
    PFN_vkAllocateMemory alloc_mem;
    PFN_vkFreeMemory free_mem;
    PFN_vkBindBufferMemory bind_mem;
    PFN_vkCreateCommandPool create_pool;
    PFN_vkDestroyCommandPool destroy_pool;
    PFN_vkAllocateCommandBuffers alloc_cb;
    PFN_vkBeginCommandBuffer begin_cb;
    PFN_vkEndCommandBuffer end_cb;
    PFN_vkCmdCopyBuffer cmd_copy;
    PFN_vkCmdPipelineBarrier cmd_bar;
    PFN_vkQueueSubmit qsubmit;
    PFN_vkQueueWaitIdle qidle;
    PFN_vkCreateSemaphore create_sem;
    PFN_vkDestroySemaphore destroy_sem;
    PFN_vkMapMemory map;
    PFN_vkUnmapMemory unmap;
    PFN_vkGetMemoryWin32HandlePropertiesKHR mem_hp;
    PFN_vkImportSemaphoreWin32HandleKHR imp_sem;
    PFN_vkCreateShaderModule create_sm;
    PFN_vkDestroyShaderModule destroy_sm;
    PFN_vkCreateDescriptorSetLayout create_dsl;
    PFN_vkDestroyDescriptorSetLayout destroy_dsl;
    PFN_vkCreatePipelineLayout create_pl;
    PFN_vkDestroyPipelineLayout destroy_pl;
    PFN_vkCreateComputePipelines create_cp;
    PFN_vkDestroyPipeline destroy_pipe;
    PFN_vkCreateDescriptorPool create_dp;
    PFN_vkDestroyDescriptorPool destroy_dp;
    PFN_vkAllocateDescriptorSets alloc_ds;
    PFN_vkUpdateDescriptorSets upd_ds;
    PFN_vkCmdBindPipeline cmd_bp;
    PFN_vkCmdBindDescriptorSets cmd_bds;
    PFN_vkCmdPushConstants cmd_pc;
    PFN_vkCmdDispatch cmd_disp;
} SsVkApi;
typedef struct {
    SsVkApi a;
    VkInstance inst;
    VkPhysicalDevice phys;
    VkDevice dev;
    VkQueue q;
    uint32_t qfam;
    VkBuffer wbuf, vis, outb;
    VkDeviceMemory wmem, vismem, outmem;
    VkCommandPool pool;
    VkSemaphore sem;
    VkShaderModule sm;
    VkDescriptorSetLayout dsl;
    VkPipelineLayout pl;
    VkPipeline pipe;
    VkDescriptorPool dpool;
    VkDescriptorSet dset;
    uint64_t luid, bytes, vis_n, out_acc;
    uint64_t dim0, dim1, element_count, which_name;
    uint32_t tensor_type, token_id, embd_dim, embd_n;
    int luid_ok, imported, bound, sync_ok, vis_ok, retain;
    int prim_disp, prim_done, out_ok, same_mem;
    int model_op, out_finite, geo_ok;
} SsVk;
int ss_vk_load(SsVk *v);
int ss_vk_dev(SsVk *v, uint64_t luid);
int ss_vk_import(SsVk *v, void *nt, uint64_t bytes);
int ss_vk_sync(SsVk *v, void *fence_nt, uint64_t fence_val);
int ss_vk_vis(SsVk *v);
int ss_vk_pipe(SsVk *v);
int ss_vk_embd(SsVk *v);
void ss_vk_drop(SsVk *v);
int ss_vk_import_hot(void *nt, uint64_t luid, uint64_t bytes, void *fence_nt,
                     uint64_t fence_val, uint32_t ttype, uint64_t dim0,
                     uint64_t dim1, uint64_t elems, uint64_t which);
#endif
