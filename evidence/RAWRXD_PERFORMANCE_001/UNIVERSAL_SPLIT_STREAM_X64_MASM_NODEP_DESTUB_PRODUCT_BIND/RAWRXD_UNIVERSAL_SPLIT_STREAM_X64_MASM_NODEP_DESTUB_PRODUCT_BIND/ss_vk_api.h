/* ss_vk_api.h — import + model/block/onorm/lmhead/decode; no promote mint */
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
    VkBuffer wbuf, vis, outb, pbuf, actb, anorm_wb, onorm_wb, lbuf, logitsb;
    VkDeviceMemory wmem, vismem, outmem, pmem, actmem, anorm_wm, onorm_wm, lmem, logitsmem;
    VkCommandPool pool;
    VkSemaphore sem;
    VkShaderModule sm;
    VkDescriptorSetLayout dsl;
    VkPipelineLayout pl;
    VkPipeline pipe;
    VkDescriptorPool dpool;
    VkDescriptorSet dset;
    uint64_t luid, bytes, pbytes, lbytes, vis_n, out_acc;
    uint64_t dim0, dim1, element_count, which_name;
    uint32_t tensor_type, token_id, embd_dim, embd_n, block_n, vocab_n, next_token;
    uint32_t decode_steps;
    double abbrev_tps;
    int luid_ok, imported, bound, sync_ok, vis_ok, retain;
    int prim_disp, prim_done, out_ok, same_mem;
    int model_op, out_finite, geo_ok;
    int proj_imported, proj_hot, rms_disp, rms_done, proj_disp, proj_done;
    int chain_gpu, block_finite, block_ok, block_op;
    int onorm_op, logits_op, token_op, decode_loop;
} SsVk;
typedef int (*SsVkPromote2)(const void *host, uint64_t n, void **nt_out,
                            void **fence_nt_out, uint64_t *fence_val_out);
int ss_vk_load(SsVk *v);
int ss_vk_dev(SsVk *v, uint64_t luid);
int ss_vk_import(SsVk *v, void *nt, uint64_t bytes);
int ss_vk_import2(SsVk *v, void *nt, uint64_t bytes);
int ss_vk_import_lm(SsVk *v, void *nt, uint64_t bytes);
int ss_vk_sync(SsVk *v, void *fence_nt, uint64_t fence_val);
int ss_vk_vis(SsVk *v);
int ss_vk_pipe(SsVk *v);
int ss_vk_embd(SsVk *v);
int ss_vk_block(SsVk *v, const char *shard, SsVkPromote2 promote2);
int ss_vk_block_exec(SsVk *v, VkBuffer nwb, uint64_t nbytes, VkBuffer nob, VkBuffer qob,
                     VkDeviceMemory qom, uint32_t rows, uint32_t cols);
int ss_vk_onorm(SsVk *v, const char *shard);
int ss_vk_lmhead(SsVk *v, const char *shard, SsVkPromote2 promote2);
int ss_vk_token_commit(SsVk *v);
int ss_vk_abbrev_decode(SsVk *v, const char *shard, uint32_t steps);
uint32_t ss_vk_host_type(SsVk *v, uint32_t bits);
int ss_vk_mkbuf(SsVk *v, VkDeviceSize sz, VkBuffer *b, VkDeviceMemory *m, void **map);
int ss_vk_pipe3(SsVk *v, const uint32_t *spv, uint32_t words, uint32_t pc_bytes,
                VkShaderModule *sm, VkDescriptorSetLayout *dsl, VkPipelineLayout *pl,
                VkPipeline *pipe, VkDescriptorPool *dpool, VkDescriptorSet *dset);
void ss_vk_drop(SsVk *v);
int ss_vk_import_hot(void *nt, uint64_t luid, uint64_t bytes, void *fence_nt,
                     uint64_t fence_val, uint32_t ttype, uint64_t dim0,
                     uint64_t dim1, uint64_t elems, uint64_t which,
                     const char *shard, SsVkPromote2 promote2);
#endif
