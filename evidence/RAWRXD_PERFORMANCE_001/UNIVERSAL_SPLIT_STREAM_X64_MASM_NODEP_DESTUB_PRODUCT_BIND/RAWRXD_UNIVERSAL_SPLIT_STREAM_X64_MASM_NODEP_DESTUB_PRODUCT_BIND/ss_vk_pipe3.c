/* ss_vk_pipe3.c — 3-binding compute pipe (rmsnorm / gemv) */
#include "ss_vk_api.h"
int ss_vk_pipe3(SsVk *v, const uint32_t *spv, uint32_t words, uint32_t pc_bytes,
                VkShaderModule *sm, VkDescriptorSetLayout *dsl, VkPipelineLayout *pl,
                VkPipeline *pipe, VkDescriptorPool *dpool, VkDescriptorSet *dset)
{
    VkShaderModuleCreateInfo smi = { VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO };
    VkDescriptorSetLayoutBinding b[3] = { 0 };
    VkDescriptorSetLayoutCreateInfo dli = { VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO };
    VkPushConstantRange pcr = { VK_SHADER_STAGE_COMPUTE_BIT, 0, pc_bytes };
    VkPipelineLayoutCreateInfo pli = { VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO };
    VkComputePipelineCreateInfo cpi = { VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO };
    VkDescriptorPoolSize ps = { VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 3 };
    VkDescriptorPoolCreateInfo dpi = { VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO };
    VkDescriptorSetAllocateInfo dai = { VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO };
    int i;
    if (!v || !v->dev || !spv || !words) return 100;
    if (!v->a.create_sm) {
        v->a.create_sm = (PFN_vkCreateShaderModule)v->a.gdpa(v->dev, "vkCreateShaderModule");
        v->a.create_dsl = (PFN_vkCreateDescriptorSetLayout)v->a.gdpa(v->dev, "vkCreateDescriptorSetLayout");
        v->a.create_pl = (PFN_vkCreatePipelineLayout)v->a.gdpa(v->dev, "vkCreatePipelineLayout");
        v->a.create_cp = (PFN_vkCreateComputePipelines)v->a.gdpa(v->dev, "vkCreateComputePipelines");
        v->a.create_dp = (PFN_vkCreateDescriptorPool)v->a.gdpa(v->dev, "vkCreateDescriptorPool");
        v->a.alloc_ds = (PFN_vkAllocateDescriptorSets)v->a.gdpa(v->dev, "vkAllocateDescriptorSets");
        v->a.upd_ds = (PFN_vkUpdateDescriptorSets)v->a.gdpa(v->dev, "vkUpdateDescriptorSets");
        v->a.destroy_sm = (PFN_vkDestroyShaderModule)v->a.gdpa(v->dev, "vkDestroyShaderModule");
        v->a.destroy_dsl = (PFN_vkDestroyDescriptorSetLayout)v->a.gdpa(v->dev, "vkDestroyDescriptorSetLayout");
        v->a.destroy_pl = (PFN_vkDestroyPipelineLayout)v->a.gdpa(v->dev, "vkDestroyPipelineLayout");
        v->a.destroy_pipe = (PFN_vkDestroyPipeline)v->a.gdpa(v->dev, "vkDestroyPipeline");
        v->a.destroy_dp = (PFN_vkDestroyDescriptorPool)v->a.gdpa(v->dev, "vkDestroyDescriptorPool");
    }
    smi.codeSize = words * 4ull; smi.pCode = spv;
    if (v->a.create_sm(v->dev, &smi, 0, sm) != VK_SUCCESS) return 100;
    for (i = 0; i < 3; ++i) {
        b[i].binding = (uint32_t)i; b[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        b[i].descriptorCount = 1; b[i].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    }
    dli.bindingCount = 3; dli.pBindings = b;
    if (v->a.create_dsl(v->dev, &dli, 0, dsl) != VK_SUCCESS) return 100;
    pli.setLayoutCount = 1; pli.pSetLayouts = dsl;
    pli.pushConstantRangeCount = 1; pli.pPushConstantRanges = &pcr;
    if (v->a.create_pl(v->dev, &pli, 0, pl) != VK_SUCCESS) return 100;
    cpi.stage.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    cpi.stage.stage = VK_SHADER_STAGE_COMPUTE_BIT; cpi.stage.module = *sm; cpi.stage.pName = "main";
    cpi.layout = *pl;
    if (v->a.create_cp(v->dev, 0, 1, &cpi, 0, pipe) != VK_SUCCESS) return 100;
    dpi.maxSets = 1; dpi.poolSizeCount = 1; dpi.pPoolSizes = &ps;
    if (v->a.create_dp(v->dev, &dpi, 0, dpool) != VK_SUCCESS) return 100;
    dai.descriptorPool = *dpool; dai.descriptorSetCount = 1; dai.pSetLayouts = dsl;
    if (v->a.alloc_ds(v->dev, &dai, dset) != VK_SUCCESS) return 100;
    return 0;
}
