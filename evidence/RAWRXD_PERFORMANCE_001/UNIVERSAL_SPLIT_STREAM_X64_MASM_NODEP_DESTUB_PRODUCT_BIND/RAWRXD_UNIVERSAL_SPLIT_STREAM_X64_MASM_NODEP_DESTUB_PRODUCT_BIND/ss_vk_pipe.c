/* ss_vk_pipe.c — compute pipeline on imported HOT device; no weight alloc */
#include "ss_vk_api.h"
#include "ss_vk_embd_spv.h"
static void bind_pipe_fns(SsVk *v)
{
    v->a.create_sm = (PFN_vkCreateShaderModule)v->a.gdpa(v->dev, "vkCreateShaderModule");
    v->a.destroy_sm = (PFN_vkDestroyShaderModule)v->a.gdpa(v->dev, "vkDestroyShaderModule");
    v->a.create_dsl = (PFN_vkCreateDescriptorSetLayout)v->a.gdpa(v->dev, "vkCreateDescriptorSetLayout");
    v->a.destroy_dsl = (PFN_vkDestroyDescriptorSetLayout)v->a.gdpa(v->dev, "vkDestroyDescriptorSetLayout");
    v->a.create_pl = (PFN_vkCreatePipelineLayout)v->a.gdpa(v->dev, "vkCreatePipelineLayout");
    v->a.destroy_pl = (PFN_vkDestroyPipelineLayout)v->a.gdpa(v->dev, "vkDestroyPipelineLayout");
    v->a.create_cp = (PFN_vkCreateComputePipelines)v->a.gdpa(v->dev, "vkCreateComputePipelines");
    v->a.destroy_pipe = (PFN_vkDestroyPipeline)v->a.gdpa(v->dev, "vkDestroyPipeline");
    v->a.create_dp = (PFN_vkCreateDescriptorPool)v->a.gdpa(v->dev, "vkCreateDescriptorPool");
    v->a.destroy_dp = (PFN_vkDestroyDescriptorPool)v->a.gdpa(v->dev, "vkDestroyDescriptorPool");
    v->a.alloc_ds = (PFN_vkAllocateDescriptorSets)v->a.gdpa(v->dev, "vkAllocateDescriptorSets");
    v->a.upd_ds = (PFN_vkUpdateDescriptorSets)v->a.gdpa(v->dev, "vkUpdateDescriptorSets");
}
int ss_vk_pipe(SsVk *v)
{
    VkShaderModuleCreateInfo smi = { VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO };
    VkDescriptorSetLayoutBinding b[2] = { 0 };
    VkDescriptorSetLayoutCreateInfo dli = { VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO };
    VkPushConstantRange pcr = { VK_SHADER_STAGE_COMPUTE_BIT, 0, 16 };
    VkPipelineLayoutCreateInfo pli = { VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO };
    VkComputePipelineCreateInfo cpi = { VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO };
    VkDescriptorPoolSize ps = { VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 2 };
    VkDescriptorPoolCreateInfo dpi = { VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO };
    VkDescriptorSetAllocateInfo dai = { VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO };
    if (!v || !v->dev || !v->bound) return 100;
    bind_pipe_fns(v);
    if (!v->a.create_sm || !v->a.create_cp || !v->a.alloc_ds) return 100;
    smi.codeSize = ss_vk_embd_spv_words * 4ull;
    smi.pCode = ss_vk_embd_spv;
    if (v->a.create_sm(v->dev, &smi, 0, &v->sm) != VK_SUCCESS) return 100;
    b[0].binding = 0; b[0].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    b[0].descriptorCount = 1; b[0].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    b[1] = b[0]; b[1].binding = 1;
    dli.bindingCount = 2; dli.pBindings = b;
    if (v->a.create_dsl(v->dev, &dli, 0, &v->dsl) != VK_SUCCESS) return 100;
    pli.setLayoutCount = 1; pli.pSetLayouts = &v->dsl;
    pli.pushConstantRangeCount = 1; pli.pPushConstantRanges = &pcr;
    if (v->a.create_pl(v->dev, &pli, 0, &v->pl) != VK_SUCCESS) return 100;
    cpi.stage.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    cpi.stage.stage = VK_SHADER_STAGE_COMPUTE_BIT;
    cpi.stage.module = v->sm; cpi.stage.pName = "main";
    cpi.layout = v->pl;
    if (v->a.create_cp(v->dev, 0, 1, &cpi, 0, &v->pipe) != VK_SUCCESS) return 100;
    dpi.maxSets = 1; dpi.poolSizeCount = 1; dpi.pPoolSizes = &ps;
    if (v->a.create_dp(v->dev, &dpi, 0, &v->dpool) != VK_SUCCESS) return 100;
    dai.descriptorPool = v->dpool; dai.descriptorSetCount = 1; dai.pSetLayouts = &v->dsl;
    if (v->a.alloc_ds(v->dev, &dai, &v->dset) != VK_SUCCESS) return 100;
    return 0;
}
