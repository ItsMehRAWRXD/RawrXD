#include "vulkan_renderer.hpp"
#include "shader_file.hpp"

void VulkanRenderer::createProductPipeline() {
    auto vert = readShaderFile("instance.vert.spv");
    auto frag = readShaderFile("terrain.frag.spv");
    if (vert.empty() || frag.empty()) throw std::runtime_error("product shader");
    VkShaderModule vs = createShaderModule(vert);
    VkShaderModule fs = createShaderModule(frag);
    VkPipelineShaderStageCreateInfo stages[2]{};
    stages[0].sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    stages[0].stage = VK_SHADER_STAGE_VERTEX_BIT; stages[0].module = vs; stages[0].pName = "main";
    stages[1].sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    stages[1].stage = VK_SHADER_STAGE_FRAGMENT_BIT; stages[1].module = fs; stages[1].pName = "main";
    VkVertexInputBindingDescription binds[2]{};
    binds[0] = Vertex::getBindingDescription();
    binds[1].binding = 1; binds[1].stride = 12; binds[1].inputRate = VK_VERTEX_INPUT_RATE_INSTANCE;
    auto base = Vertex::getAttributeDescriptions();
    VkVertexInputAttributeDescription attr[4]{};
    for (int i = 0; i < 3; ++i) attr[i] = base[i];
    attr[3].location = 3; attr[3].binding = 1; attr[3].format = VK_FORMAT_R32G32B32_SFLOAT;
    VkPipelineVertexInputStateCreateInfo vertex{};
    vertex.sType = VK_STRUCTURE_TYPE_PIPELINE_VERTEX_INPUT_STATE_CREATE_INFO;
    vertex.vertexBindingDescriptionCount = 2; vertex.pVertexBindingDescriptions = binds;
    vertex.vertexAttributeDescriptionCount = 4; vertex.pVertexAttributeDescriptions = attr;
    VkPipelineInputAssemblyStateCreateInfo ia{};
    ia.sType = VK_STRUCTURE_TYPE_PIPELINE_INPUT_ASSEMBLY_STATE_CREATE_INFO;
    ia.topology = VK_PRIMITIVE_TOPOLOGY_TRIANGLE_LIST;
    VkPipelineViewportStateCreateInfo vp{};
    vp.sType = VK_STRUCTURE_TYPE_PIPELINE_VIEWPORT_STATE_CREATE_INFO;
    vp.viewportCount = 1; vp.scissorCount = 1;
    VkDynamicState dynStates[2] = {VK_DYNAMIC_STATE_VIEWPORT, VK_DYNAMIC_STATE_SCISSOR};
    VkPipelineDynamicStateCreateInfo dyn{};
    dyn.sType = VK_STRUCTURE_TYPE_PIPELINE_DYNAMIC_STATE_CREATE_INFO;
    dyn.dynamicStateCount = 2; dyn.pDynamicStates = dynStates;
    VkPipelineRasterizationStateCreateInfo ras{};
    ras.sType = VK_STRUCTURE_TYPE_PIPELINE_RASTERIZATION_STATE_CREATE_INFO;
    ras.polygonMode = VK_POLYGON_MODE_FILL; ras.lineWidth = 1.0f; ras.cullMode = VK_CULL_MODE_NONE;
    VkPipelineMultisampleStateCreateInfo ms{};
    ms.sType = VK_STRUCTURE_TYPE_PIPELINE_MULTISAMPLE_STATE_CREATE_INFO;
    ms.rasterizationSamples = VK_SAMPLE_COUNT_1_BIT;
    VkPipelineDepthStencilStateCreateInfo ds{};
    ds.sType = VK_STRUCTURE_TYPE_PIPELINE_DEPTH_STENCIL_STATE_CREATE_INFO;
    ds.depthTestEnable = VK_TRUE; ds.depthWriteEnable = VK_TRUE; ds.depthCompareOp = VK_COMPARE_OP_LESS;
    VkPipelineColorBlendAttachmentState blend{}; blend.colorWriteMask = 0xF;
    VkPipelineColorBlendStateCreateInfo cb{};
    cb.sType = VK_STRUCTURE_TYPE_PIPELINE_COLOR_BLEND_STATE_CREATE_INFO;
    cb.attachmentCount = 1; cb.pAttachments = &blend;
    VkGraphicsPipelineCreateInfo info{};
    info.sType = VK_STRUCTURE_TYPE_GRAPHICS_PIPELINE_CREATE_INFO;
    info.stageCount = 2; info.pStages = stages;
    info.pVertexInputState = &vertex; info.pInputAssemblyState = &ia;
    info.pViewportState = &vp; info.pRasterizationState = &ras;
    info.pMultisampleState = &ms; info.pDepthStencilState = &ds;
    info.pColorBlendState = &cb; info.pDynamicState = &dyn;
    info.layout = pipelineLayout_; info.renderPass = renderPass_;
    if (vkCreateGraphicsPipelines(device_, VK_NULL_HANDLE, 1, &info, nullptr, &productPipeline_) != VK_SUCCESS)
        throw std::runtime_error("product pipeline");
    vkDestroyShaderModule(device_, vs, nullptr);
    vkDestroyShaderModule(device_, fs, nullptr);
    VkQueryPoolCreateInfo qp{};
    qp.sType = VK_STRUCTURE_TYPE_QUERY_POOL_CREATE_INFO;
    qp.queryType = VK_QUERY_TYPE_TIMESTAMP; qp.queryCount = 2;
    vkCreateQueryPool(device_, &qp, nullptr, &productQuery_);
    createProductMeshes();
}
