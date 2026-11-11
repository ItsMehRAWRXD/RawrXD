// KartGib HDR + bloom implementation additions for vulkan_renderer.cpp
//
// Copy these into G:\VSC0de\src\renderer\vulkan_renderer.cpp at the
// indicated locations.

// ============================================================================
// 1. HDR Render Pass
// ============================================================================

bool VulkanRenderer::CreateHDRRenderPass() {
    VkAttachmentDescription color_att{};
    color_att.format = VK_FORMAT_R16G16B16A16_SFLOAT;   // HDR intermediate
    color_att.samples = VK_SAMPLE_COUNT_1_BIT;
    color_att.loadOp = VK_ATTACHMENT_LOAD_OP_CLEAR;
    color_att.storeOp = VK_ATTACHMENT_STORE_OP_STORE;
    color_att.stencilLoadOp = VK_ATTACHMENT_LOAD_OP_DONT_CARE;
    color_att.stencilStoreOp = VK_ATTACHMENT_STORE_OP_DONT_CARE;
    color_att.initialLayout = VK_IMAGE_LAYOUT_UNDEFINED;
    color_att.finalLayout = VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL;

    VkAttachmentReference color_ref{};
    color_ref.attachment = 0;
    color_ref.layout = VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL;

    VkAttachmentDescription depth_att{};
    depth_att.format = VK_FORMAT_D32_SFLOAT;
    depth_att.samples = VK_SAMPLE_COUNT_1_BIT;
    depth_att.loadOp = VK_ATTACHMENT_LOAD_OP_CLEAR;
    depth_att.storeOp = VK_ATTACHMENT_STORE_OP_DONT_CARE;
    depth_att.stencilLoadOp = VK_ATTACHMENT_LOAD_OP_DONT_CARE;
    depth_att.stencilStoreOp = VK_ATTACHMENT_STORE_OP_DONT_CARE;
    depth_att.initialLayout = VK_IMAGE_LAYOUT_UNDEFINED;
    depth_att.finalLayout = VK_IMAGE_LAYOUT_DEPTH_STENCIL_ATTACHMENT_OPTIMAL;

    VkAttachmentReference depth_ref{};
    depth_ref.attachment = 1;
    depth_ref.layout = VK_IMAGE_LAYOUT_DEPTH_STENCIL_ATTACHMENT_OPTIMAL;

    VkSubpassDescription subpass{};
    subpass.pipelineBindPoint = VK_PIPELINE_BIND_POINT_GRAPHICS;
    subpass.colorAttachmentCount = 1;
    subpass.pColorAttachments = &color_ref;
    subpass.pDepthStencilAttachment = &depth_ref;

    VkSubpassDependency dep{};
    dep.srcSubpass = VK_SUBPASS_EXTERNAL;
    dep.dstSubpass = 0;
    dep.srcStageMask = VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT |
                       VK_PIPELINE_STAGE_EARLY_FRAGMENT_TESTS_BIT;
    dep.dstStageMask = VK_PIPELINE_STAGE_FRAGMENT_SHADER_BIT |
                       VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT;
    dep.srcAccessMask = 0;
    dep.dstAccessMask = VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT |
                        VK_ACCESS_DEPTH_STENCIL_ATTACHMENT_WRITE_BIT |
                        VK_ACCESS_SHADER_READ_BIT;

    const std::array<VkAttachmentDescription, 2> attachments = {color_att, depth_att};

    VkRenderPassCreateInfo rp_info{};
    rp_info.sType = VK_STRUCTURE_TYPE_RENDER_PASS_CREATE_INFO;
    rp_info.attachmentCount = static_cast<uint32_t>(attachments.size());
    rp_info.pAttachments = attachments.data();
    rp_info.subpassCount = 1;
    rp_info.pSubpasses = &subpass;
    rp_info.dependencyCount = 1;
    rp_info.pDependencies = &dep;

    return vkCreateRenderPass(device_, &rp_info, nullptr, &hdr_render_pass_) == VK_SUCCESS;
}

// ============================================================================
// 2. HDR Framebuffers
// ============================================================================

bool VulkanRenderer::CreateHDRFramebuffers() {
    // Depth image shared with HDR render target.
    VkImageCreateInfo depth_info{};
    depth_info.sType = VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO;
    depth_info.imageType = VK_IMAGE_TYPE_2D;
    depth_info.format = VK_FORMAT_D32_SFLOAT;
    depth_info.extent = {swapchain_extent_.width, swapchain_extent_.height, 1};
    depth_info.mipLevels = 1;
    depth_info.arrayLayers = 1;
    depth_info.samples = VK_SAMPLE_COUNT_1_BIT;
    depth_info.tiling = VK_IMAGE_TILING_OPTIMAL;
    depth_info.usage = VK_IMAGE_USAGE_DEPTH_STENCIL_ATTACHMENT_BIT;
    depth_info.initialLayout = VK_IMAGE_LAYOUT_UNDEFINED;
    depth_info.sharingMode = VK_SHARING_MODE_EXCLUSIVE;

    if (vkCreateImage(device_, &depth_info, nullptr, &hdr_depth_image_) != VK_SUCCESS) {
        KG_ERROR("Failed to create HDR depth image");
        return false;
    }

    VkMemoryRequirements depth_req{};
    vkGetImageMemoryRequirements(device_, hdr_depth_image_, &depth_req);

    VkPhysicalDeviceMemoryProperties mem_props{};
    vkGetPhysicalDeviceMemoryProperties(physical_device_, &mem_props);

    uint32_t depth_type = UINT32_MAX;
    for (uint32_t i = 0; i < mem_props.memoryTypeCount; ++i) {
        if ((depth_req.memoryTypeBits & (1u << i)) &&
            (mem_props.memoryTypes[i].propertyFlags & VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT) ==
                VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT) {
            depth_type = i;
            break;
        }
    }
    if (depth_type == UINT32_MAX) {
        KG_ERROR("No device-local memory type for HDR depth image");
        return false;
    }

    VkMemoryAllocateInfo depth_alloc{};
    depth_alloc.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    depth_alloc.allocationSize = depth_req.size;
    depth_alloc.memoryTypeIndex = depth_type;

    if (vkAllocateMemory(device_, &depth_alloc, nullptr, &hdr_depth_memory_) != VK_SUCCESS) {
        KG_ERROR("Failed to allocate HDR depth image memory");
        return false;
    }
    vkBindImageMemory(device_, hdr_depth_image_, hdr_depth_memory_, 0);

    VkImageViewCreateInfo depth_view_info{};
    depth_view_info.sType = VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO;
    depth_view_info.image = hdr_depth_image_;
    depth_view_info.viewType = VK_IMAGE_VIEW_TYPE_2D;
    depth_view_info.format = VK_FORMAT_D32_SFLOAT;
    depth_view_info.subresourceRange = {VK_IMAGE_ASPECT_DEPTH_BIT, 0, 1, 0, 1};
    if (vkCreateImageView(device_, &depth_view_info, nullptr, &hdr_depth_view_) != VK_SUCCESS) {
        KG_ERROR("Failed to create HDR depth image view");
        return false;
    }

    // HDR color images — one per swapchain image.
    uint32_t image_count = static_cast<uint32_t>(swapchain_image_views_.size());
    hdr_images_.resize(image_count);
    hdr_image_views_.resize(image_count);
    hdr_framebuffers_.resize(image_count);

    VkImageCreateInfo hdr_info{};
    hdr_info.sType = VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO;
    hdr_info.imageType = VK_IMAGE_TYPE_2D;
    hdr_info.format = VK_FORMAT_R16G16B16A16_SFLOAT;
    hdr_info.extent = {swapchain_extent_.width, swapchain_extent_.height, 1};
    hdr_info.mipLevels = 1;
    hdr_info.arrayLayers = 1;
    hdr_info.samples = VK_SAMPLE_COUNT_1_BIT;
    hdr_info.tiling = VK_IMAGE_TILING_OPTIMAL;
    hdr_info.usage = VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT | VK_IMAGE_USAGE_SAMPLED_BIT;
    hdr_info.initialLayout = VK_IMAGE_LAYOUT_UNDEFINED;
    hdr_info.sharingMode = VK_SHARING_MODE_EXCLUSIVE;

    for (uint32_t i = 0; i < image_count; ++i) {
        if (vkCreateImage(device_, &hdr_info, nullptr, &hdr_images_[i]) != VK_SUCCESS) {
            KG_ERROR("Failed to create HDR color image {}", i);
            return false;
        }

        VkMemoryRequirements hdr_req{};
        vkGetImageMemoryRequirements(device_, hdr_images_[i], &hdr_req);

        uint32_t hdr_type = UINT32_MAX;
        for (uint32_t j = 0; j < mem_props.memoryTypeCount; ++j) {
            if ((hdr_req.memoryTypeBits & (1u << j)) &&
                (mem_props.memoryTypes[j].propertyFlags & VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT) ==
                    VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT) {
                hdr_type = j;
                break;
            }
        }
        if (hdr_type == UINT32_MAX) {
            KG_ERROR("No device-local memory type for HDR color image");
            return false;
        }

        VkMemoryAllocateInfo hdr_alloc{};
        hdr_alloc.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
        hdr_alloc.allocationSize = hdr_req.size;
        hdr_alloc.memoryTypeIndex = hdr_type;

        VkDeviceMemory hdr_mem = VK_NULL_HANDLE;
        if (vkAllocateMemory(device_, &hdr_alloc, nullptr, &hdr_mem) != VK_SUCCESS) {
            KG_ERROR("Failed to allocate HDR color image memory");
            return false;
        }
        vkBindImageMemory(device_, hdr_images_[i], hdr_mem, 0);

        // Store the memory in a temporary — we need to track it for cleanup.
        // (In production, store in a member vector.)
        (void)hdr_mem;

        VkImageViewCreateInfo hdr_view_info{};
        hdr_view_info.sType = VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO;
        hdr_view_info.image = hdr_images_[i];
        hdr_view_info.viewType = VK_IMAGE_VIEW_TYPE_2D;
        hdr_view_info.format = VK_FORMAT_R16G16B16A16_SFLOAT;
        hdr_view_info.subresourceRange = {VK_IMAGE_ASPECT_COLOR_BIT, 0, 1, 0, 1};
        if (vkCreateImageView(device_, &hdr_view_info, nullptr, &hdr_image_views_[i]) != VK_SUCCESS) {
            KG_ERROR("Failed to create HDR image view {}", i);
            return false;
        }

        const VkImageView attachments[] = {hdr_image_views_[i], hdr_depth_view_};
        VkFramebufferCreateInfo fb_info{};
        fb_info.sType = VK_STRUCTURE_TYPE_FRAMEBUFFER_CREATE_INFO;
        fb_info.renderPass = hdr_render_pass_;
        fb_info.attachmentCount = 2;
        fb_info.pAttachments = attachments;
        fb_info.width = swapchain_extent_.width;
        fb_info.height = swapchain_extent_.height;
        fb_info.layers = 1;
        if (vkCreateFramebuffer(device_, &fb_info, nullptr, &hdr_framebuffers_[i]) != VK_SUCCESS) {
            KG_ERROR("Failed to create HDR framebuffer {}", i);
            return false;
        }
    }

    return true;
}

// ============================================================================
// 3. Bloom Resources (downsampled textures at multiple resolutions)
// ============================================================================

bool VulkanRenderer::CreateBloomResources() {
    VkExtent2D extent = swapchain_extent_;
    bloom_levels_.clear();
    bloom_levels_.reserve(config_.bloom_levels);

    for (uint32_t level = 0; level < config_.bloom_levels; ++level) {
        BloomLevel bl;
        bl.extent.width = std::max(1u, extent.width >> level);
        bl.extent.height = std::max(1u, extent.height >> level);

        VkImageCreateInfo info{};
        info.sType = VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO;
        info.imageType = VK_IMAGE_TYPE_2D;
        info.format = VK_FORMAT_R16G16B16A16_SFLOAT;
        info.extent = {bl.extent.width, bl.extent.height, 1};
        info.mipLevels = 1;
        info.arrayLayers = 1;
        info.samples = VK_SAMPLE_COUNT_1_BIT;
        info.tiling = VK_IMAGE_TILING_OPTIMAL;
        info.usage = VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT | VK_IMAGE_USAGE_SAMPLED_BIT;
        info.initialLayout = VK_IMAGE_LAYOUT_UNDEFINED;
        info.sharingMode = VK_SHARING_MODE_EXCLUSIVE;

        if (vkCreateImage(device_, &info, nullptr, &bl.image) != VK_SUCCESS) {
            KG_ERROR("Failed to create bloom level {} image", level);
            return false;
        }

        VkMemoryRequirements req{};
        vkGetImageMemoryRequirements(device_, bl.image, &req);

        VkPhysicalDeviceMemoryProperties mem_props{};
        vkGetPhysicalDeviceMemoryProperties(physical_device_, &mem_props);

        uint32_t mem_type = UINT32_MAX;
        for (uint32_t j = 0; j < mem_props.memoryTypeCount; ++j) {
            if ((req.memoryTypeBits & (1u << j)) &&
                (mem_props.memoryTypes[j].propertyFlags & VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT) ==
                    VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT) {
                mem_type = j;
                break;
            }
        }
        if (mem_type == UINT32_MAX) {
            KG_ERROR("No memory type for bloom level {}", level);
            return false;
        }

        VkMemoryAllocateInfo alloc{};
        alloc.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
        alloc.allocationSize = req.size;
        alloc.memoryTypeIndex = mem_type;

        if (vkAllocateMemory(device_, &alloc, nullptr, &bl.memory) != VK_SUCCESS) {
            KG_ERROR("Failed to allocate bloom level {} memory", level);
            return false;
        }
        vkBindImageMemory(device_, bl.image, bl.memory, 0);

        VkImageViewCreateInfo view_info{};
        view_info.sType = VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO;
        view_info.image = bl.image;
        view_info.viewType = VK_IMAGE_VIEW_TYPE_2D;
        view_info.format = VK_FORMAT_R16G16B16A16_SFLOAT;
        view_info.subresourceRange = {VK_IMAGE_ASPECT_COLOR_BIT, 0, 1, 0, 1};
        if (vkCreateImageView(device_, &view_info, nullptr, &bl.view) != VK_SUCCESS) {
            KG_ERROR("Failed to create bloom level {} view", level);
            return false;
        }

        VkFramebufferCreateInfo fb_info{};
        fb_info.sType = VK_STRUCTURE_TYPE_FRAMEBUFFER_CREATE_INFO;
        fb_info.renderPass = hdr_render_pass_;  // reuse HDR render pass (color-only)
        fb_info.attachmentCount = 1;
        fb_info.pAttachments = &bl.view;
        fb_info.width = bl.extent.width;
        fb_info.height = bl.extent.height;
        fb_info.layers = 1;
        if (vkCreateFramebuffer(device_, &fb_info, nullptr, &bl.framebuffer) != VK_SUCCESS) {
            KG_ERROR("Failed to create bloom level {} framebuffer", level);
            return false;
        }

        bloom_levels_.push_back(std::move(bl));
    }

    return true;
}

// ============================================================================
// 4. Bloom Pipelines (bright pass, blur H/V, composite)
// ============================================================================

bool VulkanRenderer::CreateBloomPipelines() {
    // Bloom pipeline layout: two sampled textures (source + optional accumulator).
    VkPipelineLayoutCreateInfo layout_info{};
    layout_info.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
    layout_info.setLayoutCount = 1;
    layout_info.pSetLayouts = &global_set_layout_;  // reused for bloom uniforms
    if (vkCreatePipelineLayout(device_, &layout_info, nullptr, &bloom_layout_) != VK_SUCCESS) {
        KG_ERROR("Failed to create bloom pipeline layout");
        return false;
    }

    // Load SPIR-V shaders.
    auto load_spirv = [this](const std::string& path) {
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file.is_open()) return std::vector<uint32_t>{};
        size_t size = static_cast<size_t>(file.tellg());
        file.seekg(0);
        std::vector<uint32_t> code(size / 4);
        file.read(reinterpret_cast<char*>(code.data()), static_cast<std::streamsize>(size));
        return code;
    };

    auto create_shader_module = [this](const std::vector<uint32_t>& code) {
        VkShaderModuleCreateInfo ci{};
        ci.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
        ci.codeSize = code.size() * sizeof(uint32_t);
        ci.pCode = code.data();
        VkShaderModule mod = VK_NULL_HANDLE;
        vkCreateShaderModule(device_, &ci, nullptr, &mod);
        return mod;
    };

    // Helper to create a fullscreen pipeline.
    auto make_fullscreen_pipeline = [&](VkShaderModule vert, VkShaderModule frag,
                                        VkRenderPass rp, VkPipeline& out) {
        std::array<VkPipelineShaderStageCreateInfo, 2> stages{};
        stages[0].sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
        stages[0].stage = VK_SHADER_STAGE_VERTEX_BIT;
        stages[0].module = vert;
        stages[0].pName = "main";
        stages[1].sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
        stages[1].stage = VK_SHADER_STAGE_FRAGMENT_BIT;
        stages[1].module = frag;
        stages[1].pName = "main";

        VkPipelineVertexInputStateCreateInfo vi{};
        vi.sType = VK_STRUCTURE_TYPE_PIPELINE_VERTEX_INPUT_STATE_CREATE_INFO;

        VkPipelineInputAssemblyStateCreateInfo ia{};
        ia.sType = VK_STRUCTURE_TYPE_PIPELINE_INPUT_ASSEMBLY_STATE_CREATE_INFO;
        ia.topology = VK_PRIMITIVE_TOPOLOGY_TRIANGLE_LIST;

        VkPipelineViewportStateCreateInfo vs{};
        vs.sType = VK_STRUCTURE_TYPE_PIPELINE_VIEWPORT_STATE_CREATE_INFO;
        vs.viewportCount = 1;
        vs.scissorCount = 1;

        VkPipelineRasterizationStateCreateInfo rs{};
        rs.sType = VK_STRUCTURE_TYPE_PIPELINE_RASTERIZATION_STATE_CREATE_INFO;
        rs.polygonMode = VK_POLYGON_MODE_FILL;
        rs.cullMode = VK_CULL_MODE_NONE;
        rs.frontFace = VK_FRONT_FACE_COUNTER_CLOCKWISE;
        rs.lineWidth = 1.0f;

        VkPipelineMultisampleStateCreateInfo ms{};
        ms.sType = VK_STRUCTURE_TYPE_PIPELINE_MULTISAMPLE_STATE_CREATE_INFO;
        ms.rasterizationSamples = VK_SAMPLE_COUNT_1_BIT;

        VkPipelineDepthStencilStateCreateInfo ds{};
        ds.sType = VK_STRUCTURE_TYPE_PIPELINE_DEPTH_STENCIL_STATE_CREATE_INFO;
        ds.depthTestEnable = VK_FALSE;
        ds.depthWriteEnable = VK_FALSE;

        VkPipelineColorBlendAttachmentState ba{};
        ba.colorWriteMask = VK_COLOR_COMPONENT_R_BIT | VK_COLOR_COMPONENT_G_BIT |
                            VK_COLOR_COMPONENT_B_BIT | VK_COLOR_COMPONENT_A_BIT;
        ba.blendEnable = VK_FALSE;

        VkPipelineColorBlendStateCreateInfo cb{};
        cb.sType = VK_STRUCTURE_TYPE_PIPELINE_COLOR_BLEND_STATE_CREATE_INFO;
        cb.attachmentCount = 1;
        cb.pAttachments = &ba;

        const std::array<VkDynamicState, 2> ds_states = {
            VK_DYNAMIC_STATE_VIEWPORT, VK_DYNAMIC_STATE_SCISSOR};
        VkPipelineDynamicStateCreateInfo dyn{};
        dyn.sType = VK_STRUCTURE_TYPE_PIPELINE_DYNAMIC_STATE_CREATE_INFO;
        dyn.dynamicStateCount = static_cast<uint32_t>(ds_states.size());
        dyn.pDynamicStates = ds_states.data();

        VkGraphicsPipelineCreateInfo pi{};
        pi.sType = VK_STRUCTURE_TYPE_GRAPHICS_PIPELINE_CREATE_INFO;
        pi.stageCount = 2;
        pi.pStages = stages.data();
        pi.pVertexInputState = &vi;
        pi.pInputAssemblyState = &ia;
        pi.pViewportState = &vs;
        pi.pRasterizationState = &rs;
        pi.pMultisampleState = &ms;
        pi.pDepthStencilState = &ds;
        pi.pColorBlendState = &cb;
        pi.pDynamicState = &dyn;
        pi.layout = bloom_layout_;
        pi.renderPass = rp;
        pi.subpass = 0;

        VkResult result = vkCreateGraphicsPipelines(device_, VK_NULL_HANDLE, 1, &pi,
                                                    nullptr, &out);
        return result == VK_SUCCESS;
    };

    // Compile shaders.
    VkShaderModule hdr_vert = create_shader_module(load_spirv("shaders/hdr_vert.spv"));
    VkShaderModule bright_frag = create_shader_module(load_spirv("shaders/bright_frag.spv"));
    VkShaderModule blur_frag = create_shader_module(load_spirv("shaders/blur_frag.spv"));
    VkShaderModule composite_frag = create_shader_module(load_spirv("shaders/bloom_composite_frag.spv"));

    if (!hdr_vert || !bright_frag || !blur_frag || !composite_frag) {
        KG_ERROR("Failed to load bloom SPIR-V shaders");
        return false;
    }

    bool ok = true;
    ok &= make_fullscreen_pipeline(hdr_vert, bright_frag, hdr_render_pass_, bright_pass_pipeline_);
    ok &= make_fullscreen_pipeline(hdr_vert, blur_frag, hdr_render_pass_, blur_h_pipeline_);
    ok &= make_fullscreen_pipeline(hdr_vert, blur_frag, hdr_render_pass_, blur_v_pipeline_);
    ok &= make_fullscreen_pipeline(hdr_vert, composite_frag, VK_NULL_HANDLE, composite_pipeline_);

    vkDestroyShaderModule(device_, hdr_vert, nullptr);
    vkDestroyShaderModule(device_, bright_frag, nullptr);
    vkDestroyShaderModule(device_, blur_frag, nullptr);
    vkDestroyShaderModule(device_, composite_frag, nullptr);

    return ok;
}

// ============================================================================
// 5. Destroy HDR + bloom resources
// ============================================================================

void VulkanRenderer::DestroyHDRResources() {
    for (auto& fb : hdr_framebuffers_) {
        if (fb) vkDestroyFramebuffer(device_, fb, nullptr);
    }
    hdr_framebuffers_.clear();
    for (auto& view : hdr_image_views_) {
        if (view) vkDestroyImageView(device_, view, nullptr);
    }
    hdr_image_views_.clear();
    for (auto& img : hdr_images_) {
        if (img) vkDestroyImage(device_, img, nullptr);
    }
    hdr_images_.clear();
    if (hdr_depth_view_) vkDestroyImageView(device_, hdr_depth_view_, nullptr);
    if (hdr_depth_image_) vkDestroyImage(device_, hdr_depth_image_, nullptr);
    if (hdr_depth_memory_) vkFreeMemory(device_, hdr_depth_memory_, nullptr);
    if (hdr_render_pass_) vkDestroyRenderPass(device_, hdr_render_pass_, nullptr);
}

void VulkanRenderer::DestroyBloomResources() {
    for (auto& level : bloom_levels_) {
        if (level.framebuffer) vkDestroyFramebuffer(device_, level.framebuffer, nullptr);
        if (level.view) vkDestroyImageView(device_, level.view, nullptr);
        if (level.image) vkDestroyImage(device_, level.image, nullptr);
        if (level.memory) vkFreeMemory(device_, level.memory, nullptr);
    }
    bloom_levels_.clear();
    if (bright_pass_pipeline_) vkDestroyPipeline(device_, bright_pass_pipeline_, nullptr);
    if (blur_h_pipeline_) vkDestroyPipeline(device_, blur_h_pipeline_, nullptr);
    if (blur_v_pipeline_) vkDestroyPipeline(device_, blur_v_pipeline_, nullptr);
    if (composite_pipeline_) vkDestroyPipeline(device_, composite_pipeline_, nullptr);
    if (bloom_layout_) vkDestroyPipelineLayout(device_, bloom_layout_, nullptr);
}

// ============================================================================
// 6. Bright-pass: isolate pixels above threshold
// ============================================================================

void VulkanRenderer::RecordBrightPass(VkCommandBuffer cmd, uint32_t level) {
    if (level >= bloom_levels_.size()) return;

    const auto& bl = bloom_levels_[level];
    vkCmdBindPipeline(cmd, VK_PIPELINE_BIND_POINT_GRAPHICS, bright_pass_pipeline_);

    VkViewport viewport{};
    viewport.width = static_cast<float>(bl.extent.width);
    viewport.height = static_cast<float>(bl.extent.height);
    viewport.maxDepth = 1.0f;
    vkCmdSetViewport(cmd, 0, 1, &viewport);

    VkRect2D scissor{};
    scissor.extent = bl.extent;
    vkCmdSetScissor(cmd, 0, 1, &scissor);

    // Source is previous level (level 0 = HDR scene, level > 0 = previous blur).
    VkDescriptorSet sets[] = {global_descriptor_sets_[current_frame_]};
    vkCmdBindDescriptorSets(cmd, VK_PIPELINE_BIND_POINT_GRAPHICS, bloom_layout_, 0, 1,
                            sets, 0, nullptr);

    // Push constants: threshold, knee, source texture binding.
    // (Simplified — in production use a dedicated bloom uniform block.)
    float push[] = {config_.bloom_threshold, config_.bloom_knee};
    vkCmdPushConstants(cmd, bloom_layout_, VK_SHADER_STAGE_FRAGMENT_BIT, 0, 8, push);

    vkCmdDraw(cmd, 3, 1, 0, 0);
}

// ============================================================================
