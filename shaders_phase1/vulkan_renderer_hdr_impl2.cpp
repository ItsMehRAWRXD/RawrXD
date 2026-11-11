// ============================================================================
// 7. Blur passes (separable Gaussian: horizontal then vertical)
// ============================================================================

void VulkanRenderer::RecordBlurPasses(VkCommandBuffer cmd) {
    if (bloom_levels_.size() < 2) return;

    // Ping-pong between levels: blur H into level[i], blur V into level[i+1],
    // then use level[i+1] as source for next H blur, etc.
    // Simplest robust approach: each level reads from the previous level's
    // output and writes to its own framebuffer, alternating H/V.

    VkDescriptorSet sets[] = {global_descriptor_sets_[current_frame_]};
    vkCmdBindDescriptorSets(cmd, VK_PIPELINE_BIND_POINT_GRAPHICS, bloom_layout_, 0, 1,
                            sets, 0, nullptr);

    for (uint32_t i = 1; i < bloom_levels_.size(); ++i) {
        const auto& prev = bloom_levels_[i - 1];
        const auto& cur = bloom_levels_[i];

        // Horizontal blur: read prev level, write current level.
        vkCmdBindPipeline(cmd, VK_PIPELINE_BIND_POINT_GRAPHICS, blur_h_pipeline_);

        VkViewport viewport{};
        viewport.width = static_cast<float>(cur.extent.width);
        viewport.height = static_cast<float>(cur.extent.height);
        viewport.maxDepth = 1.0f;
        vkCmdSetViewport(cmd, 0, 1, &viewport);

        VkRect2D scissor{};
        scissor.extent = cur.extent;
        vkCmdSetScissor(cmd, 0, 1, &scissor);

        float push_h[] = {1.0f, 0.0f, 2.0f, 1.0f / static_cast<float>(cur.extent.width)};
        vkCmdPushConstants(cmd, bloom_layout_, VK_SHADER_STAGE_FRAGMENT_BIT, 0, 16, push_h);
        vkCmdDraw(cmd, 3, 1, 0, 0);

        // Vertical blur: read current level, write back to current level.
        // (In production, use a second set of textures for ping-pong.)
        vkCmdBindPipeline(cmd, VK_PIPELINE_BIND_POINT_GRAPHICS, blur_v_pipeline_);

        float push_v[] = {0.0f, 1.0f, 2.0f, 1.0f / static_cast<float>(cur.extent.height)};
        vkCmdPushConstants(cmd, bloom_layout_, VK_SHADER_STAGE_FRAGMENT_BIT, 0, 16, push_v);
        vkCmdDraw(cmd, 3, 1, 0, 0);
    }
}

// ============================================================================
// 8. Composite: HDR scene + bloom -> tone map -> swapchain
// ============================================================================

void VulkanRenderer::RecordComposite(VkCommandBuffer cmd) {
    // Composite renders to the swapchain image, not the HDR target.
    // The swapchain render pass is the original render_pass_.

    vkCmdBindPipeline(cmd, VK_PIPELINE_BIND_POINT_GRAPHICS, composite_pipeline_);

    VkViewport viewport{};
    viewport.x = 0.0f;
    viewport.y = 0.0f;
    viewport.width = static_cast<float>(swapchain_extent_.width);
    viewport.height = static_cast<float>(swapchain_extent_.height);
    viewport.minDepth = 0.0f;
    viewport.maxDepth = 1.0f;
    vkCmdSetViewport(cmd, 0, 1, &viewport);

    VkRect2D scissor{};
    scissor.offset = {0, 0};
    scissor.extent = swapchain_extent_;
    vkCmdSetScissor(cmd, 0, 1, &scissor);

    // Push constants: exposure, bloom_strength, gamma.
    float push[] = {1.0f, 0.8f, 2.2f};
    vkCmdPushConstants(cmd, bloom_layout_, VK_SHADER_STAGE_FRAGMENT_BIT, 0, 12, push);

    vkCmdDraw(cmd, 3, 1, 0, 0);
}
