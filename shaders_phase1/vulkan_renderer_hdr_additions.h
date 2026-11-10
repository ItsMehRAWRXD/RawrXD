// KartGib HDR + bloom additions for vulkan_renderer.h
//
// Append these to the VulkanRenderer class definition in
// G:\VSC0de\src\renderer\vulkan_renderer.h

// --- Config additions (add to Config struct) ---
bool hdr_enabled = true;        // render to floating-point intermediate
uint32_t bloom_levels = 4;      // number of downsample levels for bloom
float bloom_threshold = 1.0;    // bright-pass threshold
float bloom_knee = 0.5;         // bright-pass soft knee
float bloom_strength = 0.8;     // bloom intensity multiplier

// --- New members (add to private section) ---

// HDR offscreen render target (floating point).
VkRenderPass hdr_render_pass_ = VK_NULL_HANDLE;
std::vector<VkImage> hdr_images_;
std::vector<VkImageView> hdr_image_views_;
std::vector<VkFramebuffer> hdr_framebuffers_;
VkImage hdr_depth_image_ = VK_NULL_HANDLE;
VkDeviceMemory hdr_depth_memory_ = VK_NULL_HANDLE;
VkImageView hdr_depth_view_ = VK_NULL_HANDLE;

// Bloom resources.
struct BloomLevel {
    VkImage image = VK_NULL_HANDLE;
    VkDeviceMemory memory = VK_NULL_HANDLE;
    VkImageView view = VK_NULL_HANDLE;
    VkFramebuffer framebuffer = VK_NULL_HANDLE;
    VkExtent2D extent{};
};
std::vector<BloomLevel> bloom_levels_;

// Bloom pipelines and layouts.
VkPipelineLayout bloom_layout_ = VK_NULL_HANDLE;
VkPipeline bright_pass_pipeline_ = VK_NULL_HANDLE;
VkPipeline blur_h_pipeline_ = VK_NULL_HANDLE;
VkPipeline blur_v_pipeline_ = VK_NULL_HANDLE;
VkPipeline composite_pipeline_ = VK_NULL_HANDLE;

// Bloom descriptor sets (one per level + composite).
std::vector<VkDescriptorSet> bloom_descriptor_sets_;

// --- New methods ---

bool CreateHDRRenderPass();
bool CreateHDRFramebuffers();
bool CreateBloomResources();
bool CreateBloomPipelines();
void DestroyHDRResources();
void DestroyBloomResources();

void RecordBrightPass(VkCommandBuffer cmd, uint32_t level);
void RecordBlurPasses(VkCommandBuffer cmd);
void RecordComposite(VkCommandBuffer cmd);
