# KartGib Phase 1: HDR + Bloom Integration Guide

## Overview

Phase 1 adds an HDR offscreen render target, bright-pass bloom extraction,
separable Gaussian blur, and a composite pass with ACES tone mapping and
exposure control. This is the foundation for the cinematic arcade racing
look from your reference images.

## Step 0: Compile New GLSL Shaders to SPIR-V

The five new shader files are at `F:\rawrxd\shaders_phase1\`. Compile them
with `glslc` from the Vulkan SDK (1.4.357.0 at `C:\VULKANSDK\`):

```powershell
$glslc = 'C:\VULKANSDK\1.4.357.0\Bin\glslc.exe'
$src = 'F:\rawrxd\shaders_phase1'
$dst = 'G:\VSC0de\build\Release\shaders'   # alongside existing spv files

& $glslc "$src\hdr_vert.glsl"   -o "$dst\hdr_vert.spv"
& $glslc "$src\hdr_frag.glsl"   -o "$dst\hdr_frag.spv"
& $glslc "$src\bright_frag.glsl" -o "$dst\bright_frag.spv"
& $glslc "$src\blur_frag.glsl"   -o "$dst\blur_frag.spv"
& $glslc "$src\bloom_composite_frag.glsl" -o "$dst\bloom_composite_frag.spv"
```

Verify all five `.spv` files exist in `G:\VSC0de\build\Release\shaders\`.

## Step 1: Header Additions (`vulkan_renderer.h`)

Open `G:\VSC0de\src\renderer\vulkan_renderer.h`.

### 1a. Add to `Config` struct

After `VkPresentModeKHR present_mode = VK_PRESENT_MODE_FIFO_KHR;`, add:

```cpp
bool hdr_enabled = true;        // render to floating-point intermediate
uint32_t bloom_levels = 4;      // number of downsample levels for bloom
float bloom_threshold = 1.0;    // bright-pass threshold
float bloom_knee = 0.5;         // bright-pass soft knee
float bloom_strength = 0.8;     // bloom intensity multiplier
```

### 1b. Add new members to private section

After the existing `Texture textures_;` member (or before `Config config_;`), add:

```cpp
// --- HDR offscreen render target ---
VkRenderPass hdr_render_pass_ = VK_NULL_HANDLE;
std::vector<VkImage> hdr_images_;
std::vector<VkImageView> hdr_image_views_;
std::vector<VkFramebuffer> hdr_framebuffers_;
VkImage hdr_depth_image_ = VK_NULL_HANDLE;
VkDeviceMemory hdr_depth_memory_ = VK_NULL_HANDLE;
VkImageView hdr_depth_view_ = VK_NULL_HANDLE;

// --- Bloom resources ---
struct BloomLevel {
    VkImage image = VK_NULL_HANDLE;
    VkDeviceMemory memory = VK_NULL_HANDLE;
    VkImageView view = VK_NULL_HANDLE;
    VkFramebuffer framebuffer = VK_NULL_HANDLE;
    VkExtent2D extent{};
};
std::vector<BloomLevel> bloom_levels_;

// --- Bloom pipelines ---
VkPipelineLayout bloom_layout_ = VK_NULL_HANDLE;
VkPipeline bright_pass_pipeline_ = VK_NULL_HANDLE;
VkPipeline blur_h_pipeline_ = VK_NULL_HANDLE;
VkPipeline blur_v_pipeline_ = VK_NULL_HANDLE;
VkPipeline composite_pipeline_ = VK_NULL_HANDLE;

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
```

## Step 2: Implementation Additions (`vulkan_renderer.cpp`)

Copy the contents of these files into `G:\VSC0de\src\renderer\vulkan_renderer.cpp`:

- `F:\rawrxd\shaders_phase1\vulkan_renderer_hdr_impl.cpp` — HDR render pass,
  HDR framebuffers, bloom resources, bloom pipelines, destroy functions,
  bright pass
- `F:\rawrxd\shaders_phase1\vulkan_renderer_hdr_impl2.cpp` — blur passes,
  composite pass

Place them after the existing `CreatePipelines()` implementation and before
the closing `} // namespace kartgib`.

## Step 3: Wire HDR into Initialize()

In `VulkanRenderer::Initialize()`, after `CreateRenderPass()` succeeds, add:

```cpp
if (config_.hdr_enabled) {
    if (!CreateHDRRenderPass() ||
        !CreateHDRFramebuffers() ||
        !CreateBloomResources() ||
        !CreateBloomPipelines()) {
        KG_ERROR("Failed to create HDR + bloom resources");
        return false;
    }
}
```

## Step 4: Wire HDR into CreatePipelines()

In `CreatePipelines()`, change the render pass used by the main graphics
pipeline from `render_pass_` to `hdr_render_pass_` when HDR is enabled:

```cpp
VkRenderPass pipeline_rp = config_.hdr_enabled ? hdr_render_pass_ : render_pass_;
// ... then use pipeline_rp in pipeline_info.renderPass
```

Also change `CreateSkyPipeline()` similarly so the sky renders into the HDR
target.

## Step 5: Wire HDR into BeginFrame / EndFrame

### BeginFrame()

Instead of beginning a render pass directly on the swapchain, begin on the
HDR framebuffer (level 0):

```cpp
void VulkanRenderer::BeginFrame() {
    // ... acquire swapchain image as before ...

    VkRenderPassBeginInfo rp_info{};
    rp_info.sType = VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO;
    rp_info.renderPass = config_.hdr_enabled ? hdr_render_pass_ : render_pass_;
    rp_info.framebuffer = config_.hdr_enabled
        ? hdr_framebuffers_[current_image_]
        : framebuffers_[current_image_];
    rp_info.renderArea.offset = {0, 0};
    rp_info.renderArea.extent = config_.hdr_enabled
        ? swapchain_extent_
        : swapchain_extent_;

    std::array<VkClearValue, 2> clear_values{};
    clear_values[0].color = {{0.05f, 0.06f, 0.09f, 1.0f}};
    clear_values[1].depthStencil = {1.0f, 0};
    rp_info.clearValueCount = static_cast<uint32_t>(clear_values.size());
    rp_info.pClearValues = clear_values.data();

    vkCmdBeginRenderPass(current_cmd_, &rp_info, VK_SUBPASS_CONTENTS_INLINE);
}
```

### EndFrame()

After `RecordDraws()` and `RecordSky()` complete (still inside the HDR render
pass), end the HDR pass, then run bloom:

```cpp
void VulkanRenderer::EndFrame() {
    if (config_.hdr_enabled) {
        vkCmdEndRenderPass(current_cmd_);

        // Bright pass: extract bright pixels from HDR level 0.
        RecordBrightPass(current_cmd_, 0);

        // Blur passes: separable Gaussian downsample.
        RecordBlurPasses(current_cmd_);

        // Composite: tone map + write to swapchain.
        // Need to begin a render pass on the swapchain image first.
        VkRenderPassBeginInfo rp_info{};
        rp_info.sType = VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO;
        rp_info.renderPass = render_pass_;
        rp_info.framebuffer = framebuffers_[current_image_];
        rp_info.renderArea.offset = {0, 0};
        rp_info.renderArea.extent = swapchain_extent_;
        std::array<VkClearValue, 2> clear_values{};
        clear_values[0].color = {{0.0f, 0.0f, 0.0f, 1.0f}};
        clear_values[1].depthStencil = {1.0f, 0};
        rp_info.clearValueCount = 2;
        rp_info.pClearValues = clear_values.data();
        vkCmdBeginRenderPass(current_cmd_, &rp_info, VK_SUBPASS_CONTENTS_INLINE);
        RecordComposite(current_cmd_);
        vkCmdEndRenderPass(current_cmd_);
    } else {
        vkCmdEndRenderPass(current_cmd_);
    }

    // ... submit and present as before ...
}
```

## Step 6: Shader Loading Path

The renderer's `LoadSPIRV()` loads from `shaders/vert.spv` relative to the
working directory. Make sure the working directory when running is
`G:\VSC0de\build\Release\` so it finds `shaders/hdr_vert.spv` etc.

The bloom shaders are loaded by name in `CreateBloomPipelines()`:
- `shaders/hdr_vert.spv`
- `shaders/bright_frag.spv`
- `shaders/blur_frag.spv`
- `shaders/bloom_composite_frag.spv`

## Step 7: Build and Test

```powershell
$msbuild = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe'
$solution = 'G:\VSC0de\build\KartGib.sln'

Push-Location 'G:\VSC0de\build\Release'
try {
    & $msbuild $solution /m /p:Configuration=Release /p:Platform=x64 /v:minimal
    if ($LASTEXITCODE -ne 0) { throw "Build failed" }

    & '.\KartGib.exe' --frames 100
    Write-Host "SMOKE_EXIT=$LASTEXITCODE"
}
finally {
    Pop-Location
}
```

## Expected Visual Changes

| Before | After Phase 1 |
|--------|---------------|
| Linear colors clamped to [0,1] | HDR linear values, bright surfaces exceed 1.0 |
| Direct sRGB output, no tone mapping | ACES filmic tone mapping + exposure |
| No bloom | Emissive surfaces (boost, weapons, neon) glow |
| Dark sci-fi interior looks flat | HDR range + bloom gives atmospheric depth |

## Acceptance Criteria

- [ ] Build succeeds with no errors
- [ ] `KARTGIB_SMOKE_EXIT=0` at 1440p/1080p
- [ ] Bright surfaces (boost strips, weapons) show visible bloom halo
- [ ] No clipping: very bright areas glow white rather than flat-clipping
- [ ] Frame time remains within budget (measure with `--frames 500`)

## Next Phase

Once Phase 1 is verified, proceed to Phase 2: directional shadow mapping
(karts and track structures cast stable shadows).
