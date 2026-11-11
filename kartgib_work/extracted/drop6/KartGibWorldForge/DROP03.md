# Drop 03 / 15 — HDR rendering foundation

This additive drop preserves Drops 01 and 02. It adds **15 CPU reference operations** in `src/render/hdr.hpp`/`.cpp`: luminance, exposure scale, exposure application, ACES tone mapping, linear-to-sRGB, sRGB encoding, bloom prefilter, 2x downsampling, bilinear upsampling, separable blur, bloom construction, HDR/bloom compositing, HDR frame metrics, settings validation, and viewport normalization. Also includes PPM golden-image output, 5 GLSL 450 shader stages, an optional installed-SDK `glslc` build target, and automated reference tests.

**Integration status:** This is a rendering *foundation*, not a Vulkan swapchain/render-pass implementation. The supplied shaders must be compiled to SPIR-V and wired into KartGib's existing Vulkan pipeline with HDR offscreen images, descriptor sets, barriers, render passes, resize handling, and resource cleanup. No working HDR Vulkan frame is claimed. Do not overwrite existing shaders.

**Color-space contract:** Input HDR is scene-linear. Composite shader outputs sRGB-encoded values and should target a UNORM output attachment, not an sRGB attachment that would encode a second time. Alternatively remove shader encoding for an sRGB swapchain. The existing KartGib swapchain format must be checked before integration.

**Caveat:** CPU reference uses a simplified single-level bloom filter. Production should use multi-level mip pyramids, tuned blur and measured GPU timings.
