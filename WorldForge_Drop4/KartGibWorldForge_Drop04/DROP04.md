# Drop 04 / 15 — Shadow Mapping and Advanced Lighting

Additive to Drops 01–03. Native C++20 with no third-party runtime dependencies.

## Fifteen reference functions
1. Vector dot product
2. Safe vector normalization
3. Homogeneous matrix point transform
4. Vulkan 0–1 depth orthographic projection
5. Look-at view matrix
6. Practical cascade split generation
7. Cascade selection
8. Slope-dependent receiver depth bias
9. Nearest depth-map comparison
10. Percentage-closer filtering (PCF)
11. Lambert diffuse response
12. GGX normal distribution
13. Smith geometry term
14. Directional PBR lighting with shadow visibility
15. Range-attenuated point lighting

Additional validation: shadow settings bounds. GLSL shader sources: `shadow_depth.vert`, `shadow_depth.frag`, `shadow_sample.glsl` (include snippet).

## Integration boundary
This drop supplies CPU reference math and GLSL shader sources. It does **not** create Vulkan VkImage shadow atlases, render passes, descriptors, barriers, pipelines, or frame scheduling in the actual KartGib runtime. Integrate only after inspecting the game's existing Vulkan renderer, instance attribute locations, descriptor layouts, depth format, coordinate handedness, and reversed-Z policy. Shader vertex locations are illustrative and must be matched to the real pipeline. The included projection uses conventional depth 0 near / 1 far, not reversed-Z.

## Test
`cmake -S . -B build && cmake --build build -j && ctest --test-dir build --output-on-failure`
