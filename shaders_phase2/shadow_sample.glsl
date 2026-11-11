#version 450

// 3x3 PCF shadow sampling function.
//
// Reusable across all fragment shaders that need shadow visibility.
// Samples a 3x3 kernel around the shadow map coordinate with
// slope-scaled and constant depth bias.
//
// Usage in fragment shader:
//   #include "shadow_sample.glsl"
//   float shadow = ShadowPCF(shadow_sampler, shadow_coord, cascade_idx, normal, light_dir, bias_params);

#define PCF_KERNEL_SIZE 3
#define PCF_SAMPLES 9

// Push constant block for shadow parameters (matches C++ struct).
layout(push_constant) uniform ShadowPushConstants {
    mat4 cascade_view_proj[4];           // Light-space view-proj per cascade
    vec4 cascade_splits;                 // z-split depths (camera-space)
    vec4 cascade_bias;                   // bias.x = constant, bias.y = slope, bias.z = normal offset, bias.w = unused
    vec4 light_direction;                // xyz = direction, w = intensity
    int cascade_count;                   // Active cascades (1-4)
    float pcf_radius;                    // World-space PCF kernel radius
    float min_variance;                  // For variance shadow maps (unused here)
    float padding[2];
};

// 3x3 PCF with slope-scaled depth bias.
// Returns 1.0 = fully lit, 0.0 = fully shadowed.
float ShadowPCF(
    sampler2DArrayComparison shadow_map,
    vec4 shadow_coord,       // .xyz = light-space position, .w = cascade split depth
    int cascade_idx,
    vec3 normal,
    vec3 light_dir,
    vec3 bias_params         // .x = constant, .y = slope, .z = normal
) {
    // Select cascade layer.
    float layer = float(cascade_idx);

    // Slope-scaled depth bias: bias = constant + slope * max(0, 1 - N·L).
    float NdotL = max(dot(normal, -light_dir), 0.0);
    float slope_bias = bias_params.y * (1.0 - NdotL);
    float depth_bias = bias_params.x + slope_bias + bias_params.z;

    // Offset the depth comparison value.
    float compare_depth = shadow_coord.z / shadow_coord.w + depth_bias;

    // 3x3 PCF kernel in texture space.
    // pcf_radius is in world units; convert to texture coords.
    float texel_size = 1.0 / 2048.0;  // Assumes 2048^2 shadow map
    float radius = pcf_radius * texel_size;

    float shadow = 0.0;
    int samples = 0;

    // Precomputed 3x3 offsets.
    const vec2 offsets[9] = vec2[](
        vec2(-1, -1), vec2(0, -1), vec2(1, -1),
        vec2(-1,  0), vec2(0,  0), vec2(1,  0),
        vec2(-1,  1), vec2(0,  1), vec2(1,  1)
    );

    for (int i = 0; i < PCF_SAMPLES; ++i) {
        vec2 offset = offsets[i] * radius;
        vec3 sample_coord = vec3(shadow_coord.xy / shadow_coord.w + offset, compare_depth);
        shadow += texture(shadow_map, vec3(sample_coord.xy, layer)).r;
        samples++;
    }

    return shadow / float(samples);
}

// Single-sample comparison (for debug/cascade visualization).
float ShadowSingle(
    sampler2DArrayComparison shadow_map,
    vec4 shadow_coord,
    int cascade_idx,
    float depth_bias
) {
    float layer = float(cascade_idx);
    float compare_depth = shadow_coord.z / shadow_coord.w + depth_bias;
    vec3 sample_coord = vec3(shadow_coord.xy / shadow_coord.w, layer);
    return texture(shadow_map, sample_coord).r;
}