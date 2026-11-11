#version 450

// Shadow integration for main scene fragment shader.
//
// Include this in frag.glsl / hdr_frag.glsl to add directional
// shadow visibility to the PBR lighting calculation.

layout(set = 2, binding = 0) uniform sampler2DArrayComparison shadow_map;

// Shadow push constants (same layout as shadow_sample.glsl).
layout(push_constant) uniform ShadowPushConstants {
    mat4 cascade_view_proj[4];
    vec4 cascade_splits;
    vec4 cascade_bias;
    vec4 light_direction;
    int cascade_count;
    float pcf_radius;
    float min_variance;
    float padding[2];
};

// Compute the cascade index for a world-space position.
int ComputeCascadeIndex(vec3 world_pos) {
    // Transform to camera-space Z using the inverse view matrix.
    // For simplicity, use the pre-computed cascade splits in camera space.
    // The cascade_splits are the far plane of each cascade in camera-space Z (negative).
    vec4 clip_pos = globals.view * vec4(world_pos, 1.0);
    float cam_z = -clip_pos.z;  // Positive depth

    for (int i = 0; i < cascade_count; ++i) {
        if (cam_z < cascade_splits[i]) return i;
    }
    return cascade_count - 1;
}

// Compute light-space coordinates for all cascades.
void ComputeShadowCoords(vec3 world_pos, out vec4 shadow_coords[4]) {
    for (int i = 0; i < 4; ++i) {
        vec4 clip = cascade_view_proj[i] * vec4(world_pos, 1.0);
        // NDC to texture coords [0,1]
        shadow_coords[i] = clip * 0.5 + 0.5;
    }
}

// Main shadow visibility function.
float GetShadowVisibility(
    vec3 world_pos,
    vec3 normal,
    vec3 light_dir
) {
    int cascade_idx = ComputeCascadeIndex(world_pos);
    vec4 shadow_coords[4];
    ComputeShadowCoords(world_pos, shadow_coords);
    vec4 shadow_coord = shadow_coords[cascade_idx];

    // Depth bias parameters.
    vec3 bias_params = vec3(cascade_bias.x, cascade_bias.y, cascade_bias.z);

    // 3x3 PCF with slope-scaled bias.
    return ShadowPCF(shadow_map, shadow_coord, cascade_idx, normal, light_dir, bias_params);
}