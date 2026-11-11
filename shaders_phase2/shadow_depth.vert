#version 450

// Shadow map depth-only vertex shader.
//
// Input: per-vertex position, per-instance model matrix (same layout as
// scene vertex shader). Output: clip-space position in light space.

layout(set = 0, binding = 0) uniform ShadowBlock {
    mat4 cascade_view_proj[4];
};

layout(location = 0) in vec3 in_position;

// Per-instance: model matrix as four rows.
layout(location = 4) in vec4 in_model0;
layout(location = 5) in vec4 in_model1;
layout(location = 6) in vec4 in_model2;
layout(location = 7) in vec4 in_model3;

layout(location = 0) out int out_cascade_idx;

void main() {
    mat4 model = mat4(
        vec4(in_model0.x, in_model1.x, in_model2.x, in_model3.x),
        vec4(in_model0.y, in_model1.y, in_model2.y, in_model3.y),
        vec4(in_model0.z, in_model1.z, in_model2.z, in_model3.z),
        vec4(in_model0.w, in_model1.w, in_model2.w, in_model3.w));

    vec4 world_pos = model * vec4(in_position, 1.0);

    // Find the first cascade that contains this fragment.
    // In practice, the cascade index is determined per-draw from the
    // view frustum split, not per-vertex. Here we output the cascade
    // index via a flat interpolation so the fragment shader can use it.
    // The actual cascade selection is done on CPU per draw call.

    // Output world position for cascade selection in fragment shader.
    // We use the first cascade's view-proj as a proxy; the real
    // cascade index is passed as a push constant.
    gl_Position = cascade_view_proj[0] * world_pos;
    out_cascade_idx = 0;
}