#version 450

// Fullscreen quad vertex shader for HDR/bloom passes.
//
// Produces a clip-space triangle covering the viewport. No vertex buffer
// required — gl_VertexIndex expands to the three corners directly.

layout(location = 0) out vec2 v_uv;

void main() {
    vec2 p = vec2(float((gl_VertexIndex << 1) & 2), float(gl_VertexIndex & 2));
    gl_Position = vec4(p * 2.0 - 1.0, 0.0, 1.0);
    v_uv = p * 0.5 + 0.5;
}
