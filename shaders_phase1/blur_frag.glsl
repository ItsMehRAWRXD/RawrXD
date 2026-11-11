#version 450

// Separable Gaussian blur for bloom.
//
// Each pass blurs in one direction (horizontal or vertical). Two passes
// (H then V) produce a 2D Gaussian. The blur radius is controlled by
// sigma, which scales the tap offsets and weights.

layout(set = 0, binding = 0) uniform sampler2D source;
layout(location = 0) in vec2 v_uv;
layout(location = 0) out vec4 out_color;

uniform vec2 direction;   // (1,0) horizontal, (0,1) vertical
uniform float sigma;      // controls blur width
uniform float texel_size; // 1.0 / texture dimension

// 11-tap Gaussian kernel, weights precomputed for sigma.
const int KERNEL_TAPS = 11;
const float KERNEL_WEIGHTS[KERNEL_TAPS] = float[](
    0.006, 0.061, 0.242, 0.383, 0.242, 0.061, 0.006,
    0.000, 0.000, 0.000, 0.000
);

void main() {
    vec3 color = vec3(0.0);
    float total_weight = 0.0;

    int half = KERNEL_TAPS / 2;
    for (int i = 0; i < KERNEL_TAPS; ++i) {
        float offset = (float(i) - float(half)) * sigma * texel_size;
        vec2 sample_uv = v_uv + direction * offset;
        color += texture(source, sample_uv).rgb * KERNEL_WEIGHTS[i];
        total_weight += KERNEL_WEIGHTS[i];
    }

    out_color = vec4(color / total_weight, 1.0);
}
