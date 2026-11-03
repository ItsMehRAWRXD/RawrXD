#version 450

// Bloom composite pass.
//
// Blends the blurred bright-pass (bloom) buffer over the HDR scene buffer,
// applies exposure control and ACES tone mapping, then writes to the
// sRGB swapchain. This is the final look of KartGib.

layout(set = 0, binding = 0) uniform sampler2D hdr_scene;
layout(set = 0, binding = 1) uniform sampler2D bloom_blur;
layout(location = 0) in vec2 v_uv;
layout(location = 0) out vec4 out_color;

uniform float exposure = 1.0;   // scene exposure multiplier
uniform float bloom_strength = 0.8; // how much bloom to add
uniform float gamma = 2.2;      // output gamma (sRGB)

vec3 ACESFilm(vec3 x) {
    float a = 2.51, b = 0.03, c = 2.43, d = 0.59, e = 0.14;
    return clamp((x * (a * x + b)) / (x * (c * x + d) + e), 0.0, 1.0);
}

void main() {
    vec3 scene = texture(hdr_scene, v_uv).rgb;
    vec3 bloom = texture(bloom_blur, v_uv).rgb;

    // Apply exposure to both scene and bloom.
    scene *= exposure;
    bloom *= exposure * bloom_strength;

    // Composite: scene + bloom (bloom is additive light).
    vec3 hdr = scene + bloom;

    // Tone map with ACES filmic curve.
    vec3 tonemapped = ACESFilm(hdr);

    // Gamma encode for sRGB swapchain.
    vec3 encoded = pow(tonemapped, vec3(1.0 / gamma));

    out_color = vec4(encoded, 1.0);
}
