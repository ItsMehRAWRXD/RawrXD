#version 450

// Bright-pass filter for bloom.
//
// Samples the HDR scene texture and outputs only pixels above the threshold.
// Pixels below the threshold become black — they won't contribute to bloom.
// This isolates bright emissive surfaces (boost strips, muzzle flashes,
// explosions, neon signs) for the blur pass.

layout(set = 0, binding = 0) uniform sampler2D hdr_scene;
layout(location = 0) in vec2 v_uv;
layout(location = 0) out vec4 out_color;

uniform float threshold = 1.0;   // pixels brighter than this pass through
uniform float knee   = 0.5;      // soft knee width

void main() {
    vec4 hdr = texture(hdr_scene, v_uv);
    vec3 bright = hdr.rgb;

    // Soft threshold: smoothly attenuate values below the knee.
    float luma = dot(bright, vec3(0.2126, 0.7152, 0.0722));
    float bright_factor = smoothstep(threshold - knee, threshold + knee, luma);

    out_color = vec4(bright * bright_factor, hdr.a);
}
