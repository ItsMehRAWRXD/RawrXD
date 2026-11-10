#version 450

// HDR fragment shader.
//
// Renders the lit scene to a floating-point offscreen target. This is the
// same lighting model as the original frag.glsl but writes linear HDR colors
// without gamma encoding, so bright emissive surfaces (boost strips,
// weapons, explosions) exceed 1.0 and can bloom naturally.
//
// The swapchain is sRGB; this shader must NOT gamma-encode — that happens
// in the final composite pass via tone mapping.

struct GlobalUniforms {
    mat4 view;
    mat4 proj;
    mat4 view_proj;
    vec4 camera_pos_time;          // xyz = camera position, w = time
    vec4 sun_direction_intensity;  // xyz = sun direction, w = intensity
    vec4 ambient_color_intensity;  // rgb = ambient colour, w = intensity
    vec4 point_light_positions[16];
    vec4 point_light_colors[16];
    int point_light_count;
    vec4 camera_basis0;
    vec4 camera_basis1;
    vec4 camera_basis2;
};

struct MaterialUniforms {
    vec4 base_color;
    float metallic;
    float roughness;
    float emissive;
    int texture_id;
    int surface_style;
};

layout(set = 0, binding = 0) uniform GlobalBlock { GlobalUniforms globals; };
layout(set = 1, binding = 0) uniform MaterialBlock { MaterialUniforms material; };

layout(location = 0) in vec2 v_uv;
layout(location = 0) out vec4 out_color;

float hash21(vec2 p) {
    p = fract(p * vec2(123.34, 456.21));
    p += dot(p, p + 45.32);
    return fract(p.x * p.y);
}

float valueNoise(vec2 p) {
    vec2 i = floor(p);
    vec2 f = fract(p);
    f = f * f * (3.0 - 2.0 * f);
    float a = hash21(i);
    float b = hash21(i + vec2(1.0, 0.0));
    float c = hash21(i + vec2(0.0, 1.0));
    float d = hash21(i + vec2(1.0, 1.0));
    return mix(mix(a, b, f.x), mix(c, d, f.x), f.y);
}

vec3 F_Schlick(vec3 f0, float f) { return f0 + (1.0 - f0) * pow(1.0 - f, 5.0); }

float D_GGX(float NdotH, float roughness) {
    float a = roughness * roughness;
    float a2 = a * a;
    float denom = NdotH * NdotH * (a2 - 1.0) + 1.0;
    return a2 / (PI * denom * denom);
}

float V_SmithGGX(float NdotV, float NdotL, float roughness) {
    float k = (roughness + 1.0) * (roughness + 1.0) / 8.0;
    float vis_v = NdotV / (NdotV * (1.0 - k) + k);
    float vis_l = NdotL / (NdotL * (1.0 - k) + k);
    return vis_v * vis_l;
}

vec3 BRDF(vec3 N, vec3 V, vec3 L, vec3 albedo, vec3 f0, float roughness, float metallic) {
    vec3 H = normalize(V + L);
    float NdotH = max(dot(N, H), 0.0);
    float NdotV = max(dot(N, V), 0.0);
    float NdotL = max(dot(N, L), 0.0);

    vec3 F = F_Schlick(f0, NdotH);
    float D = D_GGX(NdotH, roughness);
    float Vis = V_SmithGGX(NdotV, NdotL, roughness);

    vec3 specular = F * D * Vis * (1.0 / max(4.0 * NdotV * NdotL, 0.001));
    vec3 diffuse = albedo * (1.0 - F) * (1.0 - metallic) / PI;

    return (diffuse + specular) * NdotL;
}

void main() {
    // Position from gl_FragCoord reconstructed for lighting.
    vec3 world_pos = vec3(0.0);   // placeholder — actual world_pos passed from vertex
    vec3 N = vec3(0.0, 1.0, 0.0); // placeholder
    vec3 V = normalize(globals.camera_pos_time.xyz - world_pos);

    vec3 albedo = material.base_color.rgb;
    float roughness = material.roughness;

    // Procedural surface detail (same as original frag.glsl).
    if (material.surface_style == 1) {
        vec2 p = world_pos.xz;
        float grain = valueNoise(p * 2.7) * 0.5 + valueNoise(p * 11.3) * 0.5;
        float aggregate = smoothstep(0.42, 0.78, grain);
        float course = fract(world_pos.x * 0.22 + world_pos.z * 0.03);
        float seam = smoothstep(0.02, 0.0, abs(course - 0.5) - 0.46);
        albedo *= 0.82 + aggregate * 0.36;
        albedo *= 1.0 - seam * 0.18;
        roughness = clamp(roughness - aggregate * 0.10 + seam * 0.12, 0.05, 1.0);
    } else if (material.surface_style == 2) {
        float wear = valueNoise(world_pos.xz * 9.0);
        albedo *= 0.86 + wear * 0.18;
        roughness = clamp(roughness + wear * 0.10, 0.05, 1.0);
    } else if (material.surface_style == 3) {
        float wear = valueNoise(world_pos.xz * 6.0);
        albedo *= 0.78 + wear * 0.30;
        roughness = clamp(roughness - wear * 0.14, 0.05, 1.0);
    }

    vec3 f0 = mix(vec3(0.04), albedo, material.metallic);
    vec3 color = vec3(0.0);

    // Directional sun (warm golden hour for tropical/gothic).
    vec3 L = normalize(-globals.sun_direction_intensity.xyz);
    float sun_intensity = globals.sun_direction_intensity.w;
    float NdotL = max(dot(N, L), 0.0);
    if (NdotL > 0.0) {
        color += BRDF(N, V, L, albedo, f0, roughness, material.metallic) * sun_intensity;
    }

    // Point lights (headlights, explosions, weapon muzzle flashes).
    for (int i = 0; i < globals.point_light_count; ++i) {
        vec4 position_range = globals.point_light_positions[i];
        vec3 to_light = position_range.xyz - world_pos;
        float dist = length(to_light);
        float range = position_range.w;
        if (dist > range || dist < 0.0001) continue;
        vec3 Lp = to_light / dist;
        float atten = 1.0 / (1.0 + dist * dist * 0.01);
        float NdotLp = max(dot(N, Lp), 0.0);
        if (NdotLp > 0.0) {
            vec4 light = globals.point_light_colors[i];
            color += BRDF(N, V, Lp, albedo, f0, roughness, material.metallic) *
                     light.rgb * light.a * atten;
        }
    }

    // Ambient and emissive (boost strips, neon signs, weapon glow).
    color += albedo * globals.ambient_color_intensity.rgb * globals.ambient_color_intensity.w *
             (1.0 - material.metallic);
    color += albedo * material.emissive;

    // Distance fog.
    float fog_dist = length(globals.camera_pos_time.xyz - world_pos);
    float fog_factor = clamp((fog_dist - 90.0) / 700.0, 0.0, 1.0);
    color = mix(color, globals.ambient_color_intensity.rgb * 0.85, fog_factor);

    // Write linear HDR — no gamma, no tone map here. Tone mapping happens
    // in the final composite pass so bloom can operate on raw HDR values.
    out_color = vec4(color, 1.0);
}
